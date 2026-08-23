package com.example.wispgateclient.wisp

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher

object PeerKeyPolicy {
    fun resolve(owner: String, known: String?, advertised: String): String {
        if (known == null || known == owner) return advertised
        if (known != advertised) throw SecurityException("Public key changed for $owner")
        return known
    }
}

internal object RelayOperationCoordinator {
    private val mutex = Mutex()
    val peerSessions = mutableMapOf<String, PeerSession>()

    suspend fun <T> serialized(block: suspend () -> T): T = mutex.withLock { block() }
}

class RelayClient(private val context: Context) {
    companion object {
        const val MANAGEMENT_WISP_ID = "management"
    }
    data class ServerInfo(
        val host: String,
        val publicKey: String,
        val controlPort: Int = 443,
        val relayPort: Int = 4443,
        val bulkPort: Int = 4444,

    )
    data class Wisp(val id: String, val name: String, val description: String, val owner: String, val publicKey: String)
    data class WispState(
        val wispId: String,
        val html: String,
        val assets: Map<String, ReceivedAsset> = emptyMap(),
        private val assetDirectory: File? = null,
    ) {
        fun assetForUrl(url: String): ReceivedAsset? = runCatching {
            val uri = URI(url)
            if (uri.scheme != "https" || uri.host != "wisp.local") return null
            val prefix = "/_wispgate/assets/"
            if (!uri.path.startsWith(prefix)) return null
            val id = uri.path.removePrefix(prefix)
            if (id.isBlank() || id.contains('/')) null else assets[id]
        }.getOrNull()

        fun isWispLocalUrl(url: String): Boolean = runCatching {
            URI(url).host?.equals("wisp.local", ignoreCase = true) == true
        }.getOrDefault(false)

        fun cleanup() {
            assetDirectory?.deleteRecursively()
        }
    }

    data class ConnectionResult(val wisps: List<Wisp>)

    private val preferences = context.getSharedPreferences("relay", Context.MODE_PRIVATE)
    private val identity by lazy { EndpointIdentity().keyPair() }
    private val clientId by lazy {
        preferences.getString("endpoint_id", null) ?: UUID.randomUUID().toString().also {
            preferences.edit().putString("endpoint_id", it).apply()
        }
    }
    private val controlScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var controlSocket: Socket? = null
    private var controlJob: Job? = null
    private val _catalogUpdates = MutableSharedFlow<List<Wisp>>(replay = 1, extraBufferCapacity = 1)
    val catalogUpdates = _catalogUpdates.asSharedFlow()

    fun savedServer(): ServerInfo? {
        val host = preferences.getString("host", null) ?: return null
        val key = preferences.getString("public_key", null) ?: return null
        return ServerInfo(
            host = host,
            publicKey = key,
            controlPort = preferences.getInt("control_port", 443),
            relayPort = preferences.getInt("relay_port", 4443),
            bulkPort = preferences.getInt("bulk_port", 4444),

        )
    }

    fun saveServer(info: ServerInfo) {
        preferences.edit().putString("host", info.host).putString("public_key", info.publicKey)
            .putInt("control_port", info.controlPort)
            .putInt("relay_port", info.relayPort)
            .putInt("bulk_port", info.bulkPort)
            .apply()
    }

    suspend fun connectAndListWisps(info: ServerInfo): ConnectionResult = withContext(Dispatchers.IO) {
        closeControlConnection()
        bootstrapTrust(info)
        val socket = relaySocket(info.host, info.controlPort, tlsAnchor())
        try {
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            authenticateEndpoint(input, output, AuthRole.CONTROL, clientId)
            send(output, joinMessage(info, clientId))
            val joined = input.readJson(output, "relay response")
            if (!joined.optBoolean("ok")) error(joined.optString("error", "Join failed"))
            send(
                output,
                JSONObject()
                    .put("type", "wisps")
                    .put("client_public_key", E2EEnvelope.publicKeyText(identity.public))
                    .put("items", JSONArray())
                    .toString(),
            )
            val registration = input.readJson(output, "relay response")
            if (!registration.optBoolean("ok")) error(registration.optString("error", "Wisp catalog registration failed"))
            val wisps = parseWisps(registration.optJSONArray("items") ?: JSONArray())
            socket.soTimeout = RELAY_READ_IDLE_MILLIS
            controlSocket = socket
            controlJob = controlScope.launch {
                try {
                    while (true) {
                        val update = input.readJson(output, "catalog update")
                        if (update.optString("type") == "catalog_update") {
                            _catalogUpdates.emit(parseWisps(update.optJSONArray("items") ?: JSONArray()))
                        }
                    }
                } catch (_: Throwable) {
                    // The next explicit reconnect reports the actionable error.
                }
            }
            ConnectionResult(wisps)
        } catch (cause: Throwable) {
            socket.close()
            throw cause
        }
    }


    fun closeControlConnection() {
        controlJob?.cancel()
        controlJob = null
        controlSocket?.close()
        controlSocket = null
    }


    private fun parseWisps(items: JSONArray): List<Wisp> = buildList {
        for (index in 0 until items.length()) {
            val item = items.getJSONObject(index)
            add(
                Wisp(
                    item.getString("id"),
                    item.optString("name", item.getString("id")),
                    item.optString("description"),
                    item.optString("owner"),
                    item.getString("public_key"),
                ),
            )
        }
    }

    suspend fun requestState(info: ServerInfo, wisp: Wisp): WispState = RelayOperationCoordinator.serialized {
        if (wisp.id == MANAGEMENT_WISP_ID) return@serialized requestManagementState(info)
        retrySessionOnce(invalidate = { invalidatePeerSession(wisp.owner) }) {
            withContext(Dispatchers.IO) {
                relaySocket(info.host, info.relayPort, tlsAnchor()).use { socket ->
                    socket.soTimeout = 10_000
                    val input = socket.reader()
                    val output = socket.writer()
                    authenticateEndpoint(input, output, AuthRole.RELAY, clientId)
                    val body = JSONObject().put("wisp_id", wisp.id).put("action", "state_request")
                    val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
                    val peerSession = sessionFor(wisp.owner, peerKey, input, output)
                    val responseBody = exchangeSessionFrame(
                        input, output, peerSession, body, "Request rejected", "Wisp state response",
                    )
                    receiveWispState(info, wisp, input, output, peerSession, responseBody)
                }
            }
        }
    }

    suspend fun sendAction(info: ServerInfo, wisp: Wisp, action: String): WispState = RelayOperationCoordinator.serialized {
        if (wisp.id == MANAGEMENT_WISP_ID) {
            val request = runCatching { JSONObject(action) }.getOrElse {
                return@serialized requestManagementState(info, "Invalid management action")
            }
            val result = withContext(Dispatchers.IO) {
                managementRequest(info, request)
            }
            return@serialized requestManagementState(
                info,
                result.takeUnless { it.optBoolean("ok") }?.optString("error"),
            )
        }
        val operationId = UUID.randomUUID().toString()
        val body = OperationProtocol.userAction(wisp.id, JSONObject(action), operationId)
        recoverMutationOnce(
            operationId = operationId,
            invalidate = { invalidatePeerSession(wisp.owner) },
            start = { performActionAttempt(info, wisp, body, it, recovering = false) },
            resume = {
                performActionAttempt(info, wisp, OperationProtocol.resume(wisp.id, it), it, recovering = true)
            },
        )
    }

    private suspend fun requestManagementState(info: ServerInfo, actionError: String? = null): WispState = withContext(Dispatchers.IO) {
        val state = managementRequest(info, JSONObject().put("action", "state"))
        if (!state.optBoolean("ok")) error(actionError ?: state.optString("error", "Management state unavailable"))
        WispState(MANAGEMENT_WISP_ID, state.optString("html"))
    }

    private fun managementRequest(info: ServerInfo, request: JSONObject): JSONObject {
        bootstrapTrust(info)
        relaySocket(info.host, info.controlPort, tlsAnchor()).use { socket ->
            socket.soTimeout = 15_000
            val input = socket.reader()
            val output = socket.writer()
            authenticateEndpoint(input, output, AuthRole.CONTROL, clientId)
            send(output, joinMessage(info, clientId))
            val joined = input.readJson(output, "management join response")
            if (!joined.optBoolean("ok")) error(joined.optString("error", "Join failed"))
            send(output, JSONObject().put("type", "management_request").put("request", request).toString())
            return input.readJson(output, "management response")
        }
    }

    private suspend fun performActionAttempt(
        info: ServerInfo,
        wisp: Wisp,
        body: JSONObject,
        operationId: String,
        recovering: Boolean,
    ): WispState = withContext(Dispatchers.IO) {
        relaySocket(info.host, info.relayPort, tlsAnchor()).use { socket ->
            socket.soTimeout = RELAY_READ_IDLE_MILLIS
            val input = socket.reader()
            val output = socket.writer()
            authenticateEndpoint(input, output, AuthRole.RELAY, clientId)
            val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
            val peerSession = sessionFor(wisp.owner, peerKey, input, output)
            var responseBody = exchangeSessionFrame(
                input, output, peerSession, body,
                if (recovering) "Operation resume rejected" else "Action rejected",
                if (recovering) "Wisp operation status" else "Wisp action response",
            )
            if (recovering) {
                responseBody = when (OperationProtocol.recoveryStatus(
                    responseBody.optJSONObject("operation")?.optString("type"),
                    operationId,
                )) {
                    OperationProtocol.Status.COMPLETED -> responseBody
                    OperationProtocol.Status.RUNNING ->
                        readSessionResponse(input, output, peerSession, "Wisp operation completion")
                }
            }
            receiveWispState(info, wisp, input, output, peerSession, responseBody)
        }
    }

    suspend fun sendFileAction(info: ServerInfo, wisp: Wisp, action: StagedFileAction): WispState = RelayOperationCoordinator.serialized {
        var reconnecting = false
        val attempt: suspend (String) -> WispState = { operationId ->
            withContext(Dispatchers.IO) {
                Log.i("WispFileTransfer", "sending operation=$operationId files=${action.files.size}")
                relaySocket(info.host, info.relayPort, tlsAnchor()).use { socket ->
                    socket.soTimeout = RELAY_READ_IDLE_MILLIS
                    val input = socket.reader()
                    val output = socket.writer()
                    authenticateEndpoint(input, output, AuthRole.RELAY, clientId)
                    val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
                    val peerSession = sessionFor(wisp.owner, peerKey, input, output)
                    var completed: JSONObject? = null
                    if (reconnecting) {
                        val resumed = exchangeSessionFrame(
                            input, output, peerSession,
                            OperationProtocol.resume(wisp.id, operationId),
                            "Operation resume rejected", "Wisp operation status",
                        )
                        completed = when (OperationProtocol.recoveryStatus(
                            resumed.optJSONObject("operation")?.optString("type"), operationId,
                        )) {
                            OperationProtocol.Status.COMPLETED -> resumed
                            OperationProtocol.Status.RUNNING ->
                                readSessionResponse(input, output, peerSession, "encrypted Wisp completion")
                        }
                    }
                    if (completed == null) {
                        val prepared = BulkFileCrypto.prepare(
                            sender = clientId,
                            recipient = wisp.owner,
                            sessionId = peerSession.sessionId,
                            sessionKey = peerSession.bulkKey(action.transferId, sending = true),
                            transferId = action.transferId,
                            files = action.files,
                        )
                        val begun = exchangeSessionFrame(
                            input, output, peerSession, FileActionProtocol.begin(wisp.id, action, prepared),
                            "File action rejected", "encrypted Wisp response",
                        )
                        val transferReady = begun.optJSONObject("transfer") ?: error("Wisp did not accept the file action")
                        if (transferReady.optString("type") == "error") error(transferReady.optString("error", "File action rejected"))
                        if (transferReady.optString("type") != "ready" || transferReady.optString("transfer_id") != action.transferId) {
                            error("Unexpected file-transfer response")
                        }
                        Log.i("WispFileTransfer", "Wisp ready transfer=${action.transferId} bulkFiles=${prepared.size}")
                        prepared.forEach { upload ->
                            BulkSocketTransport.send(
                                host = info.host,
                                port = info.bulkPort,
                                recipient = wisp.owner,
                                tlsCertSha256 = tlsAnchor(),
                                upload = upload,
                            )
                            Log.i("WispFileTransfer", "bulk file sent id=${upload.file.id} bytes=${upload.file.size}")
                        }
                        completed = readSessionResponse(input, output, peerSession, "encrypted Wisp completion")
                    }
                    checkNotNull(completed)
                    completed.optJSONObject("transfer")?.let { transfer ->
                        if (transfer.optString("type") == "error") error(transfer.optString("error", "File action failed"))
                    }
                    Log.i("WispFileTransfer", "bulk action accepted transfer=${action.transferId}")
                    receiveWispState(info, wisp, input, output, peerSession, completed)
                }
            }
        }
        recoverMutationOnce(
            operationId = action.transferId,
            invalidate = { invalidatePeerSession(wisp.owner) },
            start = {
                reconnecting = false
                attempt(it)
            },
            resume = {
                reconnecting = true
                attempt(it)
            },
        )
    }

    private fun receiveWispState(
        info: ServerInfo,
        wisp: Wisp,
        input: BufferedReader,
        output: BufferedWriter,
        peerSession: PeerSession,
        body: JSONObject,
    ): WispState {
        val assets = body.optJSONObject("assets")
        if (assets == null) {
            return WispState(wisp.id, body.optJSONObject("response")?.optString("html", "") ?: "")
        }
        val parsed = InboundAssetProtocol.parse(body)
        require(parsed.wispId == wisp.id) { "Wisp asset response used the wrong Wisp id" }
        val directory = StagedFileCache.directory(context.cacheDir).resolve("received-${UUID.randomUUID()}")
        return try {
            val received = parsed.offers.associate { offer ->
                val asset = BulkSocketTransport.receive(
                    host = info.host,
                    port = info.bulkPort,
                    sender = wisp.owner,
                    recipient = clientId,
                    tlsCertSha256 = tlsAnchor(),
                    sessionId = peerSession.sessionId,
                    sessionKey = peerSession.bulkKey(parsed.transferId, sending = false),
                    offer = offer,
                    directory = directory,
                )
                asset.id to asset
            }
            val completion = readSessionResponse(input, output, peerSession, "Wisp asset completion")
                .getJSONObject("assets")
            require(
                completion.getString("type") == "complete" &&
                    completion.getString("transfer_id") == parsed.transferId
            ) { "Unexpected Wisp asset completion" }
            WispState(parsed.wispId, parsed.html, received, directory)
        } catch (cause: Throwable) {
            directory.deleteRecursively()
            throw cause
        }
    }

    private fun joinMessage(info: ServerInfo, clientId: String): String =
        JSONObject().put("type", "join").put("client_id", clientId).toString()

    private fun exchangeSessionFrame(
        input: BufferedReader,
        output: BufferedWriter,
        session: PeerSession,
        body: JSONObject,
        rejectionMessage: String,
        responseStage: String,
    ): JSONObject {
        try {
            send(output, session.encrypt(body, SystemClock.elapsedRealtime()).toString())
        } catch (cause: Exception) {
            throw PeerSessionFailure("Could not send peer-session frame", cause)
        }
        val accepted = try {
            input.readJson(output, "relay response")
        } catch (cause: Exception) {
            throw PeerSessionFailure("Relay closed while accepting peer-session frame", cause)
        }
        if (!accepted.optBoolean("ok")) error(accepted.optString("error", rejectionMessage))
        return readSessionResponse(input, output, session, responseStage)
    }

    private fun readSessionResponse(
        input: BufferedReader,
        output: BufferedWriter,
        session: PeerSession,
        stage: String,
    ): JSONObject =
        try {
            val frame = requirePeerApplicationFrame(input.readJson(output, stage), session.peerId, clientId)
            session.decrypt(frame, SystemClock.elapsedRealtime())
        } catch (cause: Exception) {
            throw PeerSessionFailure("Peer session failed while waiting for $stage", cause)
        }

    private fun invalidatePeerSession(owner: String) {
        RelayOperationCoordinator.peerSessions.keys.removeAll { it.startsWith("$owner:") }
    }

    private fun sessionFor(
        owner: String,
        peerPublicKey: String,
        input: BufferedReader,
        output: BufferedWriter,
    ): PeerSession {
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(SessionCrypto.decode64(peerPublicKey)).joinToString("") { "%02x".format(it) }
        val cacheKey = "$owner:$fingerprint"
        val now = SystemClock.elapsedRealtime()
        RelayOperationCoordinator.peerSessions[cacheKey]?.takeUnless { it.isExpired(now) }?.let { return it }
        RelayOperationCoordinator.peerSessions.keys.removeAll { it.startsWith("$owner:") }
        val pending = SessionHandshake.begin(clientId, owner, peerPublicKey, identity, now)
        send(output, pending.envelope.toString())
        val accepted = input.readJson(output, "session handshake relay acceptance")
        if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Session handshake rejected"))
        val acceptance = readSessionAcceptance(input, output)
        return SessionHandshake.finish(pending, acceptance, SystemClock.elapsedRealtime()).also {
            RelayOperationCoordinator.peerSessions[cacheKey] = it
        }
    }

    private fun readSessionAcceptance(input: BufferedReader, output: BufferedWriter): JSONObject {
        while (true) {
            val frame = input.readJson(output, "authenticated Wisp session acceptance")
            if (frame.optString("type") == "accepted") {
                if (!frame.optBoolean("ok")) {
                    error(frame.optString("error", "Session handshake rejected"))
                }
                continue
            }
            return frame
        }
    }

    private fun trustedPeerKey(owner: String, advertisedKey: String): String {
        val preference = "peer_public_key_$owner"
        val known = preferences.getString(preference, null)
        val resolved = PeerKeyPolicy.resolve(owner, known, advertisedKey)
        if (known != resolved) preferences.edit().putString(preference, resolved).apply()
        return resolved
    }

    private fun send(output: BufferedWriter, value: String) {
        output.write(value)
        output.newLine()
        output.flush()
    }

    private fun BufferedReader.readJson(output: BufferedWriter, stage: String): JSONObject =
        RelayFrames(
            readLine = { readLine() },
            writeFrame = { send(output, it.toString()) },
        ).readApplicationFrame(stage)

    private fun authenticateEndpoint(
        input: BufferedReader,
        output: BufferedWriter,
        role: AuthRole,
        clientId: String,
    ) {
        EndpointAuthenticator.authenticate(
            role = role,
            clientId = clientId,
            identity = identity,
            readFrame = { input.readJson(output, "endpoint authentication") },
            writeFrame = { send(output, it.toString()) },
        )
    }

    private fun bootstrapTrust(info: ServerInfo) {
        val cached = preferences.getString("tls_anchor_sha256", null)
        if (cached?.matches(Regex("[0-9a-f]{64}")) == true) return
        val relayKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.decode(info.publicKey, Base64.URL_SAFE or Base64.NO_WRAP)))
        val nonce = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
        RelayTls.bootstrapConnect(info.host, info.controlPort).use { socket ->
            val input = socket.reader(); val output = socket.writer()
            send(output, RelayBootstrap.createRequest(relayKey, clientId, identity.public, nonce).toString())
            val response = input.readJson(output, "encrypted bootstrap response")
            val decoded = RelayBootstrap.decryptResponse(identity.private, response, nonce)
            val hash = decoded.certificateSha256.joinToString("") { "%02x".format(it) }
            preferences.edit().putString("tls_anchor_sha256", hash).apply()
        }
    }

    private fun tlsAnchor(): String = preferences.getString("tls_anchor_sha256", null)
        ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
        ?: error("Relay encrypted bootstrap trust has not completed")

    private fun relaySocket(host: String, port: Int, tlsCertSha256: String): Socket =
        RelayTls.connect(host, port, tlsCertSha256)
    private fun Socket.reader() = BufferedReader(InputStreamReader(getInputStream()))
    private fun Socket.writer() = BufferedWriter(OutputStreamWriter(getOutputStream()))
}

class WispStateOwner {
    private var current: RelayClient.WispState? = null

    fun replace(next: RelayClient.WispState?) {
        if (current === next) return
        val previous = current
        current = next
        previous?.cleanup()
    }

    fun clear() = replace(null)
}
