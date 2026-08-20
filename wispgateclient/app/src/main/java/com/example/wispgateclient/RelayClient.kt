package com.example.wispgateclient

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

    data class ConnectionResult(val wisps: List<Wisp>, val sessionToken: String)

    private val preferences = context.getSharedPreferences("relay", Context.MODE_PRIVATE)
    private val identity by lazy { EndpointIdentity().keyPair() }
    private val controlScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var controlSocket: Socket? = null
    private var controlJob: Job? = null
    private val _catalogUpdates = MutableSharedFlow<List<Wisp>>(replay = 1, extraBufferCapacity = 1)
    val catalogUpdates = _catalogUpdates.asSharedFlow()

    fun savedServer(): ServerInfo? {
        val host = preferences.getString("host", null) ?: return null
        val key = preferences.getString("public_key", null) ?: return null
        return ServerInfo(
            host,
            key,
            preferences.getInt("control_port", 443),
            preferences.getInt("relay_port", 4443),
            preferences.getInt("bulk_port", 4444),
        )
    }

    fun saveServer(info: ServerInfo) {
        preferences.edit().putString("host", info.host).putString("public_key", info.publicKey)
            .putInt("control_port", info.controlPort).putInt("relay_port", info.relayPort)
            .putInt("bulk_port", info.bulkPort)
            .apply()
    }

    suspend fun connectAndListWisps(info: ServerInfo): ConnectionResult = withContext(Dispatchers.IO) {
        val clientId = "android-user"
        closeControlConnection()
        val socket = Socket(info.host, info.controlPort)
        try {
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, joinMessage(info, clientId))
            val joined = input.readJson("relay response")
            if (!joined.optBoolean("ok")) error(joined.optString("error", "Join failed"))
            send(
                output,
                JSONObject()
                    .put("type", "wisps")
                    .put("client_public_key", E2EEnvelope.publicKeyText(identity.public))
                    .put("items", JSONArray())
                    .toString(),
            )
            val registration = input.readJson("relay response")
            if (!registration.optBoolean("ok")) error(registration.optString("error", "Wisp catalog registration failed"))
            val wisps = parseWisps(registration.optJSONArray("items") ?: JSONArray())
            val sessionToken = joined.getString("session_token")
            preferences.edit().putString("session_token", sessionToken).apply()
            socket.soTimeout = 0
            controlSocket = socket
            controlJob = controlScope.launch {
                try {
                    while (true) {
                        val update = input.readJson("catalog update")
                        if (update.optString("type") == "catalog_update") {
                            _catalogUpdates.emit(parseWisps(update.optJSONArray("items") ?: JSONArray()))
                        }
                    }
                } catch (_: Throwable) {
                    // The next explicit reconnect reports the actionable error.
                }
            }
            ConnectionResult(wisps, sessionToken)
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

    suspend fun updateServer(info: ServerInfo): String = withContext(Dispatchers.IO) {
        Socket(info.host, info.controlPort).use { socket ->
            socket.soTimeout = 15_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, joinMessage(info, "android-user"))
            val joined = input.readJson("relay response")
            if (!joined.optBoolean("ok")) error(joined.optString("error", "Join failed"))
            send(output, JSONObject().put("type", "update_server").toString())
            val result = input.readJson("update response")
            if (!result.optBoolean("ok")) error(result.optString("error", "Server update rejected"))
            result.optString("type", "update_started")
        }
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
        retrySessionOnce(invalidate = { invalidatePeerSession(wisp.owner) }) {
            withContext(Dispatchers.IO) {
                val token = preferences.getString("session_token", null) ?: error("Connect before requesting state")
                Socket(info.host, info.relayPort).use { socket ->
                    socket.soTimeout = 10_000
                    val input = socket.reader()
                    val output = socket.writer()
                    openRelaySession(input, output, token)
                    val body = JSONObject().put("wisp_id", wisp.id).put("action", "state_request")
                    val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
                    val peerSession = sessionFor(wisp.owner, peerKey, input, output)
                    val responseBody = exchangeSessionFrame(
                        input, output, peerSession, body, "Request rejected", "Wisp state response",
                    )
                    receiveWispState(info, wisp, token, input, peerSession, responseBody)
                }
            }
        }
    }

    suspend fun sendAction(info: ServerInfo, wisp: Wisp, action: String): WispState = RelayOperationCoordinator.serialized {
        retrySessionOnce(invalidate = { invalidatePeerSession(wisp.owner) }) {
            withContext(Dispatchers.IO) {
                val token = preferences.getString("session_token", null) ?: error("Connect before sending action")
                Socket(info.host, info.relayPort).use { socket ->
                    socket.soTimeout = 10_000
                    val input = socket.reader()
                    val output = socket.writer()
                    openRelaySession(input, output, token)
                    val body = JSONObject().put("wisp_id", wisp.id).put("action", "user_action")
                        .put("action_data", JSONObject(action))
                    val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
                    val peerSession = sessionFor(wisp.owner, peerKey, input, output)
                    val responseBody = exchangeSessionFrame(
                        input, output, peerSession, body, "Action rejected", "Wisp action response",
                    )
                    receiveWispState(info, wisp, token, input, peerSession, responseBody)
                }
            }
        }
    }

    suspend fun sendFileAction(info: ServerInfo, wisp: Wisp, action: StagedFileAction): WispState = RelayOperationCoordinator.serialized {
        retrySessionOnce(invalidate = { invalidatePeerSession(wisp.owner) }) {
            withContext(Dispatchers.IO) {
                Log.i("WispFileTransfer", "sending begin transfer=${action.transferId} files=${action.files.size}")
                val token = preferences.getString("session_token", null) ?: error("Connect before sending an action")
                Socket(info.host, info.relayPort).use { socket ->
                    socket.soTimeout = 10 * 60_000
                    val input = socket.reader()
                    val output = socket.writer()
                    openRelaySession(input, output, token)
                    val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
                    val peerSession = sessionFor(wisp.owner, peerKey, input, output)
                    val prepared = BulkFileCrypto.prepare(
                        sender = "android-user",
                        recipient = wisp.owner,
                        transferId = action.transferId,
                        files = action.files,
                        recipientPublicKey = peerKey,
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
                        BulkSocketTransport.send(info.host, info.bulkPort, wisp.owner, token, upload)
                        Log.i("WispFileTransfer", "bulk file sent id=${upload.file.id} bytes=${upload.file.size}")
                    }

                    val completed = readSessionResponse(input, peerSession, "encrypted Wisp completion")
                    completed.optJSONObject("transfer")?.let { transfer ->
                        if (transfer.optString("type") == "error") error(transfer.optString("error", "File action failed"))
                    }
                    Log.i("WispFileTransfer", "bulk action accepted transfer=${action.transferId}")
                    receiveWispState(info, wisp, token, input, peerSession, completed)
                }
            }
        }
    }

    private fun receiveWispState(
        info: ServerInfo,
        wisp: Wisp,
        sessionToken: String,
        input: BufferedReader,
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
                    recipient = "android-user",
                    sessionToken = sessionToken,
                    offer = offer,
                    privateKey = identity.private,
                    directory = directory,
                )
                asset.id to asset
            }
            val completion = readSessionResponse(input, peerSession, "Wisp asset completion")
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

    private fun joinMessage(info: ServerInfo, clientId: String): String {
        val payload = JSONObject()
            .put("deployment_id", "private")
            .put("client_id", clientId)
            .put("client_public_key", clientId)
            .put("nonce", clientId)
            .put("timestamp", System.currentTimeMillis() / 1000)
            .toString()
        val keyBytes = Base64.decode(info.publicKey, Base64.URL_SAFE or Base64.NO_WRAP)
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encrypted = Base64.encodeToString(cipher.doFinal(payload.toByteArray()), Base64.URL_SAFE or Base64.NO_WRAP)
        return JSONObject().put("type", "join").put("payload", encrypted).toString()
    }

    private fun openRelaySession(input: BufferedReader, output: BufferedWriter, token: String) {
        send(output, JSONObject().put("type", "session").put("session_token", token).toString())
        val ready = input.readJson("relay response")
        if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
    }

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
            input.readJson("relay response")
        } catch (cause: Exception) {
            throw PeerSessionFailure("Relay closed while accepting peer-session frame", cause)
        }
        if (!accepted.optBoolean("ok")) error(accepted.optString("error", rejectionMessage))
        return readSessionResponse(input, session, responseStage)
    }

    private fun readSessionResponse(input: BufferedReader, session: PeerSession, stage: String): JSONObject =
        try {
            session.decrypt(input.readJson(stage), SystemClock.elapsedRealtime())
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
        val pending = SessionHandshake.begin(owner, peerPublicKey, identity, now)
        send(output, pending.envelope.toString())
        val accepted = input.readJson("session handshake relay acceptance")
        if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Session handshake rejected"))
        val acceptance = input.readJson("authenticated Wisp session acceptance")
        return SessionHandshake.finish(pending, acceptance, SystemClock.elapsedRealtime()).also {
            RelayOperationCoordinator.peerSessions[cacheKey] = it
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

    private fun BufferedReader.readJson(stage: String): JSONObject =
        readLine()?.let(::JSONObject) ?: error("Relay closed connection while waiting for $stage")

    private fun Socket.reader() = BufferedReader(InputStreamReader(getInputStream()))
    private fun Socket.writer() = BufferedWriter(OutputStreamWriter(getOutputStream()))
}

internal class WispStateOwner {
    private var current: RelayClient.WispState? = null

    fun replace(next: RelayClient.WispState?) {
        if (current === next) return
        val previous = current
        current = next
        previous?.cleanup()
    }

    fun clear() = replace(null)
}
