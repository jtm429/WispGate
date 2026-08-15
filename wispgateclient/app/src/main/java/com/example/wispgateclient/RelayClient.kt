package com.example.wispgateclient

import android.content.Context
import android.util.Base64
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
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.security.KeyFactory
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

class RelayClient(private val context: Context) {
    data class ServerInfo(
        val host: String,
        val publicKey: String,
        val controlPort: Int = 443,
        val relayPort: Int = 4443,
    )
    data class Wisp(val id: String, val name: String, val description: String, val owner: String, val publicKey: String)
    data class WispState(val wispId: String, val html: String)

    data class ConnectionResult(val wisps: List<Wisp>, val sessionToken: String)

    private val preferences = context.getSharedPreferences("relay", Context.MODE_PRIVATE)
    private val identity by lazy { EndpointIdentity().keyPair() }
    private val controlScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val interactiveMutex = Mutex()
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
        )
    }

    fun saveServer(info: ServerInfo) {
        preferences.edit().putString("host", info.host).putString("public_key", info.publicKey)
            .putInt("control_port", info.controlPort).putInt("relay_port", info.relayPort)
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

    suspend fun requestState(info: ServerInfo, wisp: Wisp): WispState = interactiveMutex.withLock {
        withContext(Dispatchers.IO) {
        val token = preferences.getString("session_token", null) ?: error("Connect before requesting state")
        Socket(info.host, info.relayPort).use { socket ->
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, JSONObject().put("type", "session").put("session_token", token).toString())
            val ready = input.readJson("relay response")
            if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
            val body = JSONObject()
                .put("wisp_id", wisp.id)
                .put("action", "state_request")
            val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
            send(output, envelope(wisp.owner, body, peerKey, advertisePublicKey = true))
            val accepted = input.readJson("relay response")
            if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Request rejected"))
            val response = input.readJson("relay response")
            val responseBody = decryptResponse(response, wisp.owner, peerKey)
            WispState(wisp.id, responseBody.optJSONObject("response")?.optString("html", "") ?: "")
        }
        }
    }

    suspend fun sendAction(info: ServerInfo, wisp: Wisp, action: String): WispState = interactiveMutex.withLock {
        withContext(Dispatchers.IO) {
        val token = preferences.getString("session_token", null) ?: error("Connect before sending action")
        Socket(info.host, info.relayPort).use { socket ->
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, JSONObject().put("type", "session").put("session_token", token).toString())
            val ready = input.readJson("relay response")
            if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
            val body = JSONObject().put("wisp_id", wisp.id).put("action", "user_action").put("action_data", JSONObject(action))
            val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)
            send(output, envelope(wisp.owner, body, peerKey, advertisePublicKey = false))
            val accepted = input.readJson("relay response")
            if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Action rejected"))
            val response = input.readJson("relay response")
            val responseBody = decryptResponse(response, wisp.owner, peerKey)
            WispState(wisp.id, responseBody.optJSONObject("response")?.optString("html", "") ?: "")
        }
        }
    }

    suspend fun sendFileAction(info: ServerInfo, wisp: Wisp, action: StagedFileAction): WispState = interactiveMutex.withLock {
        withContext(Dispatchers.IO) {
        val token = preferences.getString("session_token", null) ?: error("Connect before sending an action")
        Socket(info.host, info.relayPort).use { socket ->
            socket.soTimeout = 30_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, JSONObject().put("type", "session").put("session_token", token).toString())
            val ready = input.readJson("relay response")
            if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
            val peerKey = trustedPeerKey(wisp.owner, wisp.publicKey)

            fun exchange(body: JSONObject, advertisePublicKey: Boolean = false): JSONObject {
                send(output, envelope(wisp.owner, body, peerKey, advertisePublicKey))
                val accepted = input.readJson("relay response")
                if (!accepted.optBoolean("ok")) error(accepted.optString("error", "File action rejected"))
                return decryptResponse(input.readJson("encrypted Wisp response"), wisp.owner, peerKey)
            }

            val begun = exchange(FileActionProtocol.begin(wisp.id, action), advertisePublicKey = true)
            val transferReady = begun.optJSONObject("transfer") ?: error("Wisp did not accept the file action")
            if (transferReady.optString("type") == "error") error(transferReady.optString("error", "File action rejected"))
            if (transferReady.optString("type") != "ready" || transferReady.optString("transfer_id") != action.transferId) {
                error("Unexpected file-transfer response")
            }
            val chunkSize = transferReady.optInt("chunk_size", FileTransferStager.MAX_CHUNK_BYTES)
            require(chunkSize in 1..FileTransferStager.MAX_CHUNK_BYTES) { "Wisp requested an invalid file chunk size" }

            action.files.forEach { file ->
                file.path.inputStream().use { source ->
                    val buffer = ByteArray(chunkSize)
                    var offset = 0L
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        val chunk = if (count == buffer.size) buffer else buffer.copyOf(count)
                        val acknowledged = exchange(FileActionProtocol.chunk(wisp.id, action.transferId, file.id, offset, chunk))
                        val transfer = acknowledged.optJSONObject("transfer") ?: error("Wisp did not acknowledge a file chunk")
                        if (transfer.optString("type") == "error") error(transfer.optString("error", "File chunk rejected"))
                        val nextOffset = transfer.optLong("next_offset", -1)
                        require(
                            transfer.optString("type") == "chunk_accepted" &&
                                transfer.optString("file_id") == file.id &&
                                nextOffset == offset + count
                        ) { "Unexpected file-chunk acknowledgement" }
                        offset = nextOffset
                    }
                    require(offset == file.size) { "Staged file length changed before upload" }
                }
            }

            val completed = exchange(FileActionProtocol.commit(wisp.id, action.transferId))
            completed.optJSONObject("transfer")?.let { transfer ->
                if (transfer.optString("type") == "error") error(transfer.optString("error", "File action failed"))
            }
            WispState(wisp.id, completed.optJSONObject("response")?.optString("html", "") ?: "")
        }
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

    private fun envelope(recipient: String, body: JSONObject, recipientPublicKey: String, advertisePublicKey: Boolean): String =
        E2EEnvelope.encrypt(
            sender = "android-user",
            recipient = recipient,
            messageId = UUID.randomUUID().toString(),
            body = body,
            recipientPublicKey = recipientPublicKey,
            senderPrivateKey = identity.private,
            senderPublicKey = identity.public,
            advertiseSenderKey = advertisePublicKey,
        ).toString()

    private fun decryptResponse(envelope: JSONObject, sender: String, senderPublicKey: String): JSONObject {
        if (envelope.optString("sender") != sender || envelope.optString("recipient") != "android-user") {
            throw SecurityException("Unexpected encrypted response route")
        }
        return E2EEnvelope.decrypt(envelope, identity.private, senderPublicKey).body
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
