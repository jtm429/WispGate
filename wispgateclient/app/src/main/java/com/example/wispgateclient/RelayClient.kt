package com.example.wispgateclient

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class RelayClient(private val context: Context) {
    data class ServerInfo(val host: String, val publicKey: String, val controlPort: Int = 443, val relayPort: Int = 4443)
    data class Wisp(val id: String, val name: String, val description: String, val owner: String)
    data class WispState(val wispId: String, val html: String)
    data class ConnectionResult(val wisps: List<Wisp>, val sessionToken: String)

    private val preferences = context.getSharedPreferences("relay", Context.MODE_PRIVATE)

    fun savedServer(): ServerInfo? {
        val host = preferences.getString("host", null) ?: return null
        val key = preferences.getString("public_key", null) ?: return null
        return ServerInfo(host, key, preferences.getInt("control_port", 443), preferences.getInt("relay_port", 4443))
    }

    fun saveServer(info: ServerInfo) {
        preferences.edit().putString("host", info.host).putString("public_key", info.publicKey)
            .putInt("control_port", info.controlPort).putInt("relay_port", info.relayPort).apply()
    }

    suspend fun connectAndListWisps(info: ServerInfo): ConnectionResult = withContext(Dispatchers.IO) {
        val clientId = "android-user"
        Socket(info.host, info.controlPort).use { socket ->
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, joinMessage(info, clientId))
            val joined = JSONObject(input.readLine())
            if (!joined.optBoolean("ok")) error(joined.optString("error", "Join failed"))
            send(output, JSONObject().put("type", "wisps").put("items", JSONArray()).toString())
            val registration = JSONObject(input.readLine())
            if (!registration.optBoolean("ok")) error(registration.optString("error", "Wisp catalog registration failed"))
            val wisps = parseWisps(registration.optJSONArray("items") ?: JSONArray())
            val sessionToken = joined.getString("session_token")
            preferences.edit().putString("session_token", sessionToken).apply()
            ConnectionResult(wisps, sessionToken)
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
                ),
            )
        }
    }

    suspend fun requestState(info: ServerInfo, wisp: Wisp): WispState = withContext(Dispatchers.IO) {
        val token = preferences.getString("session_token", null) ?: error("Connect before requesting state")
        Socket(info.host, info.relayPort).use { socket ->
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, JSONObject().put("type", "session").put("session_token", token).toString())
            val ready = JSONObject(input.readLine())
            if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
            val body = JSONObject()
                .put("wisp_id", wisp.id)
                .put("action", "state_request")
            send(output, envelope(wisp.owner, body))
            val accepted = JSONObject(input.readLine())
            if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Request rejected"))
            val response = JSONObject(input.readLine())
            val responseBody = response.optJSONObject("body") ?: error("Wisp did not return state")
            WispState(wisp.id, responseBody.optJSONObject("response")?.optString("html", "") ?: "")
        }
    }

    suspend fun sendAction(info: ServerInfo, wisp: Wisp, action: String): WispState = withContext(Dispatchers.IO) {
        val token = preferences.getString("session_token", null) ?: error("Connect before sending action")
        Socket(info.host, info.relayPort).use { socket ->
            socket.soTimeout = 10_000
            val input = socket.reader()
            val output = socket.writer()
            send(output, JSONObject().put("type", "session").put("session_token", token).toString())
            val ready = JSONObject(input.readLine())
            if (!ready.optBoolean("ok")) error(ready.optString("error", "Relay session failed"))
            val body = JSONObject().put("wisp_id", wisp.id).put("action", "user_action").put("action_data", JSONObject(action))
            send(output, envelope(wisp.owner, body))
            val accepted = JSONObject(input.readLine())
            if (!accepted.optBoolean("ok")) error(accepted.optString("error", "Action rejected"))
            val response = JSONObject(input.readLine())
            val responseBody = JSONObject(response.getJSONObject("body").getString("response"))
            WispState(wisp.id, responseBody.optString("html", ""))
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

    private fun envelope(recipient: String, body: JSONObject): String = JSONObject()
        .put("type", "envelope")
        .put("sender", "android-user")
        .put("recipient", recipient)
        .put("message_id", System.nanoTime().toString())
        .put("ciphertext", "appserve-v1")
        .put("body", body)
        .toString()

    private fun send(output: BufferedWriter, value: String) {
        output.write(value)
        output.newLine()
        output.flush()
    }

    private fun Socket.reader() = BufferedReader(InputStreamReader(getInputStream()))
    private fun Socket.writer() = BufferedWriter(OutputStreamWriter(getOutputStream()))
}
