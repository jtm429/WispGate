package com.example.wispgateclient.wisp

import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.io.OutputStreamWriter
import java.net.Socket
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class InboundAssetOffer(
    val transferId: String,
    val id: String,
    val name: String,
    val contentType: String,
    val size: Long,
    val nonce: String,
    val ciphertextSize: Long,
) {
    companion object {
        fun fromJson(transferId: String, value: JSONObject): InboundAssetOffer {
            val bulk = value.getJSONObject("bulk")
            val offer = InboundAssetOffer(
                transferId, value.getString("id"), value.getString("name"),
                value.optString("content_type", "application/octet-stream"), value.getLong("size"),
                bulk.getString("nonce"), bulk.getLong("ciphertext_size"),
            )
            require(
                transferId.isNotBlank() && transferId.length <= 256 &&
                    offer.id.matches(Regex("[A-Za-z0-9._~-]+")) && offer.id !in setOf(".", "..") &&
                    offer.id.length <= 128 && offer.name.isNotBlank() && offer.name.length <= 512 &&
                    offer.contentType.length <= 128 && offer.size >= 0 &&
                    offer.ciphertextSize == offer.size + 16 &&
                    bulk.getString("algorithm") == "SESSION-A256GCM-v2"
            ) { "Invalid Wisp asset offer" }
            return offer
        }
    }

    fun aad(sessionId: String, sender: String, recipient: String): ByteArray = listOf(
        "wispgate-bulk-v2", sessionId, sender, recipient, transferId, id, size.toString(),
    ).joinToString("\u0000").toByteArray(Charsets.UTF_8)
}

data class ReceivedAsset(val id: String, val name: String, val contentType: String, val size: Long, val path: File)
data class InboundAssetResponse(val wispId: String, val html: String, val transferId: String, val offers: List<InboundAssetOffer>)

object InboundAssetProtocol {
    fun parse(body: JSONObject): InboundAssetResponse {
        val assets = body.getJSONObject("assets")
        require(assets.getString("type") == "begin") { "Expected a Wisp asset begin response" }
        val transferId = assets.getString("transfer_id")
        val files = assets.getJSONArray("files")
        require(files.length() in 1..32) { "A Wisp response requires between 1 and 32 assets" }
        val offers = (0 until files.length()).map { InboundAssetOffer.fromJson(transferId, files.getJSONObject(it)) }
        require(offers.map(InboundAssetOffer::id).distinct().size == offers.size) { "Duplicate Wisp asset id" }
        require(offers.sumOf(InboundAssetOffer::size) <= 256L * 1024 * 1024) { "Wisp assets exceed the size limit" }
        return InboundAssetResponse(body.getString("wisp_id"), body.optJSONObject("response")?.optString("html", "") ?: "", transferId, offers)
    }
}

object BulkSocketTransport {
    private const val TRANSFER_TIMEOUT_MILLIS = 10 * 60_000

    fun send(host: String, port: Int, recipient: String, tlsCertSha256: String, upload: PreparedBulkUpload,
             connect: (String, Int, String) -> Socket = { target, targetPort, pin -> RelayTls.connect(target, targetPort, pin) }) {
        connect(host, port, tlsCertSha256).use { socket ->
            enableTcpKeepAlive(socket); socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
            val input = socket.getInputStream(); val output = OutputStreamWriter(socket.getOutputStream()).buffered()
            writeConnect(output, "sender", upload.sessionId, upload.transferId, upload.sender, recipient, upload.ciphertextSize)
            requireReady(input)
            val written = upload.encryptTo(socket.getOutputStream()); socket.getOutputStream().flush()
            require(written == upload.ciphertextSize) { "Bulk ciphertext length mismatch" }
            requireComplete(input)
        }
    }

    fun receive(host: String, port: Int, sender: String, recipient: String, tlsCertSha256: String,
                sessionId: String, sessionKey: ByteArray, offer: InboundAssetOffer,
                directory: File,
                connect: (String, Int, String) -> Socket = { target, targetPort, pin -> RelayTls.connect(target, targetPort, pin) }): ReceivedAsset {
        require(directory.exists() || directory.mkdirs()) { "Unable to create Wisp asset cache" }
        val destination = directory.resolve("${UUID.randomUUID()}.asset")
        try {
            connect(host, port, tlsCertSha256).use { socket ->
                enableTcpKeepAlive(socket); socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
                val input = socket.getInputStream(); val output = OutputStreamWriter(socket.getOutputStream()).buffered()
                writeConnect(output, "receiver", sessionId, offer.transferId, recipient, sender, offer.ciphertextSize)
                requireReady(input)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, Base64.getUrlDecoder().decode(offer.nonce)))
                cipher.updateAAD(offer.aad(sessionId, sender, recipient))
                var remaining = offer.ciphertextSize
                var written = 0L
                destination.outputStream().use { target ->
                    val buffer = ByteArray(256 * 1024)
                    while (remaining > 0) {
                        val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                        require(count >= 0) { "Wisp asset transfer ended early" }
                        target.write(cipher.update(buffer, 0, count)); written += count; remaining -= count
                    }
                    cipher.doFinal()?.let { target.write(it); written += it.size }
                }
                require(written == offer.size) { "Wisp asset length did not match its manifest" }
                requireComplete(input)
            }
            return ReceivedAsset(offer.id, offer.name, offer.contentType, offer.size, destination)
        } catch (cause: Throwable) { destination.delete(); throw cause }
    }

    private fun writeConnect(output: java.io.BufferedWriter, role: String, sessionId: String, transferId: String, sender: String, recipient: String, length: Long) {
        output.write(JSONObject().put("type", "bulk_connect").put("role", role).put("session_id", sessionId)
            .put("transfer_id", transferId).put("sender", sender).put("recipient", recipient).put("length", length).toString())
        output.newLine(); output.flush()
    }
    private fun readJson(input: InputStream, stage: String): JSONObject {
        val bytes = java.io.ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            if (next < 0) error("Relay closed connection while waiting for $stage")
            if (next == '\n'.code) return JSONObject(bytes.toString(Charsets.UTF_8.name()))
            require(bytes.size() < 64 * 1024) { "Bulk relay response is too large" }
            bytes.write(next)
        }
    }
    private fun requireReady(input: InputStream) { val value = readJson(input, "bulk relay readiness"); require(value.optBoolean("ok") && value.optString("type") == "bulk_ready") { value.optString("error", "Bulk relay rejected transfer") } }
    private fun requireComplete(input: InputStream) { val value = readJson(input, "bulk relay completion"); require(value.optBoolean("ok") && value.optString("type") == "bulk_complete") { value.optString("error", "Bulk relay did not complete transfer") } }
}
