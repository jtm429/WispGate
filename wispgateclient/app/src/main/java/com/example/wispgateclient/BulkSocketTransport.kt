package com.example.wispgateclient

import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.security.PrivateKey
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
    val ticket: String,
    val encryptedKey: String,
    val nonce: String,
    val ciphertextSize: Long,
) {
    companion object {
        fun fromJson(transferId: String, value: JSONObject): InboundAssetOffer {
            val bulk = value.getJSONObject("bulk")
            val offer = InboundAssetOffer(
                transferId = transferId,
                id = value.getString("id"),
                name = value.getString("name"),
                contentType = value.optString("content_type", "application/octet-stream"),
                size = value.getLong("size"),
                ticket = bulk.getString("ticket"),
                encryptedKey = bulk.getString("encrypted_key"),
                nonce = bulk.getString("nonce"),
                ciphertextSize = bulk.getLong("ciphertext_size"),
            )
            require(
                transferId.isNotBlank() && transferId.length <= 256 &&
                    offer.id.matches(Regex("[A-Za-z0-9._~-]+")) && offer.id !in setOf(".", "..") &&
                    offer.id.length <= 128 &&
                    offer.name.isNotBlank() && offer.name.length <= 512 && offer.contentType.length <= 128 &&
                    offer.size >= 0 && offer.size <= 256L * 1024 * 1024 &&
                    offer.ticket.length in 16..256 && offer.ciphertextSize == offer.size + 16 &&
                    bulk.getString("algorithm") == "RSA-OAEP-256+A256GCM"
            ) { "Invalid Wisp asset offer" }
            return offer
        }
    }

    fun aad(sender: String, recipient: String): ByteArray = listOf(
        "wispgate-bulk-v1", sender, recipient, transferId, id, ticket, size.toString(),
    ).joinToString("\u0000").toByteArray(Charsets.UTF_8)
}


data class ReceivedAsset(
    val id: String,
    val name: String,
    val contentType: String,
    val size: Long,
    val path: File,
)


data class InboundAssetResponse(
    val wispId: String,
    val html: String,
    val transferId: String,
    val offers: List<InboundAssetOffer>,
)


object InboundAssetProtocol {
    fun parse(body: JSONObject): InboundAssetResponse {
        val wispId = body.getString("wisp_id")
        val response = body.getJSONObject("response")
        val assets = body.getJSONObject("assets")
        require(assets.getString("type") == "begin") { "Expected a Wisp asset begin response" }
        val transferId = assets.getString("transfer_id")
        val files = assets.getJSONArray("files")
        require(files.length() in 1..32) { "A Wisp response requires between 1 and 32 assets" }
        val offers = (0 until files.length()).map { index ->
            InboundAssetOffer.fromJson(transferId, files.getJSONObject(index))
        }
        require(offers.map(InboundAssetOffer::id).distinct().size == offers.size) { "Duplicate Wisp asset id" }
        require(offers.sumOf(InboundAssetOffer::size) <= 256L * 1024 * 1024) { "Wisp assets exceed the size limit" }
        return InboundAssetResponse(wispId, response.optString("html", ""), transferId, offers)
    }
}

/** Sends one prepared ciphertext through the relay's dedicated opaque bulk socket. */
object BulkSocketTransport {
    private const val CONNECT_TIMEOUT_MILLIS = 15_000
    private const val TRANSFER_TIMEOUT_MILLIS = 10 * 60_000

    fun send(
        host: String,
        port: Int,
        recipient: String,
        sessionToken: String,
        upload: PreparedBulkUpload,
    ) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MILLIS)
            socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
            val input = BufferedReader(InputStreamReader(socket.getInputStream()))
            val output = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
            output.write(
                JSONObject()
                    .put("type", "bulk")
                    .put("session_token", sessionToken)
                    .put("ticket", upload.ticket)
                    .put("role", "sender")
                    .put("peer", recipient)
                    .put("length", upload.ciphertextSize)
                    .toString(),
            )
            output.newLine()
            output.flush()

            val ready = input.readJson("bulk relay readiness")
            if (!ready.optBoolean("ok") || ready.optString("type") != "bulk_ready") {
                error(ready.optString("error", "Bulk relay rejected transfer"))
            }
            val written = upload.encryptTo(socket.getOutputStream())
            socket.getOutputStream().flush()
            require(written == upload.ciphertextSize) { "Bulk ciphertext length mismatch" }

            val complete = input.readJson("bulk relay completion")
            if (!complete.optBoolean("ok") || complete.optString("type") != "bulk_complete") {
                error(complete.optString("error", "Bulk relay did not complete transfer"))
            }
        }
    }

    fun receive(
        host: String,
        port: Int,
        sender: String,
        recipient: String,
        sessionToken: String,
        offer: InboundAssetOffer,
        privateKey: PrivateKey,
        directory: File,
    ): ReceivedAsset {
        require(directory.exists() || directory.mkdirs()) { "Unable to create Wisp asset cache" }
        val destination = directory.resolve("${UUID.randomUUID()}.asset")
        try {
            val contentKey = Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
                init(Cipher.DECRYPT_MODE, privateKey, E2EEnvelope.oaepParameters())
            }.doFinal(Base64.getUrlDecoder().decode(offer.encryptedKey))
            require(contentKey.size == 32) { "Invalid Wisp asset key" }
            val nonce = Base64.getUrlDecoder().decode(offer.nonce)
            require(nonce.size == 12) { "Invalid Wisp asset nonce" }
            val decryptor = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(offer.aad(sender, recipient))
            }

            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MILLIS)
                socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
                val input = socket.getInputStream()
                val output = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
                output.write(
                    JSONObject()
                        .put("type", "bulk")
                        .put("session_token", sessionToken)
                        .put("ticket", offer.ticket)
                        .put("role", "receiver")
                        .put("peer", sender)
                        .put("length", offer.ciphertextSize)
                        .toString(),
                )
                output.newLine()
                output.flush()
                val ready = input.readJsonLine("bulk relay readiness")
                if (!ready.optBoolean("ok") || ready.optString("type") != "bulk_ready") {
                    error(ready.optString("error", "Bulk relay rejected transfer"))
                }

                var remaining = offer.ciphertextSize
                var written = 0L
                destination.outputStream().use { target ->
                    val buffer = ByteArray(256 * 1024)
                    while (remaining > 0) {
                        val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                        require(count >= 0) { "Wisp asset transfer ended early" }
                        decryptor.update(buffer, 0, count)?.let {
                            target.write(it)
                            written += it.size
                        }
                        remaining -= count
                    }
                    decryptor.doFinal()?.let {
                        target.write(it)
                        written += it.size
                    }
                }
                require(written == offer.size) { "Wisp asset length did not match its manifest" }
            }
            return ReceivedAsset(offer.id, offer.name, offer.contentType, offer.size, destination)
        } catch (cause: Throwable) {
            destination.delete()
            throw cause
        }
    }

    private fun BufferedReader.readJson(stage: String): JSONObject =
        readLine()?.let(::JSONObject) ?: error("Relay closed connection while waiting for $stage")

    private fun InputStream.readJsonLine(stage: String): JSONObject {
        val bytes = java.io.ByteArrayOutputStream()
        while (true) {
            val next = read()
            if (next < 0) error("Relay closed connection while waiting for $stage")
            if (next == '\n'.code) return JSONObject(bytes.toString(Charsets.UTF_8.name()))
            require(bytes.size() < 64 * 1024) { "Bulk relay response is too large" }
            bytes.write(next)
        }
    }
}
