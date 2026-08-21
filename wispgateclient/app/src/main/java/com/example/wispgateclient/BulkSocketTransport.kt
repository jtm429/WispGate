package com.example.wispgateclient

import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.security.KeyPair
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
        tlsCertSha256: String,
        clientId: String,
        identity: KeyPair,
        upload: PreparedBulkUpload,
        connect: (String, Int, String) -> Socket = { target, targetPort, pin -> RelayTls.connect(target, targetPort, pin) },
    ) {
        connect(host, port, tlsCertSha256).use { socket ->
            enableTcpKeepAlive(socket)
            socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
            val input = socket.getInputStream()
            val output = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
            authenticate(input, output, AuthRole.BULK_SENDER, clientId, identity, upload.ticket, recipient, upload.ciphertextSize)

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
        tlsCertSha256: String,
        clientId: String,
        identity: KeyPair,
        offer: InboundAssetOffer,
        privateKey: PrivateKey,
        directory: File,
        connect: (String, Int, String) -> Socket = { target, targetPort, pin -> RelayTls.connect(target, targetPort, pin) },
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

            connect(host, port, tlsCertSha256).use { socket ->
                enableTcpKeepAlive(socket)
                socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
                val input = socket.getInputStream()
                val output = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
                authenticate(input, output, AuthRole.BULK_RECEIVER, clientId, identity, offer.ticket, sender, offer.ciphertextSize)
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

    private fun authenticate(
        input: InputStream,
        output: BufferedWriter,
        role: AuthRole,
        clientId: String,
        identity: KeyPair,
        ticket: String,
        peer: String,
        length: Long,
    ) {
        EndpointAuthenticator.authenticate(
            role, clientId, identity, ticket, peer, length,
            readFrame = { input.readJsonLine("endpoint authentication") },
            writeFrame = { frame -> output.write(frame.toString()); output.newLine(); output.flush() },
        )
    }

    private fun InputStream.readJson(stage: String): JSONObject = readJsonLine(stage)

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
