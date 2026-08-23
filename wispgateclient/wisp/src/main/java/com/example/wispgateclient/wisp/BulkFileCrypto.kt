package com.example.wispgateclient.wisp

import java.io.OutputStream
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class PreparedBulkUpload(
    val file: StagedUpload,
    val sender: String,
    val recipient: String,
    val sessionId: String,
    val transferId: String,
    val nonce: String,
    private val contentKey: ByteArray,
) {
    val ciphertextSize: Long get() = file.size + 16

    fun aad(): ByteArray = listOf(
        "wispgate-bulk-v2", sessionId, sender, recipient, transferId, file.id, file.size.toString(),
    ).joinToString("\u0000").toByteArray(Charsets.UTF_8)

    fun encryptTo(output: OutputStream): Long {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(contentKey, "AES"),
            GCMParameterSpec(128, Base64.getUrlDecoder().decode(nonce)),
        )
        cipher.updateAAD(aad())
        var written = 0L
        file.path.inputStream().use { source ->
            val buffer = ByteArray(256 * 1024)
            while (true) {
                val count = source.read(buffer)
                if (count < 0) break
                cipher.update(buffer, 0, count)?.let {
                    output.write(it)
                    written += it.size
                }
            }
        }
        val final = cipher.doFinal()
        output.write(final)
        written += final.size
        require(written == ciphertextSize) { "Encrypted file length changed during transfer" }
        return written
    }
}

object BulkFileCrypto {
    private val random = SecureRandom()

    fun prepare(
        sender: String,
        recipient: String,
        sessionId: String,
        sessionKey: ByteArray,
        transferId: String,
        files: List<StagedUpload>,
    ): List<PreparedBulkUpload> = files.map { file ->
        val nonce = ByteArray(12).also(random::nextBytes)
        PreparedBulkUpload(
            file = file,
            sender = sender,
            recipient = recipient,
            sessionId = sessionId,
            transferId = transferId,
            nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce),
            contentKey = sessionKey.copyOf(),
        )
    }
}
