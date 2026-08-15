package com.example.wispgateclient

import java.io.OutputStream
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class PreparedBulkUpload(
    val file: StagedUpload,
    val sender: String,
    val recipient: String,
    val transferId: String,
    val ticket: String,
    val encryptedKey: String,
    val nonce: String,
    private val contentKey: ByteArray,
) {
    val ciphertextSize: Long get() = file.size + 16

    fun aad(): ByteArray = listOf(
        "wispgate-bulk-v1",
        sender,
        recipient,
        transferId,
        file.id,
        ticket,
        file.size.toString(),
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
        transferId: String,
        files: List<StagedUpload>,
        recipientPublicKey: String,
    ): List<PreparedBulkUpload> {
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(
            X509EncodedKeySpec(Base64.getUrlDecoder().decode(recipientPublicKey)),
        )
        return files.map { file ->
            val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
            val nonce = ByteArray(12).also(random::nextBytes)
            val ticketBytes = ByteArray(24).also(random::nextBytes)
            val wrapped = Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
                init(Cipher.ENCRYPT_MODE, publicKey, E2EEnvelope.oaepParameters())
            }.doFinal(key)
            PreparedBulkUpload(
                file = file,
                sender = sender,
                recipient = recipient,
                transferId = transferId,
                ticket = Base64.getUrlEncoder().withoutPadding().encodeToString(ticketBytes),
                encryptedKey = Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped),
                nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce),
                contentKey = key,
            )
        }
    }
}
