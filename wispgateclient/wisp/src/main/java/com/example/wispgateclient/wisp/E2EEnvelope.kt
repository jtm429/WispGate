package com.example.wispgateclient.wisp

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

object E2EEnvelope {
    const val ALGORITHM = "RSA-OAEP-256+A256GCM+PS256"
    private val random = SecureRandom()
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    data class Decrypted(val body: JSONObject, val senderPublicKey: String)

    fun publicKeyText(key: PublicKey): String = encode64(key.encoded)

    fun encrypt(
        sender: String,
        recipient: String,
        messageId: String,
        body: JSONObject,
        recipientPublicKey: String,
        senderPrivateKey: PrivateKey,
        senderPublicKey: PublicKey,
        advertiseSenderKey: Boolean = false,
    ): JSONObject {
        val envelope = JSONObject()
            .put("version", 1)
            .put("type", "envelope")
            .put("sender", sender)
            .put("recipient", recipient)
            .put("message_id", messageId)
            .put("algorithm", ALGORITHM)
        val contentKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        val nonce = ByteArray(12).also(random::nextBytes)
        envelope.put("encrypted_key", encode64(rsaCipher(Cipher.ENCRYPT_MODE, decodePublicKey(recipientPublicKey)).doFinal(contentKey)))
        envelope.put("nonce", encode64(nonce))
        val aes = Cipher.getInstance("AES/GCM/NoPadding")
        aes.init(Cipher.ENCRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, nonce))
        aes.updateAAD(aad(envelope))
        envelope.put("ciphertext", encode64(aes.doFinal(body.toString().toByteArray(Charsets.UTF_8))))
        if (advertiseSenderKey) envelope.put("sender_public_key", publicKeyText(senderPublicKey))
        envelope.put("signature", encode64(signature(senderPrivateKey).run {
            update(signedBytes(envelope))
            sign()
        }))
        return envelope
    }

    fun decrypt(envelope: JSONObject, recipientPrivateKey: PrivateKey, knownSenderPublicKey: String?): Decrypted {
        require(envelope.getString("type") == "envelope" && envelope.getString("algorithm") == ALGORITHM) {
            "Unsupported encrypted envelope"
        }
        val advertised = envelope.optString("sender_public_key").ifBlank { null }
        if (knownSenderPublicKey != null && advertised != null && knownSenderPublicKey != advertised) {
            throw SecurityException("Peer public key changed")
        }
        val senderKey = knownSenderPublicKey ?: advertised ?: throw SecurityException("Sender public key required")
        val verified = signature(decodePublicKey(senderKey)).run {
            update(signedBytes(envelope))
            verify(decode64(envelope.getString("signature")))
        }
        if (!verified) throw SecurityException("Invalid envelope signature")
        val contentKey = rsaCipher(Cipher.DECRYPT_MODE, recipientPrivateKey)
            .doFinal(decode64(envelope.getString("encrypted_key")))
        val nonce = decode64(envelope.getString("nonce"))
        val aes = Cipher.getInstance("AES/GCM/NoPadding")
        aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, nonce))
        aes.updateAAD(aad(envelope))
        val plaintext = aes.doFinal(decode64(envelope.getString("ciphertext")))
        return Decrypted(JSONObject(String(plaintext, Charsets.UTF_8)), senderKey)
    }

    private fun aad(envelope: JSONObject): ByteArray {
        fun quoted(name: String) = JSONObject.quote(envelope.getString(name))
        return ("{\"algorithm\":" + quoted("algorithm") +
            ",\"message_id\":" + quoted("message_id") +
            ",\"recipient\":" + quoted("recipient") +
            ",\"sender\":" + quoted("sender") +
            ",\"type\":" + quoted("type") +
            ",\"version\":" + envelope.getInt("version") + "}").toByteArray(Charsets.UTF_8)
    }

    private fun signedBytes(envelope: JSONObject): ByteArray = ByteArrayOutputStream().apply {
        write(aad(envelope))
        write(0)
        write(envelope.getString("encrypted_key").toByteArray(Charsets.US_ASCII))
        write(0)
        write(envelope.getString("nonce").toByteArray(Charsets.US_ASCII))
        write(0)
        write(envelope.getString("ciphertext").toByteArray(Charsets.US_ASCII))
    }.toByteArray()

    private fun decodePublicKey(value: String): PublicKey =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(decode64(value)))

    fun signPss(privateKey: PrivateKey, message: ByteArray): ByteArray =
        signature(privateKey).run {
            update(message)
            sign()
        }

    fun oaepParameters() =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    private fun rsaCipher(mode: Int, key: java.security.Key): Cipher =
        Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(mode, key, oaepParameters())
        }

    fun selectPssAlgorithm(available: (String) -> Boolean): String =
        listOf("SHA256withRSA/PSS", "RSASSA-PSS").firstOrNull(available)
            ?: throw java.security.NoSuchAlgorithmException("RSA-PSS SHA-256 is not available")

    private fun pssAlgorithm(): String = selectPssAlgorithm { name ->
        runCatching { Signature.getInstance(name) }.isSuccess
    }

    private fun signature(key: PrivateKey): Signature {
        val algorithm = pssAlgorithm()
        return Signature.getInstance(algorithm).apply {
            initSign(key)
            if (algorithm == "RSASSA-PSS") {
                setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            }
        }
    }

    private fun signature(key: PublicKey): Signature {
        val algorithm = pssAlgorithm()
        return Signature.getInstance(algorithm).apply {
            initVerify(key)
            if (algorithm == "RSASSA-PSS") {
                setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            }
        }
    }

    private fun encode64(data: ByteArray): String {
        val output = StringBuilder((data.size * 4 + 2) / 3)
        var index = 0
        while (index < data.size) {
            val first = data[index++].toInt() and 255
            val second = if (index < data.size) data[index++].toInt() and 255 else -1
            val third = if (index < data.size) data[index++].toInt() and 255 else -1
            output.append(alphabet[first ushr 2])
            output.append(alphabet[((first and 3) shl 4) or if (second >= 0) second ushr 4 else 0])
            if (second >= 0) output.append(alphabet[((second and 15) shl 2) or if (third >= 0) third ushr 6 else 0])
            if (third >= 0) output.append(alphabet[third and 63])
        }
        return output.toString()
    }

    private fun decode64(value: String): ByteArray {
        val output = ByteArrayOutputStream(value.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (character in value) {
            val decoded = alphabet.indexOf(character)
            require(decoded >= 0) { "Invalid base64url value" }
            buffer = (buffer shl 6) or decoded
            bits += 6
            if (bits >= 8) {
                bits -= 8
                output.write((buffer ushr bits) and 255)
            }
        }
        return output.toByteArray()
    }
}
