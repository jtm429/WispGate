package com.example.wispgateclient

import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PeerSessionFailure(message: String, cause: Throwable? = null) : RecoverableSessionFailure(message, cause)

internal fun requirePeerApplicationFrame(frame: JSONObject, expectedPeer: String, expectedLocalId: String): JSONObject {
    if (frame.optString("type") != "session_reset") return frame
    if (frame.optString("sender") != expectedPeer ||
        frame.optString("recipient") != expectedLocalId ||
        frame.optString("reason") != "unknown_session"
    ) {
        throw SecurityException("Invalid session reset")
    }
    throw PeerSessionFailure("Peer requested session reset: unknown_session")
}

suspend fun <T> retrySessionOnce(invalidate: () -> Unit, operation: suspend () -> T): T =
    try {
        operation()
    } catch (cause: Exception) {
        if (cause !is RecoverableSessionFailure && cause !is IOException) throw cause
        invalidate()
        operation()
    }

suspend fun <T> recoverMutationOnce(
    operationId: String,
    invalidate: () -> Unit,
    start: suspend (String) -> T,
    resume: suspend (String) -> T,
): T = try {
    start(operationId)
} catch (cause: Exception) {
    if (cause !is RecoverableSessionFailure && cause !is IOException) throw cause
    invalidate()
    resume(operationId)
}

object SessionCrypto {
    const val LIFETIME_MILLIS = 30L * 60L * 1000L
    private val prefix = byteArrayOf('W'.code.toByte(), 'G'.code.toByte(), 1, 0)
    data class Keys(val androidToWisp: ByteArray, val wispToAndroid: ByteArray)

    fun deriveKeys(master: ByteArray, sessionId: String): Keys {
        require(master.size == 32 && sessionId.isNotEmpty())
        return Keys(
            hkdf(master, sessionId.toByteArray(), "wispgate-session-v1/android-to-wisp".toByteArray()),
            hkdf(master, sessionId.toByteArray(), "wispgate-session-v1/wisp-to-android".toByteArray()),
        )
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(1)
        return mac.doFinal()
    }

    fun nonce(sequence: Long): ByteArray {
        require(sequence >= 0) { "Invalid session sequence" }
        return prefix + ByteBuffer.allocate(8).putLong(sequence).array()
    }

    fun aad(sessionId: String, sender: String, recipient: String, sequence: Long): ByteArray =
        ("{\"recipient\":" + JSONObject.quote(recipient) +
            ",\"sender\":" + JSONObject.quote(sender) +
            ",\"sequence\":" + sequence +
            ",\"session_id\":" + JSONObject.quote(sessionId) +
            ",\"type\":\"session_envelope\",\"version\":1}").toByteArray()

    fun crypt(mode: Int, key: ByteArray, sequence: Long, aad: ByteArray, value: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce(sequence)))
            updateAAD(aad)
            doFinal(value)
        }

    fun encode64(data: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data)
    fun decode64(value: String): ByteArray = java.util.Base64.getUrlDecoder().decode(value)

    fun acceptProof(master: ByteArray, sessionId: String, challenge: String, androidId: String, wispId: String): String {
        val key = deriveKeys(master, sessionId).wispToAndroid
        val transcript = listOf("wispgate-session-v1/accept", sessionId, challenge, androidId, wispId)
            .joinToString("\u0000").toByteArray()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return encode64(mac.doFinal(transcript))
    }
}

object SessionHandshake {
    data class Pending(
        val localId: String,
        val owner: String,
        val peerPublicKey: String,
        internal val identity: KeyPair,
        internal val master: ByteArray,
        val sessionId: String,
        internal val challenge: String,
        internal val createdAtMillis: Long,
        val envelope: JSONObject,
    )

    fun begin(
        localId: String,
        owner: String,
        peerPublicKey: String,
        identity: KeyPair,
        nowMillis: Long,
        master: ByteArray = ByteArray(32).also(SecureRandom()::nextBytes),
        sessionId: String = UUID.randomUUID().toString(),
        challenge: String = UUID.randomUUID().toString(),
    ): Pending {
        require(master.size == 32)
        val body = JSONObject().put("type", "session_init").put("session_id", sessionId)
            .put("master_secret", SessionCrypto.encode64(master)).put("challenge", challenge)
        val envelope = E2EEnvelope.encrypt(
            localId, owner, UUID.randomUUID().toString(), body, peerPublicKey,
            identity.private, identity.public, true,
        )
        return Pending(localId, owner, peerPublicKey, identity, master.copyOf(), sessionId, challenge, nowMillis, envelope)
    }

    fun finish(pending: Pending, envelope: JSONObject, nowMillis: Long): PeerSession {
        if (nowMillis >= pending.createdAtMillis + SessionCrypto.LIFETIME_MILLIS ||
            envelope.optString("sender") != pending.owner || envelope.optString("recipient") != pending.localId) {
            throw SecurityException("Invalid session acceptance route or lifetime")
        }
        val body = E2EEnvelope.decrypt(envelope, pending.identity.private, pending.peerPublicKey).body
        if (body.optString("type") != "session_accept" || body.optString("session_id") != pending.sessionId ||
            body.optString("challenge") != pending.challenge) throw SecurityException("Invalid session acceptance")
        val expected = SessionCrypto.acceptProof(pending.master, pending.sessionId, pending.challenge, pending.localId, pending.owner)
        if (!MessageDigest.isEqual(expected.toByteArray(), body.optString("proof").toByteArray())) {
            throw SecurityException("Invalid session acceptance proof")
        }
        return PeerSession(pending.sessionId, pending.localId, pending.owner,
            SessionCrypto.deriveKeys(pending.master, pending.sessionId), pending.createdAtMillis, androidSide = true)
    }
}

class PeerSession(
    val sessionId: String,
    private val localId: String,
    internal val peerId: String,
    keys: SessionCrypto.Keys,
    private val createdAtMillis: Long,
    private val androidSide: Boolean,
) {
    private val sendKey = if (androidSide) keys.androidToWisp else keys.wispToAndroid
    private val receiveKey = if (androidSide) keys.wispToAndroid else keys.androidToWisp
    private var sendSequence = 0L
    private var receiveSequence = 0L

    private fun checkLive(nowMillis: Long) {
        if (isExpired(nowMillis)) throw SecurityException("Session expired")
    }

    fun isExpired(nowMillis: Long): Boolean = nowMillis >= createdAtMillis + SessionCrypto.LIFETIME_MILLIS

    @Synchronized
    fun encrypt(body: JSONObject, nowMillis: Long): JSONObject {
        checkLive(nowMillis)
        val sequence = sendSequence
        val aad = SessionCrypto.aad(sessionId, localId, peerId, sequence)
        val ciphertext = SessionCrypto.crypt(Cipher.ENCRYPT_MODE, sendKey, sequence, aad, body.toString().toByteArray())
        sendSequence++
        return JSONObject().put("version", 1).put("type", "session_envelope")
            .put("session_id", sessionId).put("sender", localId).put("recipient", peerId)
            .put("sequence", sequence).put("ciphertext", SessionCrypto.encode64(ciphertext))
    }

    @Synchronized
    fun decrypt(envelope: JSONObject, nowMillis: Long): JSONObject {
        checkLive(nowMillis)
        if (envelope.optInt("version") != 1 || envelope.optString("type") != "session_envelope" ||
            envelope.optString("session_id") != sessionId || envelope.optString("sender") != peerId ||
            envelope.optString("recipient") != localId) throw SecurityException("Invalid session route")
        val sequence = envelope.optLong("sequence", -1)
        if (sequence != receiveSequence) throw SecurityException("Invalid session sequence")
        val plaintext = try {
            SessionCrypto.crypt(Cipher.DECRYPT_MODE, receiveKey, sequence,
                SessionCrypto.aad(sessionId, peerId, localId, sequence),
                SessionCrypto.decode64(envelope.getString("ciphertext")))
        } catch (cause: Exception) {
            throw SecurityException("Invalid session authentication", cause)
        }
        receiveSequence++
        return JSONObject(String(plaintext))
    }
}