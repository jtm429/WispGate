package com.example.wispgateclient.wisp

import org.json.JSONObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64
import java.security.PrivateKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** TLS transport policy: TLS 1.3 only, with an exact pinned leaf certificate digest. */
object RelayTls {
    private val protocols = arrayOf("TLSv1.3")

    fun enabledProtocols(): Array<String> = protocols.copyOf()

    fun bootstrapConnect(host: String, port: Int, timeoutMillis: Int = 15_000): SSLSocket {
        val trustAll = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        }
        val context = SSLContext.getInstance("TLSv1.3").apply { init(null, arrayOf<TrustManager>(trustAll), null) }
        return (context.socketFactory.createSocket() as SSLSocket).also {
            try { it.enabledProtocols = protocols; it.keepAlive = true; it.connect(InetSocketAddress(host, port), timeoutMillis); it.startHandshake() }
            catch (cause: Throwable) { it.close(); throw cause }
        }
    }

    fun verifyLeafFingerprint(leafDer: ByteArray, expectedSha256: String) {
        if (!expectedSha256.matches(Regex("[0-9a-f]{64}"))) {
            throw SecurityException("TLS leaf pin must be a lowercase SHA-256 fingerprint")
        }
        val actual = MessageDigest.getInstance("SHA-256").digest(leafDer)
            .joinToString("") { "%02x".format(it) }
        if (!MessageDigest.isEqual(actual.toByteArray(Charsets.US_ASCII), expectedSha256.toByteArray(Charsets.US_ASCII))) {
            throw SecurityException("TLS leaf certificate fingerprint mismatch")
        }
    }

    fun connect(host: String, port: Int, expectedSha256: String, timeoutMillis: Int = 15_000): SSLSocket {
        require(expectedSha256.matches(Regex("[0-9a-f]{64}"))) {
            "TLS leaf pin must be configured as lowercase SHA-256"
        }
        val trustAll = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        }
        val context = SSLContext.getInstance("TLSv1.3").apply {
            init(null, arrayOf<TrustManager>(trustAll), null)
        }
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            socket.enabledProtocols = protocols
            socket.keepAlive = true
            socket.connect(InetSocketAddress(host, port), timeoutMillis)
            socket.startHandshake()
            val chain = socket.session.peerCertificates
            require(chain.isNotEmpty() && chain[0] is X509Certificate) { "TLS peer did not present a leaf certificate" }
            verifyLeafFingerprint((chain[0] as X509Certificate).encoded, expectedSha256)
            return socket
        } catch (cause: Throwable) {
            socket.close()
            throw cause
        }
    }
}

data class BootstrapRequest(val clientId: String, val nonce: ByteArray)
data class BootstrapResponse(val certificateDer: ByteArray, val certificateSha256: ByteArray)

object RelayBootstrap {
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun unb64(value: String) = Base64.getUrlDecoder().decode(value)
    private fun seal(publicKey: java.security.PublicKey, payload: ByteArray): String {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val wrapped = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.ENCRYPT_MODE, publicKey, oaep) }.doFinal(key)
        val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)) }.doFinal(payload)
        return JSONObject().put("key", b64(wrapped)).put("nonce", b64(nonce)).put("ciphertext", b64(ciphertext)).toString()
    }
    private fun open(privateKey: PrivateKey, envelope: String): ByteArray {
        val value = JSONObject(envelope)
        val key = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE, privateKey, oaep) }.doFinal(unb64(value.getString("key")))
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, unb64(value.getString("nonce")))) }.doFinal(unb64(value.getString("ciphertext")))
    }
    fun createRequest(relayKey: java.security.PublicKey, clientId: String, clientKey: java.security.PublicKey, nonce: ByteArray): JSONObject =
    JSONObject().put("type", "bootstrap_request").put("payload", b64(seal(relayKey, JSONObject().put("version", 1).put("client_id", clientId).put("client_kind", "android").put("client_public_key", b64(clientKey.encoded)).put("nonce", b64(nonce)).toString().toByteArray()).toByteArray()))
    fun decryptRequest(relayKey: PrivateKey, frame: JSONObject): BootstrapRequest {
        val value = JSONObject(String(open(relayKey, String(unb64(frame.getString("payload")))), Charsets.UTF_8))
        return BootstrapRequest(value.getString("client_id"), unb64(value.getString("nonce")))
    }
    fun createResponse(clientKey: java.security.PublicKey, nonce: ByteArray, certificateDer: ByteArray): JSONObject {
        val hash = MessageDigest.getInstance("SHA-256").digest(certificateDer)
        val body = JSONObject().put("version", 1).put("nonce", b64(nonce)).put("certificate_der", b64(certificateDer)).put("certificate_sha256", b64(hash))
        return JSONObject().put("ok", true).put("type", "bootstrap_response").put("payload", b64(seal(clientKey, body.toString().toByteArray()).toByteArray()))
    }
    fun decryptResponse(clientKey: PrivateKey, frame: JSONObject, expectedNonce: ByteArray): BootstrapResponse {
        val value = JSONObject(String(open(clientKey, String(unb64(frame.getString("payload")))), Charsets.UTF_8))
        val nonce = unb64(value.getString("nonce")); if (!nonce.contentEquals(expectedNonce)) throw SecurityException("bootstrap nonce mismatch")
        val cert = unb64(value.getString("certificate_der")); val hash = unb64(value.getString("certificate_sha256"))
        if (!MessageDigest.isEqual(hash, MessageDigest.getInstance("SHA-256").digest(cert))) throw SecurityException("bootstrap certificate hash mismatch")
        return BootstrapResponse(cert, hash)
    }
}

enum class AuthRole(val wireName: String) {
    CONTROL("control"),
    RELAY("relay"),
    BULK_SENDER("bulk_sender"),
    BULK_RECEIVER("bulk_receiver"),
}

class EnrollmentRequiredException(message: String = "Endpoint enrollment is required") : IOException(message)

/** One-use endpoint challenge authentication. */
object EndpointAuthenticator {
    private const val TRANSCRIPT_PREFIX = "wisp-relay-auth-v1"

    fun authenticate(
        role: AuthRole,
        clientId: String,
        identity: KeyPair,
        ticket: String? = null,
        peer: String? = null,
        length: Long? = null,
        readFrame: () -> JSONObject,
        writeFrame: (JSONObject) -> Unit,
    ) {
        writeFrame(
            JSONObject()
                .put("type", "auth_hello")
                .put("role", role.wireName)
                .put("client_id", clientId)
                .put("client_kind", "android")
                .put("public_key", Base64.getUrlEncoder().withoutPadding().encodeToString(identity.public.encoded))
                .apply {
                    ticket?.let { put("ticket", it) }
                    peer?.let { put("peer", it) }
                    length?.let { put("length", it) }
                },
        )
        val challengeFrame = readFrame()
        if (challengeFrame.optString("type") != "auth_challenge") {
            throw IOException("Relay did not issue an endpoint challenge")
        }
        val challenge = challengeFrame.optString("challenge")
        if (challenge.isEmpty()) throw SecurityException("Relay issued an empty endpoint challenge")
        val transcript = listOf(
            TRANSCRIPT_PREFIX,
            role.wireName,
            clientId,
            challenge,
            ticket.orEmpty(),
            peer.orEmpty(),
            length?.toString().orEmpty(),
        ).joinToString("\n").toByteArray(Charsets.US_ASCII)
        val signature = E2EEnvelope.signPss(identity.private, transcript)
        writeFrame(
            JSONObject()
                .put("type", "auth_proof")
                .put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature)),
        )
        val result = readFrame()
        if (!result.optBoolean("ok")) {
            val error = result.optString("error", "Endpoint authentication rejected")
            if (error == "unknown_endpoint" || error == "enrollment_required") {
                throw EnrollmentRequiredException("Endpoint enrollment required: $error")
            }
            throw SecurityException(error)
        }
    }
}
