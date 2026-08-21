package com.example.wispgateclient

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
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** TLS transport policy: TLS 1.3 only, with an exact pinned leaf certificate digest. */
object RelayTls {
    private val protocols = arrayOf("TLSv1.3")

    fun enabledProtocols(): Array<String> = protocols.copyOf()

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

enum class AuthRole(val wireName: String) {
    CONTROL("control"),
    RELAY("relay"),
    BULK_SENDER("bulk_sender"),
    BULK_RECEIVER("bulk_receiver"),
}

class EnrollmentRequiredException(message: String = "Endpoint enrollment is required") : IOException(message)

/** One-use endpoint challenge authentication. No bearer/session token is sent. */
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
        val signature = Signature.getInstance("RSASSA-PSS").apply {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            initSign(identity.private)
            update(transcript)
        }.sign()
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
