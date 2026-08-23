package com.example.wispgateclient

import com.example.wispgateclient.wisp.*

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64

class TransportSecurityTest {
    @Test
    fun encryptedBootstrapUsesNonceBoundCertificateTrustAndTls13Only() {
        val relay = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val endpoint = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val nonce = "client nonce".toByteArray()
        val request = RelayBootstrap.createRequest(relay.public, "android-user", endpoint.public, nonce)
        val decodedRequest = RelayBootstrap.decryptRequest(relay.private, request)
        assertEquals("android-user", decodedRequest.clientId)
        assertTrue(nonce.contentEquals(decodedRequest.nonce))
        val response = RelayBootstrap.createResponse(endpoint.public, nonce, "certificate".toByteArray())
        val decodedResponse = RelayBootstrap.decryptResponse(endpoint.private, response, nonce)
        assertEquals("certificate", String(decodedResponse.certificateDer))
        assertThrows(SecurityException::class.java) {
            RelayBootstrap.decryptResponse(endpoint.private, response, "wrong".toByteArray())
        }
        assertEquals(listOf("TLSv1.3"), RelayTls.enabledProtocols().toList())
    }

    @Test
    fun challengeAuthenticationSignsCanonicalRelayTranscriptWithoutBearerToken() {
        val identity = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { it.toByte() })
        val sent = mutableListOf<JSONObject>()
        val replies = ArrayDeque<JSONObject>().apply {
            add(JSONObject().put("type", "auth_challenge").put("challenge", challenge))
            add(JSONObject().put("ok", true).put("type", "authenticated"))
        }

        EndpointAuthenticator.authenticate(
            role = AuthRole.BULK_SENDER,
            clientId = "android-user",
            identity = identity,
            ticket = "bulk-ticket",
            peer = "prime-wisp",
            length = 123L,
            readFrame = { replies.removeFirst() },
            writeFrame = { sent += JSONObject(it.toString()) },
        )

        val hello = sent[0]
        assertEquals("auth_hello", hello.getString("type"))
        assertEquals("bulk_sender", hello.getString("role"))
        assertEquals("android-user", hello.getString("client_id"))
        assertEquals("bulk-ticket", hello.getString("ticket"))
        assertEquals("prime-wisp", hello.getString("peer"))
        assertEquals(123L, hello.getLong("length"))
        assertEquals(
            Base64.getUrlEncoder().withoutPadding().encodeToString(identity.public.encoded),
            hello.getString("public_key"),
        )
        assertFalse(sent.any { it.has("session_token") || it.has("token") })

        val proof = sent[1]
        assertEquals("auth_proof", proof.getString("type"))
        val verifier = Signature.getInstance("RSASSA-PSS").apply {
            setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            initVerify(identity.public)
            update("wisp-relay-auth-v1\nbulk_sender\nandroid-user\n$challenge\nbulk-ticket\nprime-wisp\n123".toByteArray(Charsets.US_ASCII))
        }
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode(proof.getString("signature"))))
    }

    @Test
    fun unknownEndpointEnrollmentFailsExplicitlyWithoutRetryingIdentity() {
        val identity = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val sent = mutableListOf<JSONObject>()
        val replies = ArrayDeque<JSONObject>().apply {
            add(JSONObject().put("type", "auth_challenge").put("challenge", "YWJjZGVmZ2hpamtsbW5vcA"))
            add(JSONObject().put("ok", false).put("error", "unknown_endpoint"))
        }

        val failure = runCatching {
            EndpointAuthenticator.authenticate(
                role = AuthRole.CONTROL,
                clientId = "android-user",
                identity = identity,
                readFrame = { replies.removeFirst() },
                writeFrame = { sent += JSONObject(it.toString()) },
            )
        }.exceptionOrNull()

        assertTrue(failure is EnrollmentRequiredException)
        assertEquals(2, sent.size)
        assertEquals(
            Base64.getUrlEncoder().withoutPadding().encodeToString(identity.public.encoded),
            sent.single { it.getString("type") == "auth_hello" }.getString("public_key"),
        )
    }
}
