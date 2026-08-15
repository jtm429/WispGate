package com.example.wispgateclient

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

class E2EEnvelopeTest {
    private fun identity() = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()

    @Test
    fun selectsAndroidPssNameBeforeDesktopJvmFallback() {
        assertEquals(
            "SHA256withRSA/PSS",
            E2EEnvelope.selectPssAlgorithm { it == "SHA256withRSA/PSS" || it == "RSASSA-PSS" },
        )
        assertEquals(
            "RSASSA-PSS",
            E2EEnvelope.selectPssAlgorithm { it == "RSASSA-PSS" },
        )
    }

    @Test
    fun encryptsApplicationBodyAndAuthenticatesSender() {
        val android = identity()
        val wisp = identity()
        val body = JSONObject()
            .put("wisp_id", "prime")
            .put("action", "state_request")
            .put("secret", "not for relay")

        val envelope = E2EEnvelope.encrypt(
            sender = "android-user",
            recipient = "prime-wisp",
            messageId = "m1",
            body = body,
            recipientPublicKey = E2EEnvelope.publicKeyText(wisp.public),
            senderPrivateKey = android.private,
            senderPublicKey = android.public,
            advertiseSenderKey = true,
        )

        assertFalse(envelope.has("body"))
        assertFalse(envelope.toString().contains("not for relay"))
        assertEquals(E2EEnvelope.publicKeyText(android.public), envelope.getString("sender_public_key"))
        val decrypted = E2EEnvelope.decrypt(envelope, wisp.private, null)
        assertEquals("state_request", decrypted.body.getString("action"))
        assertEquals(E2EEnvelope.publicKeyText(android.public), decrypted.senderPublicKey)
    }

    @Test
    fun rejectsChangedAuthenticatedRoutingMetadata() {
        val android = identity()
        val wisp = identity()
        val envelope = E2EEnvelope.encrypt(
            "android-user",
            "prime-wisp",
            "m2",
            JSONObject().put("action", "state_request"),
            E2EEnvelope.publicKeyText(wisp.public),
            android.private,
            android.public,
            true,
        )
        envelope.put("sender", "attacker")

        val error = runCatching { E2EEnvelope.decrypt(envelope, wisp.private, null) }.exceptionOrNull()
        assertTrue(error is SecurityException)
    }

    @Test
    fun decryptsEnvelopeProducedByPythonRuntime() {
        val resource = checkNotNull(javaClass.classLoader?.getResourceAsStream("python-envelope.json"))
        val fixture = resource.bufferedReader().use { JSONObject(it.readText()) }
        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(
            PKCS8EncodedKeySpec(Base64.getDecoder().decode(fixture.getString("recipient_private_key_base64"))),
        )

        val decrypted = E2EEnvelope.decrypt(
            fixture.getJSONObject("envelope"),
            privateKey,
            fixture.getString("sender_public_key"),
        )

        assertEquals("<p>python encrypted</p>", decrypted.body.getJSONObject("response").getString("html"))
    }

    @Test
    fun migratesOnlyLegacyOwnerNamePlaceholderKey() {
        val realKey = E2EEnvelope.publicKeyText(identity().public)

        assertEquals(realKey, PeerKeyPolicy.resolve("prime-wisp", "prime-wisp", realKey))
        assertEquals(realKey, PeerKeyPolicy.resolve("prime-wisp", null, realKey))
        assertEquals(realKey, PeerKeyPolicy.resolve("prime-wisp", realKey, realKey))

        val changed = E2EEnvelope.publicKeyText(identity().public)
        val error = runCatching { PeerKeyPolicy.resolve("prime-wisp", realKey, changed) }.exceptionOrNull()
        assertTrue(error is SecurityException)
    }
}
