package com.example.wispgateclient

import com.example.wispgateclient.wisp.*

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator

class SessionHandshakeTest {
    private fun identity() = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()

    @Test
    fun mutuallyAuthenticatesRsaIdentitiesAndReturnsSymmetricSession() {
        val android = identity()
        val wisp = identity()
        val pending = SessionHandshake.begin(
            localId = "android-endpoint-uuid", owner = "prime-wisp", peerPublicKey = E2EEnvelope.publicKeyText(wisp.public),
            identity = android, nowMillis = 1000L,
            master = ByteArray(32) { it.toByte() }, sessionId = "session-1", challenge = "challenge-1",
        )
        val init = E2EEnvelope.decrypt(pending.envelope, wisp.private, E2EEnvelope.publicKeyText(android.public)).body
        assertEquals("session_init", init.getString("type"))
        assertEquals("session-1", init.getString("session_id"))
        val acceptBody = JSONObject().put("type", "session_accept").put("session_id", "session-1")
            .put("challenge", "challenge-1")
            .put("proof", SessionCrypto.acceptProof(ByteArray(32) { it.toByte() }, "session-1", "challenge-1", "android-endpoint-uuid", "prime-wisp"))
        val accept = E2EEnvelope.encrypt(
            "prime-wisp", "android-endpoint-uuid", "accept-1", acceptBody,
            E2EEnvelope.publicKeyText(android.public), wisp.private, wisp.public, false,
        )

        val session = SessionHandshake.finish(pending, accept, 1100L)
        val frame = session.encrypt(JSONObject().put("action", "state_request"), 1200L)
        assertEquals("session_envelope", frame.getString("type"))
        assertFalse(frame.has("encrypted_key"))
        assertFalse(frame.has("signature"))
    }

    @Test
    fun rejectsAcceptanceWithoutChallengeBoundMasterProof() {
        val android = identity()
        val wisp = identity()
        val pending = SessionHandshake.begin(
            "android-endpoint-uuid", "prime-wisp", E2EEnvelope.publicKeyText(wisp.public), android, 1000L,
            ByteArray(32) { it.toByte() }, "session-1", "challenge-1",
        )
        val bad = E2EEnvelope.encrypt(
            "prime-wisp", "android-endpoint-uuid", "accept-1",
            JSONObject().put("type", "session_accept").put("session_id", "session-1")
                .put("challenge", "challenge-1").put("proof", "wrong"),
            E2EEnvelope.publicKeyText(android.public), wisp.private, wisp.public, false,
        )
        assertTrue(runCatching { SessionHandshake.finish(pending, bad, 1100L) }.exceptionOrNull() is SecurityException)
    }
}
