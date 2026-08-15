package com.example.wispgateclient

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SessionCryptoTest {
    private val master = ByteArray(32) { it.toByte() }

    @Test
    fun matchesPythonSessionFixtureInBothDirections() {
        val keys = SessionCrypto.deriveKeys(master, "fixture-session")
        assertEquals("a8939e89e7802a5eb2d16ab1cca6a8e4e271b6f558e7edfb931a5a8633bb989d", keys.androidToWisp.toHex())
        assertEquals("2d25b59f6cf17aeac50fe64d89fe94b1faf7aeb92589ce75f861f62b97ed6585", keys.wispToAndroid.toHex())
        assertEquals("574701000000000000000007", SessionCrypto.nonce(7).toHex())
        val session = PeerSession("fixture-session", "android-user", "prime-wisp", keys, 100_000L)
        val envelope = session.encrypt(JSONObject().put("action", "state_request"), 101_000L)
        assertEquals("35795103fff46cace67a89b589f4c1bc5ed059b8f8887d13a2642a379a17ee4c96c45e2b1c253e530844", SessionCrypto.decode64(envelope.getString("ciphertext")).toHex())
        assertFalse(envelope.has("encrypted_key"))
        assertFalse(envelope.has("signature"))
    }

    @Test
    fun rejectsReplayAndAbsoluteExpiration() {
        val keys = SessionCrypto.deriveKeys(master, "fixture-session")
        val sender = PeerSession("fixture-session", "android-user", "prime-wisp", keys, 10_000L)
        val receiver = PeerSession("fixture-session", "prime-wisp", "android-user", keys, 10_000L)
        val envelope = sender.encrypt(JSONObject().put("n", 1), 11_000L)
        assertEquals(1, receiver.decrypt(envelope, 11_000L).getInt("n"))
        val replay = runCatching { receiver.decrypt(envelope, 12_000L) }.exceptionOrNull()
        assert(replay is SecurityException)
        val expired = runCatching { sender.encrypt(JSONObject(), 10_000L + SessionCrypto.LIFETIME_MILLIS) }.exceptionOrNull()
        assert(expired is SecurityException)
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
