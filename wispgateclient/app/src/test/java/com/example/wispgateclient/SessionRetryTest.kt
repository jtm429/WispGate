package com.example.wispgateclient

import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class SessionRetryTest {
    @Test
    fun invalidatesAndReestablishesExactlyOnceAfterSessionFailure() = runBlocking {
        var invalidations = 0
        var attempts = 0

        val result = retrySessionOnce(
            invalidate = { invalidations++ },
            operation = {
                attempts++
                if (attempts == 1) throw PeerSessionFailure("remote session was lost")
                "completed"
            },
        )

        assertEquals("completed", result)
        assertEquals(2, attempts)
        assertEquals(1, invalidations)
    }

    @Test
    fun ambiguousMutationLossResumesStableOperationWithoutReplayingMutation() = runBlocking {
        val startedIds = mutableListOf<String>()
        val resumedIds = mutableListOf<String>()
        var invalidations = 0

        val result = recoverMutationOnce(
            operationId = "stable-operation",
            invalidate = { invalidations++ },
            start = { operationId ->
                startedIds += operationId
                throw IOException("socket lost after dispatch")
            },
            resume = { operationId ->
                resumedIds += operationId
                "completed"
            },
        )

        assertEquals("completed", result)
        assertEquals(listOf("stable-operation"), startedIds)
        assertEquals(listOf("stable-operation"), resumedIds)
        assertEquals(1, invalidations)
    }

    @Test
    fun expiredMutationIsIndeterminateAndNeverReplaysOriginalMutation() = runBlocking {
        var starts = 0
        var resumes = 0

        val failure = runCatching {
            recoverMutationOnce(
                operationId = "retained-operation",
                invalidate = {},
                start = {
                    starts++
                    throw IOException("ambiguous dispatch")
                },
                resume = {
                    resumes++
                    throw IndeterminateOperationException("Operation retained-operation expired; retry explicitly")
                },
            )
        }.exceptionOrNull()

        assertTrue(failure is IndeterminateOperationException)
        assertEquals(1, starts)
        assertEquals(1, resumes)
    }

    @Test
    fun authenticatedSessionResetIsRecoverableBeforeDecryption() {
        val reset = JSONObject().put("type", "session_reset")
            .put("sender", "prime-wisp").put("recipient", "android-user")
            .put("reason", "unknown_session")

        val failure = runCatching { requirePeerApplicationFrame(reset, "prime-wisp") }.exceptionOrNull()

        assertTrue(failure is PeerSessionFailure)
        assertEquals("Peer requested session reset: unknown_session", failure?.message)
    }

    @Test
    fun doesNotRetryOrdinaryFailuresOrRetryMoreThanOnce() = runBlocking {
        val ordinary = IllegalStateException("application rejected")
        val ordinaryThrown = runCatching {
            retrySessionOnce(invalidate = {}, operation = { throw ordinary })
        }.exceptionOrNull()
        assertSame(ordinary, ordinaryThrown)

        var attempts = 0
        var invalidations = 0
        val secondSessionFailure = runCatching {
            retrySessionOnce(
                invalidate = { invalidations++ },
                operation = {
                    attempts++
                    throw PeerSessionFailure("session failure $attempts")
                },
            )
        }.exceptionOrNull()
        assertEquals(2, attempts)
        assertEquals(1, invalidations)
        assertEquals("session failure 2", secondSessionFailure?.message)
    }
}
