package com.example.wispgateclient

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

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
