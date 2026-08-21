package com.example.wispgateclient

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Socket
import java.net.SocketTimeoutException

class RelayTransportTest {
    @Test
    fun relaySocketsUseKeepaliveAndBoundedReadIdle() {
        Socket().use { socket ->
            assertFalse(socket.keepAlive)

            configureRelaySocket(socket)

            assertTrue(socket.keepAlive)
            assertEquals(RELAY_READ_IDLE_MILLIS, socket.soTimeout)
        }
    }

    @Test
    fun tcpKeepaliveDoesNotChangeBulkTransferTimeout() {
        Socket().use { socket ->
            socket.soTimeout = 1234

            enableTcpKeepAlive(socket)

            assertTrue(socket.keepAlive)
            assertEquals(1234, socket.soTimeout)
        }
    }

    @Test
    fun readIdleSendsPingAndControlFramesStayTransparent() {
        val inputs = ArrayDeque<Any>().apply {
            add(SocketTimeoutException("idle"))
            add("{\"type\":\"pong\",\"nonce\":\"client-ping\"}")
            add("{\"type\":\"ping\",\"nonce\":\"peer-ping\"}")
            add("{\"type\":\"session_envelope\",\"sequence\":0}")
        }
        val sent = mutableListOf<JSONObject>()
        val frames = RelayFrames(
            readLine = {
                when (val next = inputs.removeFirst()) {
                    is Throwable -> throw next
                    else -> next as String
                }
            },
            writeFrame = { sent += JSONObject(it.toString()) },
            nonceFactory = { "client-ping" },
        )

        val application = frames.readApplicationFrame("Wisp response")

        assertEquals("session_envelope", application.getString("type"))
        assertEquals(listOf("ping", "pong"), sent.map { it.getString("type") })
        assertEquals("client-ping", sent[0].getString("nonce"))
        assertEquals("peer-ping", sent[1].getString("nonce"))
    }

    @Test
    fun eofBecomesRecoverableTransportFailure() {
        val frames = RelayFrames(readLine = { null }, writeFrame = {}, nonceFactory = { "unused" })

        val failure = runCatching { frames.readApplicationFrame("relay response") }.exceptionOrNull()

        assertTrue(failure is RelayTransportFailure)
        assertTrue(failure?.message?.contains("relay response") == true)
    }

    @Test
    fun mutationAndResumeRequestsCarryTheSameStableOperationId() {
        val action = OperationProtocol.userAction(
            "upload-wisp",
            JSONObject().put("command", "submit"),
            "stable-operation",
        )
        val resume = OperationProtocol.resume("upload-wisp", "stable-operation")

        assertEquals("user_action", action.getString("action"))
        assertEquals("stable-operation", action.getString("operation_id"))
        assertEquals("operation_resume", resume.getString("action"))
        assertEquals("upload-wisp", resume.getString("wisp_id"))
        assertEquals("stable-operation", resume.getString("operation_id"))
    }

    @Test
    fun expiredOrUnknownResumeIsExplicitlyIndeterminate() {
        listOf("expired", "unknown").forEach { status ->
            val failure = runCatching {
                OperationProtocol.recoveryStatus(status, "stable-operation")
            }.exceptionOrNull()

            assertTrue(failure is IndeterminateOperationException)
            assertTrue(failure?.message?.contains("retry explicitly") == true)
        }

        assertEquals(OperationProtocol.Status.RUNNING, OperationProtocol.recoveryStatus("running", "stable-operation"))
        assertEquals(OperationProtocol.Status.COMPLETED, OperationProtocol.recoveryStatus("completed", "stable-operation"))
    }

}
