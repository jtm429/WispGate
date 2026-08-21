package com.example.wispgateclient

import org.json.JSONObject
import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID

internal const val RELAY_READ_IDLE_MILLIS = 10_000

internal fun enableTcpKeepAlive(socket: Socket): Socket = socket.apply {
    keepAlive = true
}

internal fun configureRelaySocket(socket: Socket): Socket = socket.apply {
    enableTcpKeepAlive(this)
    soTimeout = RELAY_READ_IDLE_MILLIS
}

open class RecoverableSessionFailure(message: String, cause: Throwable? = null) : Exception(message, cause)
class RelayTransportFailure(message: String, cause: Throwable? = null) : RecoverableSessionFailure(message, cause)
class IndeterminateOperationException(message: String) : Exception(message)

internal class RelayFrames(
    private val readLine: () -> String?,
    private val writeFrame: (JSONObject) -> Unit,
    private val nonceFactory: () -> String = { UUID.randomUUID().toString() },
) {
    fun readApplicationFrame(stage: String): JSONObject {
        var outstandingPing: String? = null
        while (true) {
            val frame = try {
                val line = readLine() ?: throw RelayTransportFailure(
                    "Relay closed connection while waiting for $stage",
                )
                JSONObject(line)
            } catch (_: SocketTimeoutException) {
                if (outstandingPing != null) {
                    throw RelayTransportFailure("Relay heartbeat timed out while waiting for $stage")
                }
                outstandingPing = nonceFactory()
                writeFrame(JSONObject().put("type", "ping").put("nonce", outstandingPing))
                continue
            } catch (cause: RelayTransportFailure) {
                throw cause
            } catch (cause: IOException) {
                throw RelayTransportFailure("Relay transport failed while waiting for $stage", cause)
            }

            when (frame.optString("type")) {
                "ping" -> {
                    val nonce = frame.optString("nonce")
                    if (nonce.isEmpty()) throw RelayTransportFailure("Invalid ping while waiting for $stage")
                    writeFrame(JSONObject().put("type", "pong").put("nonce", nonce))
                }
                "pong" -> {
                    if (frame.optString("nonce") != outstandingPing) {
                        throw RelayTransportFailure("Relay heartbeat nonce mismatch while waiting for $stage")
                    }
                    outstandingPing = null
                }
                else -> return frame
            }
        }
    }
}
