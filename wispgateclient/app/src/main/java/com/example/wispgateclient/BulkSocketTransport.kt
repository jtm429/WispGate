package com.example.wispgateclient

import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket

/** Sends one prepared ciphertext through the relay's dedicated opaque bulk socket. */
object BulkSocketTransport {
    private const val CONNECT_TIMEOUT_MILLIS = 15_000
    private const val TRANSFER_TIMEOUT_MILLIS = 10 * 60_000

    fun send(
        host: String,
        port: Int,
        recipient: String,
        sessionToken: String,
        upload: PreparedBulkUpload,
    ) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MILLIS)
            socket.soTimeout = TRANSFER_TIMEOUT_MILLIS
            val input = BufferedReader(InputStreamReader(socket.getInputStream()))
            val output = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
            output.write(
                JSONObject()
                    .put("type", "bulk")
                    .put("session_token", sessionToken)
                    .put("ticket", upload.ticket)
                    .put("role", "sender")
                    .put("peer", recipient)
                    .put("length", upload.ciphertextSize)
                    .toString(),
            )
            output.newLine()
            output.flush()

            val ready = input.readJson("bulk relay readiness")
            if (!ready.optBoolean("ok") || ready.optString("type") != "bulk_ready") {
                error(ready.optString("error", "Bulk relay rejected transfer"))
            }
            val written = upload.encryptTo(socket.getOutputStream())
            socket.getOutputStream().flush()
            require(written == upload.ciphertextSize) { "Bulk ciphertext length mismatch" }

            val complete = input.readJson("bulk relay completion")
            if (!complete.optBoolean("ok") || complete.optString("type") != "bulk_complete") {
                error(complete.optString("error", "Bulk relay did not complete transfer"))
            }
        }
    }

    private fun BufferedReader.readJson(stage: String): JSONObject =
        readLine()?.let(::JSONObject) ?: error("Relay closed connection while waiting for $stage")
}
