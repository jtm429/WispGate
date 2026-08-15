package com.example.wispgateclient

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class WispFileTransferTest {
    @Test
    fun sweepsPlaintextLeftByAPreviousProcess() {
        val root = Files.createTempDirectory("wisp-cache-test").toFile()
        val abandoned = StagedFileCache.directory(root).resolve("abandoned").apply { mkdirs() }
        abandoned.resolve("0.upload").writeText("plaintext")

        StagedFileCache.sweepOnce(root)

        assertFalse(StagedFileCache.directory(root).exists())
        root.deleteRecursively()
    }

    @Test
    fun stagesDeclaredChunksAndCompletesOneReusableAction() {
        val root = Files.createTempDirectory("wisp-stager-test").toFile()
        val completed = mutableListOf<StagedFileAction>()
        val stager = FileTransferStager(root, completed::add)
        val manifest = JSONArray().put(
            JSONObject()
                .put("id", "file-1")
                .put("field", "recording")
                .put("name", "voice.ogg")
                .put("content_type", "audio/ogg")
                .put("size", 11),
        )

        val transferId = stager.begin("{\"type\":\"transcribe\"}", manifest.toString())
        assertEquals(6, stager.append(transferId, "file-1", 0, "aGVsbG8g"))
        assertEquals(11, stager.append(transferId, "file-1", 6, "d29ybGQ"))
        stager.finish(transferId)

        val action = completed.single()
        assertEquals("transcribe", action.actionData.getString("type"))
        assertEquals("voice.ogg", action.files.single().name)
        assertEquals("hello world", action.files.single().path.readText())
        action.cleanup()
        assertFalse(action.directory.exists())
        root.deleteRecursively()
    }

    @Test
    fun rejectsOffsetsOrCompletionThatDoNotMatchTheManifest() {
        val root = Files.createTempDirectory("wisp-stager-test").toFile()
        val stager = FileTransferStager(root) { error("must not complete") }
        val manifest = JSONArray().put(
            JSONObject()
                .put("id", "f")
                .put("field", "file")
                .put("name", "x.bin")
                .put("content_type", "application/octet-stream")
                .put("size", 5),
        )
        val transferId = stager.begin("{}", manifest.toString())

        assertTrue(runCatching { stager.append(transferId, "f", 1, "YQ") }.exceptionOrNull() is IllegalArgumentException)
        assertTrue(runCatching { stager.finish(transferId) }.exceptionOrNull() is IllegalArgumentException)
        stager.cancel(transferId)
        root.deleteRecursively()
    }

    @Test
    fun nativeStagingChunksCanBeLargerThanRelayChunks() {
        val root = Files.createTempDirectory("wisp-stager-test").toFile()
        val completed = mutableListOf<StagedFileAction>()
        val stager = FileTransferStager(root, completed::add)
        val bytes = ByteArray(32 * 1024) { (it % 251).toByte() }
        val manifest = JSONArray().put(
            JSONObject().put("id", "f").put("field", "file").put("name", "x.bin")
                .put("content_type", "application/octet-stream").put("size", bytes.size),
        )
        val transferId = stager.begin("{}", manifest.toString())

        val received = stager.append(
            transferId,
            "f",
            0,
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
        )
        stager.finish(transferId)

        assertEquals(bytes.size.toLong(), received)
        assertTrue(completed.single().files.single().path.readBytes().contentEquals(bytes))
        completed.single().cleanup()
        root.deleteRecursively()
    }

    @Test
    fun boundsConcurrentStagedTransfers() {
        val root = Files.createTempDirectory("wisp-stager-test").toFile()
        val stager = FileTransferStager(root) { }
        val manifest = JSONArray().put(
            JSONObject().put("id", "f").put("field", "file").put("name", "x.bin")
                .put("content_type", "application/octet-stream").put("size", 0),
        )
        repeat(FileTransferStager.MAX_ACTIVE_TRANSFERS) {
            stager.begin("{}", manifest.toString())
        }

        val rejected = runCatching { stager.begin("{}", manifest.toString()) }.exceptionOrNull()

        assertTrue(rejected is IllegalArgumentException)
        stager.cancelAll()
        assertFalse(root.resolve("wispgate-file-actions").walkTopDown().any { it.isFile })
        root.deleteRecursively()
    }

    @Test
    fun injectsBasicSubmitAndGenericSubmitFormRuntime() {
        val rendered = WispHtmlRuntime.apply("<html><head></head><body><form></form></body></html>")

        assertTrue(rendered.contains("window.WispGate"))
        assertTrue(rendered.contains("submitForm"))
        assertTrue(rendered.contains("beginFileAction"))
        assertTrue(rendered.contains("file.slice"))
        assertTrue(rendered.contains("native.submit"))
    }

    @Test
    fun foregroundTransferRegistryHandsEachJobToTheServiceOnlyOnce() {
        val directory = Files.createTempDirectory("wisp-service-test").toFile()
        val action = StagedFileAction("transfer-service", JSONObject(), directory, emptyList())
        val job = BulkTransferJob(
            RelayClient.ServerInfo("relay", "key"),
            RelayClient.Wisp("wisp", "Wisp", "", "owner", "peer-key"),
            action,
        )

        BulkTransferJobs.put(job)

        assertTrue(BulkTransferJobs.take(action.transferId) === job)
        assertEquals(null, BulkTransferJobs.take(action.transferId))
        directory.deleteRecursively()
    }

    @Test
    fun foregroundServiceStopsOnlyAfterEveryConcurrentTransferFinishes() {
        val ownership = BulkTransferOwnership()
        ownership.started("older", 1)
        ownership.started("newer", 2)

        assertEquals(null, ownership.finished("newer"))
        assertEquals(2, ownership.finished("older"))
    }

    @Test
    fun foregroundExecutionCleansStagingWhenWakeLockAcquisitionFails() {
        val directory = Files.createTempDirectory("wisp-service-cleanup-test").toFile()
        directory.resolve("0.upload").writeText("plaintext")
        val action = StagedFileAction("cleanup-transfer", JSONObject(), directory, emptyList())

        val failure = runCatching {
            kotlinx.coroutines.runBlocking {
                BulkTransferExecution.run(
                    action = action,
                    acquireWakeLock = { error("wake lock unavailable") },
                    wakeLockHeld = { false },
                    releaseWakeLock = {},
                ) { error("transfer must not start") }
            }
        }.exceptionOrNull()

        assertTrue(failure is IllegalStateException)
        assertFalse(directory.exists())
    }

    @Test
    fun preparesOneHybridEncryptedRawStreamWithoutChunkMessages() {
        val directory = Files.createTempDirectory("wisp-protocol-test").toFile()
        val file = directory.resolve("0.upload").apply { writeText("hello") }
        val action = StagedFileAction(
            "transfer-1",
            JSONObject().put("type", "anything"),
            directory,
            listOf(StagedUpload("f", "attachment", "hello.txt", "text/plain", 5, file)),
        )
        val keyPair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val recipientKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(keyPair.public.encoded)

        val prepared = BulkFileCrypto.prepare(
            sender = "android-user",
            recipient = "wisp-owner",
            transferId = action.transferId,
            files = action.files,
            recipientPublicKey = recipientKey,
        )
        val begin = FileActionProtocol.begin("wisp-1", action, prepared)
        val offer = begin.getJSONArray("files").getJSONObject(0).getJSONObject("bulk")
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
        val receivedHeader = java.util.concurrent.atomic.AtomicReference<JSONObject>()
        val receivedCiphertext = java.util.concurrent.atomic.AtomicReference<ByteArray>()
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        val serverTask = executor.submit {
            server.accept().use { socket ->
                val input = socket.getInputStream()
                val headerBytes = java.io.ByteArrayOutputStream()
                while (true) {
                    val next = input.read()
                    require(next >= 0) { "sender closed before bulk header" }
                    if (next == '\n'.code) break
                    headerBytes.write(next)
                }
                receivedHeader.set(JSONObject(headerBytes.toString(Charsets.UTF_8.name())))
                socket.getOutputStream().write("{\"ok\":true,\"type\":\"bulk_ready\"}\n".toByteArray())
                socket.getOutputStream().flush()
                receivedCiphertext.set(input.readNBytes(prepared.single().ciphertextSize.toInt()))
                socket.getOutputStream().write("{\"ok\":true,\"type\":\"bulk_complete\"}\n".toByteArray())
                socket.getOutputStream().flush()
            }
        }

        BulkSocketTransport.send(
            host = java.net.InetAddress.getLoopbackAddress().hostAddress!!,
            port = server.localPort,
            recipient = "wisp-owner",
            sessionToken = "session-token",
            upload = prepared.single(),
        )
        serverTask.get(5, java.util.concurrent.TimeUnit.SECONDS)
        executor.shutdownNow()
        server.close()
        val encrypted = receivedCiphertext.get()

        val unwrap = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(javax.crypto.Cipher.DECRYPT_MODE, keyPair.private, E2EEnvelope.oaepParameters())
        }
        val fileKey = unwrap.doFinal(java.util.Base64.getUrlDecoder().decode(offer.getString("encrypted_key")))
        val decrypt = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.DECRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(fileKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, java.util.Base64.getUrlDecoder().decode(offer.getString("nonce"))),
            )
            updateAAD(prepared.single().aad())
        }

        assertEquals("file_begin", begin.getString("action"))
        assertEquals("RSA-OAEP-256+A256GCM", offer.getString("algorithm"))
        assertTrue(offer.getString("ticket").length >= 16)
        assertEquals(
            JSONObject()
                .put("type", "bulk")
                .put("session_token", "session-token")
                .put("ticket", prepared.single().ticket)
                .put("role", "sender")
                .put("peer", "wisp-owner")
                .put("length", prepared.single().ciphertextSize)
                .toString(),
            receivedHeader.get().toString(),
        )
        assertEquals(21, encrypted.size)
        assertEquals("hello", String(decrypt.doFinal(encrypted)))
        assertFalse(begin.toString().contains("file_chunk"))
        action.cleanup()
    }
}
