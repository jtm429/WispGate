package com.example.wispgateclient

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Socket
import java.nio.file.Files
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

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
        val identity = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val tlsPin = "a".repeat(64)
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
        val receivedHello = java.util.concurrent.atomic.AtomicReference<JSONObject>()
        val receivedProof = java.util.concurrent.atomic.AtomicReference<JSONObject>()
        val receivedCiphertext = java.util.concurrent.atomic.AtomicReference<ByteArray>()
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        val serverTask = executor.submit {
            server.accept().use { socket ->
                val input = socket.getInputStream()
                fun readFrame(): JSONObject {
                    val bytes = java.io.ByteArrayOutputStream()
                    while (true) {
                        val next = input.read()
                        require(next >= 0) { "sender closed before auth frame" }
                        if (next == '\n'.code) return JSONObject(bytes.toString(Charsets.UTF_8.name()))
                        bytes.write(next)
                    }
                }
                receivedHello.set(readFrame())
                socket.getOutputStream().write("{\"type\":\"auth_challenge\",\"challenge\":\"challenge-1\"}\n".toByteArray())
                socket.getOutputStream().flush()
                receivedProof.set(readFrame())
                socket.getOutputStream().write("{\"ok\":true}\n".toByteArray())
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
            tlsCertSha256 = tlsPin,
            clientId = "android-user",
            identity = identity,
            upload = prepared.single(),
            connect = { _, targetPort, _ -> Socket(java.net.InetAddress.getLoopbackAddress(), targetPort) },
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
        assertEquals("transfer-1", begin.getString("operation_id"))
        assertEquals("RSA-OAEP-256+A256GCM", offer.getString("algorithm"))
        assertTrue(offer.getString("ticket").length >= 16)
        assertEquals("auth_hello", receivedHello.get().getString("type"))
        assertEquals("bulk_sender", receivedHello.get().getString("role"))
        assertEquals("android-user", receivedHello.get().getString("client_id"))
        assertFalse(receivedHello.get().toString().contains("session_token"))
        assertEquals("auth_proof", receivedProof.get().getString("type"))
        assertTrue(receivedProof.get().getString("signature").isNotBlank())
        assertEquals(21, encrypted.size)
        assertEquals("hello", String(decrypt.doFinal(encrypted)))
        assertFalse(begin.toString().contains("file_chunk"))
        action.cleanup()
    }

    @Test
    fun receivesAndAuthenticatesWispAssetIntoLocalCache() {
        val plaintext = ByteArray(1024 * 1024) { (it % 251).toByte() }
        val identity = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val contentKey = javax.crypto.KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        val nonce = ByteArray(12) { it.toByte() }
        val transferId = "asset-transfer"
        val ticket = "asset-ticket-1234567890"
        val fileId = "qr-code"
        val wrapped = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(javax.crypto.Cipher.ENCRYPT_MODE, identity.public, E2EEnvelope.oaepParameters())
        }.doFinal(contentKey)
        val offer = InboundAssetOffer.fromJson(
            transferId,
            JSONObject()
                .put("id", fileId)
                .put("name", "qr.png")
                .put("content_type", "image/png")
                .put("size", plaintext.size)
                .put(
                    "bulk",
                    JSONObject()
                        .put("algorithm", "RSA-OAEP-256+A256GCM")
                        .put("ticket", ticket)
                        .put("encrypted_key", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped))
                        .put("nonce", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(nonce))
                        .put("ciphertext_size", plaintext.size + 16),
                ),
        )
        val encrypt = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(contentKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, nonce),
            )
            updateAAD(offer.aad("wisp-owner", "android-user"))
        }
        val ciphertext = encrypt.doFinal(plaintext)
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
        val receivedHello = java.util.concurrent.atomic.AtomicReference<JSONObject>()
        val receivedProof = java.util.concurrent.atomic.AtomicReference<JSONObject>()
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        val serverTask = executor.submit {
            server.accept().use { socket ->
                val input = socket.getInputStream()
                fun readFrame(): JSONObject {
                    val bytes = java.io.ByteArrayOutputStream()
                    while (true) {
                        val next = input.read()
                        require(next >= 0)
                        if (next == '\n'.code) return JSONObject(bytes.toString(Charsets.UTF_8.name()))
                        bytes.write(next)
                    }
                }
                receivedHello.set(readFrame())
                socket.getOutputStream().write("{\"type\":\"auth_challenge\",\"challenge\":\"challenge-2\"}\n".toByteArray())
                socket.getOutputStream().flush()
                receivedProof.set(readFrame())
                socket.getOutputStream().write("{\"ok\":true}\n".toByteArray())
                socket.getOutputStream().write("{\"ok\":true,\"type\":\"bulk_ready\"}\n".toByteArray())
                socket.getOutputStream().write(ciphertext)
                socket.getOutputStream().flush()
            }
        }
        val directory = Files.createTempDirectory("wisp-asset-receive-test").toFile()
        val tlsPin = "b".repeat(64)

        val received = BulkSocketTransport.receive(
            host = java.net.InetAddress.getLoopbackAddress().hostAddress!!,
            port = server.localPort,
            sender = "wisp-owner",
            recipient = "android-user",
            tlsCertSha256 = tlsPin,
            clientId = "android-user",
            identity = identity,
            offer = offer,
            privateKey = identity.private,
            directory = directory,
            connect = { _, targetPort, _ -> Socket(java.net.InetAddress.getLoopbackAddress(), targetPort) },
        )
        serverTask.get(5, java.util.concurrent.TimeUnit.SECONDS)
        executor.shutdownNow()
        server.close()

        assertEquals("qr-code", received.id)
        assertEquals("image/png", received.contentType)
        assertTrue(received.path.readBytes().contentEquals(plaintext))
        assertEquals("auth_hello", receivedHello.get().getString("type"))
        assertEquals("bulk_receiver", receivedHello.get().getString("role"))
        assertEquals("android-user", receivedHello.get().getString("client_id"))
        assertFalse(receivedHello.get().toString().contains("session_token"))
        assertEquals("auth_proof", receivedProof.get().getString("type"))
        assertTrue(receivedProof.get().getString("signature").isNotBlank())
        directory.deleteRecursively()
    }

    @Test
    fun resolvesOnlyDeclaredWispAssetUrlsForWebViewRendering() {
        val directory = Files.createTempDirectory("wisp-asset-url-test").toFile()
        val path = directory.resolve("opaque.asset").apply { writeText("image") }
        val asset = ReceivedAsset("qr-code", "qr.png", "image/png", path.length(), path)
        val state = RelayClient.WispState("qr", "<img>", mapOf(asset.id to asset), directory)

        assertTrue(state.assetForUrl("https://wisp.local/_wispgate/assets/qr-code") === asset)
        assertEquals(null, state.assetForUrl("https://wisp.local/_wispgate/assets/missing"))
        assertEquals(null, state.assetForUrl("https://example.com/_wispgate/assets/qr-code"))
        assertTrue(state.isWispLocalUrl("https://wisp.local/other"))
        assertTrue(state.isWispLocalUrl("https://WISP.LOCAL/other"))
        assertFalse(state.isWispLocalUrl("https://example.com/other"))

        state.cleanup()
        assertFalse(directory.exists())
    }

    @Test
    fun parsesAssetBeginResponseWithoutEmbeddingFileBytesInHtml() {
        val body = JSONObject()
            .put("wisp_id", "qr")
            .put("response", JSONObject().put("html", "<img src='https://wisp.local/_wispgate/assets/qr-code'>"))
            .put(
                "assets",
                JSONObject()
                    .put("type", "begin")
                    .put("transfer_id", "transfer-1")
                    .put(
                        "files",
                        JSONArray().put(
                            JSONObject()
                                .put("id", "qr-code")
                                .put("name", "qr.png")
                                .put("content_type", "image/png")
                                .put("size", 100)
                                .put(
                                    "bulk",
                                    JSONObject()
                                        .put("algorithm", "RSA-OAEP-256+A256GCM")
                                        .put("ticket", "ticket-1234567890")
                                        .put("encrypted_key", "wrapped")
                                        .put("nonce", "nonce")
                                        .put("ciphertext_size", 116),
                                ),
                        ),
                    ),
            )

        val parsed = InboundAssetProtocol.parse(body)

        assertEquals("qr", parsed.wispId)
        assertTrue(parsed.html.contains("/_wispgate/assets/qr-code"))
        assertEquals("transfer-1", parsed.transferId)
        assertEquals("qr-code", parsed.offers.single().id)
    }

    @Test
    fun rejectsWispAssetIdsThatAreNotSafeUrlSegments() {
        val value = JSONObject()
            .put("name", "qr.png")
            .put("content_type", "image/png")
            .put("size", 3)
            .put(
                "bulk",
                JSONObject()
                    .put("algorithm", "RSA-OAEP-256+A256GCM")
                    .put("ticket", "ticket-1234567890")
                    .put("encrypted_key", "wrapped")
                    .put("nonce", "nonce")
                    .put("ciphertext_size", 19),
            )

        listOf("../qr", "..", "qr%2Fcode").forEach { unsafeId ->
            value.put("id", unsafeId)
            assertThrows(IllegalArgumentException::class.java) {
                InboundAssetOffer.fromJson("transfer-1", value)
            }
        }
    }

    @Test
    fun bulkTransferResultQueueRetainsOneResultForExactlyOneConsumer() = runBlocking {
        val queue = BulkTransferResultQueue()
        val result = BulkTransferResult("transfer-1", "qr", error = "done")

        assertTrue(queue.publish(result))
        assertTrue(queue.results.first() === result)
    }

    @Test
    fun relayOperationsAreSerializedAcrossClientInstances() = runBlocking {
        var active = 0
        var maximumActive = 0

        coroutineScope {
            List(2) {
                async {
                    RelayOperationCoordinator.serialized {
                        active += 1
                        maximumActive = maxOf(maximumActive, active)
                        delay(25)
                        active -= 1
                    }
                }
            }.awaitAll()
        }

        assertEquals(1, maximumActive)
    }

    @Test
    fun wispStateOwnerSynchronouslyCleansEveryReplacedIntermediateState() {
        val firstDirectory = Files.createTempDirectory("wisp-state-first").toFile()
        val secondDirectory = Files.createTempDirectory("wisp-state-second").toFile()
        val first = RelayClient.WispState("qr", "first", assetDirectory = firstDirectory)
        val second = RelayClient.WispState("qr", "second", assetDirectory = secondDirectory)
        val owner = WispStateOwner()

        owner.replace(first)
        owner.replace(second)

        assertFalse(firstDirectory.exists())
        assertTrue(secondDirectory.exists())

        owner.clear()
        assertFalse(secondDirectory.exists())
    }
}
