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
    fun buildsGenericProtocolBodiesWithoutAppSpecificFields() {
        val directory = Files.createTempDirectory("wisp-protocol-test").toFile()
        val file = directory.resolve("0.upload").apply { writeText("hello") }
        val action = StagedFileAction(
            "transfer-1",
            JSONObject().put("type", "anything"),
            directory,
            listOf(StagedUpload("f", "attachment", "hello.txt", "text/plain", 5, file)),
        )

        val begin = FileActionProtocol.begin("wisp-1", action)
        val chunk = FileActionProtocol.chunk("wisp-1", "transfer-1", "f", 0, byteArrayOf(1, 2, 3))
        val commit = FileActionProtocol.commit("wisp-1", "transfer-1")

        assertEquals("file_begin", begin.getString("action"))
        assertEquals(5, begin.getJSONArray("files").getJSONObject(0).getLong("size"))
        assertEquals("file_chunk", chunk.getString("action"))
        assertEquals("AQID", chunk.getString("data"))
        assertEquals("file_commit", commit.getString("action"))
        action.cleanup()
    }
}
