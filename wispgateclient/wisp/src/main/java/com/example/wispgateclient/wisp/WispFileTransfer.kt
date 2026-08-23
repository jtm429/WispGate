package com.example.wispgateclient.wisp

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

internal object OperationProtocol {
    enum class Status { RUNNING, COMPLETED }

    fun userAction(wispId: String, actionData: JSONObject, operationId: String): JSONObject =
        JSONObject()
            .put("wisp_id", wispId)
            .put("action", "user_action")
            .put("operation_id", operationId)
            .put("action_data", actionData)

    fun resume(wispId: String, operationId: String): JSONObject =
        JSONObject()
            .put("wisp_id", wispId)
            .put("action", "operation_resume")
            .put("operation_id", operationId)

    fun recoveryStatus(status: String?, operationId: String): Status = when (status) {
        "running" -> Status.RUNNING
        "completed" -> Status.COMPLETED
        else -> throw IndeterminateOperationException(
            "Operation $operationId is ${status ?: "unknown"}; retry explicitly",
        )
    }
}

object StagedFileCache {
    private const val DIRECTORY_NAME = "wispgate-file-actions"
    private val sweptThisProcess = AtomicBoolean(false)

    fun directory(cacheDirectory: File): File = cacheDirectory.resolve(DIRECTORY_NAME)

    fun sweepOnce(cacheDirectory: File) {
        if (sweptThisProcess.compareAndSet(false, true)) {
            directory(cacheDirectory).deleteRecursively()
        }
    }
}

private object Base64Url {
    fun encode(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    fun decode(value: String): ByteArray = try {
        Base64.getUrlDecoder().decode(value)
    } catch (cause: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid base64url file chunk", cause)
    }
}

data class StagedUpload(
    val id: String,
    val field: String,
    val name: String,
    val contentType: String,
    val size: Long,
    val path: File,
    var received: Long = 0,
)

data class StagedFileAction(
    val transferId: String,
    val actionData: JSONObject,
    val directory: File,
    val files: List<StagedUpload>,
) {
    fun cleanup() {
        directory.deleteRecursively()
    }
}

class FileTransferStager(
    private val cacheDirectory: File,
    private val onComplete: (StagedFileAction) -> Unit,
) {
    companion object {
        const val MAX_FILES = 32
        const val MAX_ACTIVE_TRANSFERS = 4
        const val MAX_TOTAL_BYTES = 256L * 1024 * 1024
        const val MAX_CHUNK_BYTES = 24 * 1024
        const val MAX_STAGING_CHUNK_BYTES = 256 * 1024
    }

    private val transfers = mutableMapOf<String, StagedFileAction>()

    @Synchronized
    fun begin(actionJson: String, manifestJson: String): String {
        require(transfers.size < MAX_ACTIVE_TRANSFERS) { "Too many active file transfers" }
        val actionData = JSONObject(actionJson)
        val manifests = JSONArray(manifestJson)
        require(manifests.length() in 1..MAX_FILES) { "A file action requires between 1 and $MAX_FILES files" }
        val transferId = UUID.randomUUID().toString()
        val directory = StagedFileCache.directory(cacheDirectory).resolve(transferId)
        require(directory.mkdirs()) { "Unable to create temporary upload directory" }
        val files = mutableListOf<StagedUpload>()
        var total = 0L
        val reserved = transfers.values.sumOf { action -> action.files.sumOf(StagedUpload::size) }
        try {
            for (index in 0 until manifests.length()) {
                val manifest = manifests.getJSONObject(index)
                val id = manifest.getString("id")
                val field = manifest.getString("field")
                val name = manifest.getString("name")
                val contentType = manifest.optString("content_type", "application/octet-stream")
                val size = manifest.getLong("size")
                require(
                    id.isNotBlank() && id.length <= 128 &&
                        field.isNotBlank() && field.length <= 128 &&
                        name.isNotBlank() && name.length <= 512 &&
                        contentType.length <= 128 && size >= 0
                ) { "Invalid file manifest" }
                require(files.none { it.id == id }) { "Duplicate file id" }
                require(size <= MAX_TOTAL_BYTES - reserved - total) { "File action exceeds the configured size limit" }
                total += size
                val path = directory.resolve("$index.upload")
                require(path.createNewFile()) { "Unable to create temporary upload file" }
                files += StagedUpload(id, field, name, contentType, size, path)
            }
            transfers[transferId] = StagedFileAction(transferId, actionData, directory, files)
            return transferId
        } catch (cause: Throwable) {
            directory.deleteRecursively()
            throw cause
        }
    }

    @Synchronized
    fun append(transferId: String, fileId: String, offset: Long, encoded: String): Long {
        val action = transfers[transferId] ?: throw IllegalArgumentException("Unknown file transfer")
        val file = action.files.firstOrNull { it.id == fileId } ?: throw IllegalArgumentException("Unknown file in transfer")
        require(offset == file.received) { "Unexpected file offset; expected ${file.received}" }
        val chunk = Base64Url.decode(encoded)
        require(chunk.size <= MAX_STAGING_CHUNK_BYTES && file.received + chunk.size <= file.size) {
            "File chunk exceeds the declared size"
        }
        RandomAccessFile(file.path, "rw").use { output ->
            output.seek(file.received)
            output.write(chunk)
        }
        file.received += chunk.size
        return file.received
    }

    @Synchronized
    fun finish(transferId: String) {
        val action = transfers[transferId] ?: throw IllegalArgumentException("Unknown file transfer")
        require(action.files.all { it.received == it.size }) { "File transfer is incomplete" }
        transfers.remove(transferId)
        try {
            onComplete(action)
        } catch (cause: Throwable) {
            action.cleanup()
            throw cause
        }
    }

    @Synchronized
    fun cancel(transferId: String) {
        transfers.remove(transferId)?.cleanup()
    }

    @Synchronized
    fun cancelAll() {
        transfers.values.forEach(StagedFileAction::cleanup)
        transfers.clear()
    }
}

object FileActionProtocol {
    fun begin(wispId: String, action: StagedFileAction, prepared: List<PreparedBulkUpload>): JSONObject {
        require(prepared.map { it.file.id } == action.files.map { it.id }) { "Prepared files do not match staged files" }
        val files = JSONArray()
        prepared.forEach { upload ->
            val file = upload.file
            files.put(
                JSONObject()
                    .put("id", file.id)
                    .put("field", file.field)
                    .put("name", file.name)
                    .put("content_type", file.contentType)
                    .put("size", file.size)
                    .put(
                        "bulk",
                        JSONObject()
                            .put("algorithm", "SESSION-A256GCM-v2")
                            .put("nonce", upload.nonce)
                            .put("ciphertext_size", upload.ciphertextSize),
                    ),
            )
        }
        return JSONObject()
            .put("wisp_id", wispId)
            .put("action", "file_begin")
            .put("operation_id", action.transferId)
            .put("transfer_id", action.transferId)
            .put("action_data", action.actionData)
            .put("files", files)
    }
}

object WispHtmlRuntime {
    private val headStart = Regex("<head\\b[^>]*>", RegexOption.IGNORE_CASE)

    private val script = """
<script data-wispgate-runtime>
(() => {
  const native = window._WispGateNative;
  const encode = bytes => {
    let binary = "";
    const block = 8192;
    for (let i = 0; i < bytes.length; i += block) {
      binary += String.fromCharCode(...bytes.subarray(i, i + block));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const addValue = (target, name, value) => {
    if (!(name in target)) target[name] = value;
    else if (Array.isArray(target[name])) target[name].push(value);
    else target[name] = [target[name], value];
  };
  window.WispGate = Object.freeze({
    submit(action) {
      native.submit(typeof action === "string" ? action : JSON.stringify(action));
    },
    async submitForm(form, action = {}) {
      const values = Object.assign({}, action);
      const files = [];
      for (const [field, value] of new FormData(form).entries()) {
        if (value instanceof File && value.name) {
          files.push({ id: `file-${'$'}{files.length}`, field, file: value });
        } else {
          addValue(values, field, value);
        }
      }
      if (!files.length) {
        native.submit(JSON.stringify(values));
        return;
      }
      const manifest = files.map(({id, field, file}) => ({
        id, field, name: file.name, content_type: file.type || "application/octet-stream", size: file.size
      }));
      const transferId = native.beginFileAction(JSON.stringify(values), JSON.stringify(manifest));
      try {
        const chunkSize = 256 * 1024;
        let sent = 0;
        const total = files.reduce((sum, item) => sum + item.file.size, 0);
        for (const {id, file} of files) {
          for (let offset = 0; offset < file.size; offset += chunkSize) {
            const bytes = new Uint8Array(await file.slice(offset, offset + chunkSize).arrayBuffer());
            native.appendFileChunk(transferId, id, offset, encode(bytes));
            sent += bytes.length;
            window.dispatchEvent(new CustomEvent("wispgate-upload-progress", {detail: {transferId, sent, total}}));
          }
        }
        native.finishFileAction(transferId);
      } catch (error) {
        native.cancelFileAction(transferId);
        throw error;
      }
    }
  });
})();
</script>
""".trim()

    fun apply(html: String): String {
        if (html.contains("data-wispgate-runtime")) return html
        val match = headStart.find(html)
        return if (match == null) "$script$html" else html.replaceRange(match.range.last + 1, match.range.last + 1, script)
    }
}
