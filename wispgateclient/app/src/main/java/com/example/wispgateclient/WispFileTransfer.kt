package com.example.wispgateclient

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

private object Base64Url {
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun encode(data: ByteArray): String {
        val output = StringBuilder((data.size * 4 + 2) / 3)
        var index = 0
        while (index < data.size) {
            val first = data[index++].toInt() and 255
            val second = if (index < data.size) data[index++].toInt() and 255 else -1
            val third = if (index < data.size) data[index++].toInt() and 255 else -1
            output.append(alphabet[first ushr 2])
            output.append(alphabet[((first and 3) shl 4) or if (second >= 0) second ushr 4 else 0])
            if (second >= 0) output.append(alphabet[((second and 15) shl 2) or if (third >= 0) third ushr 6 else 0])
            if (third >= 0) output.append(alphabet[third and 63])
        }
        return output.toString()
    }

    fun decode(value: String): ByteArray {
        val output = ByteArrayOutputStream(value.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (character in value) {
            val decoded = alphabet.indexOf(character)
            require(decoded >= 0) { "Invalid base64url file chunk" }
            buffer = (buffer shl 6) or decoded
            bits += 6
            if (bits >= 8) {
                bits -= 8
                output.write((buffer ushr bits) and 255)
            }
        }
        return output.toByteArray()
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
    }

    private val transfers = mutableMapOf<String, StagedFileAction>()

    @Synchronized
    fun begin(actionJson: String, manifestJson: String): String {
        require(transfers.size < MAX_ACTIVE_TRANSFERS) { "Too many active file transfers" }
        val actionData = JSONObject(actionJson)
        val manifests = JSONArray(manifestJson)
        require(manifests.length() in 1..MAX_FILES) { "A file action requires between 1 and $MAX_FILES files" }
        val transferId = UUID.randomUUID().toString()
        val directory = cacheDirectory.resolve("wispgate-file-actions").resolve(transferId)
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
        require(chunk.size <= MAX_CHUNK_BYTES && file.received + chunk.size <= file.size) { "File chunk exceeds the declared size" }
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
    fun begin(wispId: String, action: StagedFileAction): JSONObject {
        val files = JSONArray()
        action.files.forEach { file ->
            files.put(
                JSONObject()
                    .put("id", file.id)
                    .put("field", file.field)
                    .put("name", file.name)
                    .put("content_type", file.contentType)
                    .put("size", file.size),
            )
        }
        return JSONObject()
            .put("wisp_id", wispId)
            .put("action", "file_begin")
            .put("transfer_id", action.transferId)
            .put("action_data", action.actionData)
            .put("files", files)
    }

    fun chunk(wispId: String, transferId: String, fileId: String, offset: Long, data: ByteArray): JSONObject =
        JSONObject()
            .put("wisp_id", wispId)
            .put("action", "file_chunk")
            .put("transfer_id", transferId)
            .put("file_id", fileId)
            .put("offset", offset)
            .put("data", Base64Url.encode(data))

    fun commit(wispId: String, transferId: String): JSONObject =
        JSONObject()
            .put("wisp_id", wispId)
            .put("action", "file_commit")
            .put("transfer_id", transferId)
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
        const chunkSize = 24 * 1024;
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
