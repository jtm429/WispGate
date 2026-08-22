package com.example.wispgateclient

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.IconButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.example.wispgateclient.ui.theme.WispGateClientTheme
import java.io.ByteArrayInputStream
import kotlinx.coroutines.launch
import kotlinx.coroutines.coroutineScope


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        StagedFileCache.sweepOnce(cacheDir)
        enableEdgeToEdge()
        setContent {
            WispGateClientTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    WispGateApp(RelayClient(this))
                }
            }
        }
    }
}

@Composable
private fun WispGateApp(client: RelayClient) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var server by remember { mutableStateOf(client.savedServer()) }
    var wisps by remember { mutableStateOf<List<RelayClient.Wisp>>(emptyList()) }
    var selected by remember { mutableStateOf<RelayClient.Wisp?>(null) }
    var wispState by remember { mutableStateOf<RelayClient.WispState?>(null) }
    val wispStateOwner = remember { WispStateOwner() }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var connected by remember { mutableStateOf(false) }
    var settingsOpen by remember { mutableStateOf(false) }



    fun replaceWispState(next: RelayClient.WispState?) {
        wispState = next
        wispStateOwner.replace(next)
    }

    DisposableEffect(Unit) {
        onDispose { wispStateOwner.clear() }
    }

    LaunchedEffect(Unit) {
        BulkTransferService.results.collect { result ->
            var accepted = false
            try {
                if (selected?.id != result.wispId) return@collect
                result.state?.let {
                    replaceWispState(it)
                    accepted = true
                }
                result.error?.let { error = it }
            } finally {
                if (!accepted) result.state?.cleanup()
            }
        }
    }

    if (server == null) {
        SetupScreen(
            onSave = { host, key, controlPort, relayPort, bulkPort ->
                val info = RelayClient.ServerInfo(
                    host.trim(), key.trim(), controlPort.toInt(), relayPort.toInt(), bulkPort.toInt(),
                )
                client.saveServer(info)
                server = info
            },
        )
        return
    }

    if (settingsOpen) {
        SettingsScreen(
            initial = server!!,
            onSave = { info ->
                client.saveServer(info)
                server = info
                settingsOpen = false
                selected = null
                replaceWispState(null)
            },
            onCancel = { settingsOpen = false },
        )
        return
    }

    if (selected != null && wispState != null) {
        WebAppScreen(
            wisp = selected!!,
            state = wispState!!,
            error = error,
            onAction = { action ->
                scope.launch {
                    error = null
                    try {
                        val next = client.sendAction(server!!, selected!!, action)
                        replaceWispState(next)
                        if (selected?.id == RelayClient.MANAGEMENT_WISP_ID &&
                            runCatching { org.json.JSONObject(action).optString("action") }.getOrNull() == "update_server"
                        ) {
                            error = "Update request sent; the relay may restart briefly."
                        }
                    } catch (cause: Throwable) {
                        error = cause.message ?: "Unable to send Wisp action"
                    }
                }
            },
            onFileAction = { action ->
                Log.i("WispFileTransfer", "native upload queued transfer=${action.transferId} files=${action.files.size}")
                try {
                    BulkTransferService.enqueue(
                        context,
                        BulkTransferJob(server!!, selected!!, action),
                    )
                } catch (cause: Throwable) {
                    Log.e("WispFileTransfer", "unable to queue transfer=${action.transferId}", cause)
                    error = cause.message ?: "Unable to queue Wisp file action"
                }
            },
            onBack = { selected = null; replaceWispState(null) },
        )
        return
    }

    suspend fun refresh() {
        loading = true
        error = null
        try {
            val result = client.connectAndListWisps(server!!)
            wisps = result.wisps
            connected = true
        } catch (cause: Throwable) {
            connected = false
            wisps = emptyList()
            error = cause.message ?: "Unable to connect to relay"
        } finally {
            loading = false
        }
    }

    LaunchedEffect(server) {
        coroutineScope {
            launch {
                client.catalogUpdates.collect { catalog ->
                    wisps = catalog
                    connected = true
                    error = null
                }
            }
            refresh()
        }
    }

    val refreshState = rememberPullToRefreshState()
    val statusText = when {
        loading -> "Connecting to relay…"
        !connected -> "Not connected to relay"
        wisps.isEmpty() -> "Connected to relay · no Wisps available"
        else -> "Connected to relay · ${wisps.size} Wisp${if (wisps.size == 1) "" else "s"} available"
    }

    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(20.dp)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("WispGate", style = MaterialTheme.typography.headlineMedium)
            IconButton(onClick = { settingsOpen = true }) {
                androidx.compose.material3.Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Relay settings",
                )
            }
        }
        Text("Available Wisps", style = MaterialTheme.typography.titleMedium)
        Text(
            statusText,
            color = if (connected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
        )

        if (!loading && !connected) {
            Button(onClick = { scope.launch { refresh() } }) {
                Text("Retry connection")
            }
        }
        Spacer(Modifier.height(12.dp))
        PullToRefreshBox(
            isRefreshing = loading,
            onRefresh = { scope.launch { refresh() } },
            state = refreshState,
            modifier = Modifier.fillMaxSize(),
        ) {
            Column(Modifier.fillMaxSize()) {
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (!loading && connected && wisps.isEmpty()) {
                    Text("The relay is reachable, but no Wisps are currently connected.")
                }
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(wisps) { wisp ->
                        Card(Modifier.fillMaxWidth().clickable {
                            selected = wisp
                            scope.launch {
                                try {
                                    replaceWispState(client.requestState(server!!, wisp))
                                } catch (cause: Throwable) {
                                    Log.e("WispGate", "Unable to request Wisp state", cause)
                                    error = cause.message ?: "Unable to request Wisp state"
                                    selected = null
                                }
                            }
                        }) {
                            Column(Modifier.padding(16.dp)) {
                                Text(wisp.name, style = MaterialTheme.typography.titleLarge)
                                Text(wisp.description, style = MaterialTheme.typography.bodyMedium)
                                if (wisp.id == RelayClient.MANAGEMENT_WISP_ID) {
                                    Text("Server-owned management · not a real Wisp")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SetupScreen(onSave: (String, String, String, String, String) -> Unit) {
    var host by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }

    var controlPort by remember { mutableStateOf("443") }
    var relayPort by remember { mutableStateOf("4443") }
    var bulkPort by remember { mutableStateOf("4444") }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Set up relay", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(host, { host = it }, label = { Text("Relay IP or hostname") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(key, { key = it }, label = { Text("Relay public key") }, singleLine = true)
        Spacer(Modifier.height(12.dp))

        Spacer(Modifier.height(12.dp))
        OutlinedTextField(controlPort, { controlPort = it }, label = { Text("Control port") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(relayPort, { relayPort = it }, label = { Text("Relay port") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(bulkPort, { bulkPort = it }, label = { Text("Bulk port") }, singleLine = true)
        Spacer(Modifier.height(20.dp))
        Button(
            enabled = host.isNotBlank() && key.isNotBlank() && controlPort.toIntOrNull() != null &&
                relayPort.toIntOrNull() != null && bulkPort.toIntOrNull() != null,
            onClick = { onSave(host, key, controlPort, relayPort, bulkPort) },
        ) {
            Text("Save and connect")
        }
    }
}

@Composable
private fun WebAppScreen(
    wisp: RelayClient.Wisp,
    state: RelayClient.WispState,
    error: String?,
    onAction: (String) -> Unit,
    onFileAction: (StagedFileAction) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val darkTheme = isSystemInDarkTheme()
    val pendingFileChooser = remember { PendingFileChooser<Array<Uri>>() }
    val fileTransferStager = remember(context.cacheDir) { FileTransferStager(context.cacheDir, onFileAction) }
    val fileChooserLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        pendingFileChooser.complete(WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data))
    }
    DisposableEffect(Unit) {
        onDispose {
            pendingFileChooser.cancel()
            fileTransferStager.cancelAll()
        }
    }
    val themedHtml = remember(state.html, darkTheme) {
        WispHtmlRuntime.apply(WispHtmlTheme.apply(context, state.html, darkTheme))
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = onBack) { Text("Back") }
            Text(wisp.name, Modifier.padding(start = 12.dp), style = MaterialTheme.typography.titleLarge)
        }
        error?.let {
            Text(
                it,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
                color = if (it.startsWith("Update request sent")) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.error,
            )
        }
        androidx.compose.runtime.key(state) {
            AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                WebView(context).apply {
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    webViewClient = object : WebViewClient() {
                        override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? {
                            val uri = request.url
                            if (!state.isWispLocalUrl(uri.toString())) return null
                            if (uri.scheme == "https" && uri.path?.startsWith("/_wispgate/assets/") == true) {
                                val asset = state.assetForUrl(uri.toString())
                                asset?.let {
                                    runCatching {
                                        WebResourceResponse(it.contentType, null, it.path.inputStream())
                                    }.getOrNull()?.let { response -> return response }
                                }
                            }
                            return WebResourceResponse(
                                "text/plain", "UTF-8", 404, "Not Found", emptyMap(),
                                ByteArrayInputStream("Unknown Wisp asset".toByteArray()),
                            )
                        }

                        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean {
                            val uri = request.url
                            if (state.isWispLocalUrl(uri.toString())) return true
                            if (uri.scheme in setOf("about", "data", "blob", "javascript")) {
                                return false
                            }
                            if (request.isForMainFrame && uri.scheme in setOf("http", "https")) {
                                runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, uri)) }
                            }
                            return true
                        }
                    }
                    webChromeClient = object : WebChromeClient() {
                        override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
                            Log.w(
                                "WispWebView",
                                "${consoleMessage.messageLevel()} ${consoleMessage.message()} @${consoleMessage.lineNumber()}",
                            )
                            return true
                        }

                        override fun onShowFileChooser(
                            webView: WebView?,
                            filePathCallback: android.webkit.ValueCallback<Array<Uri>>?,
                            fileChooserParams: FileChooserParams?,
                        ): Boolean {
                            if (filePathCallback == null || fileChooserParams == null) return false
                            pendingFileChooser.replace(filePathCallback::onReceiveValue)
                            return try {
                                fileChooserLauncher.launch(fileChooserParams.createIntent())
                                true
                            } catch (_: ActivityNotFoundException) {
                                pendingFileChooser.cancel()
                                false
                            }
                        }
                    }
                    addJavascriptInterface(object {
                        @JavascriptInterface
                        fun submit(action: String) = onAction(action)

                        @JavascriptInterface
                        fun beginFileAction(action: String, manifest: String): String {
                            Log.i("WispFileTransfer", "bridge begin requested")
                            return fileTransferStager.begin(action, manifest).also {
                                Log.i("WispFileTransfer", "bridge staged transfer=$it")
                            }
                        }

                        @JavascriptInterface
                        fun appendFileChunk(transferId: String, fileId: String, offset: Long, data: String): Long =
                            fileTransferStager.append(transferId, fileId, offset, data)

                        @JavascriptInterface
                        fun finishFileAction(transferId: String) {
                            Log.i("WispFileTransfer", "bridge finish transfer=$transferId")
                            fileTransferStager.finish(transferId)
                        }

                        @JavascriptInterface
                        fun cancelFileAction(transferId: String) {
                            Log.w("WispFileTransfer", "bridge cancel transfer=$transferId")
                            fileTransferStager.cancel(transferId)
                        }
                    }, "_WispGateNative")
                }
            },
            update = { view -> view.loadDataWithBaseURL("https://wisp.local/", themedHtml, "text/html", "UTF-8", null) },
            onRelease = { view ->
                view.removeJavascriptInterface("_WispGateNative")
                view.stopLoading()
                view.destroy()
            },
        )
        }
    }
}
