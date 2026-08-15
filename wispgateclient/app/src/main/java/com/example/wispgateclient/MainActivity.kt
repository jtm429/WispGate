package com.example.wispgateclient

import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.JavascriptInterface
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.coroutineScope


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
    val scope = rememberCoroutineScope()
    var server by remember { mutableStateOf(client.savedServer()) }
    var wisps by remember { mutableStateOf<List<RelayClient.Wisp>>(emptyList()) }
    var selected by remember { mutableStateOf<RelayClient.Wisp?>(null) }
    var html by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }
    var connected by remember { mutableStateOf(false) }
    var settingsOpen by remember { mutableStateOf(false) }
    var updatingServer by remember { mutableStateOf(false) }
    var updateMessage by remember { mutableStateOf<String?>(null) }


    if (server == null) {
        SetupScreen(
            onSave = { host, key, controlPort, relayPort ->
                val info = RelayClient.ServerInfo(host.trim(), key.trim(), controlPort.toInt(), relayPort.toInt())
                client.saveServer(info)
                server = info
            },
        )
        return
    }

    if (settingsOpen) {
        SettingsScreen(
            initial = server!!,
            onUpdate = {
                scope.launch {
                    updatingServer = true
                    updateMessage = null
                    try {
                        client.updateServer(server!!)
                        updateMessage = "Server update started."
                    } catch (cause: Throwable) {
                        updateMessage = cause.message ?: "Unable to start server update"
                    } finally {
                        updatingServer = false
                    }
                }
            },
            updating = updatingServer,
            updateMessage = updateMessage,
            onSave = { info ->
                client.saveServer(info)
                server = info
                settingsOpen = false
                selected = null
                html = null
            },
            onCancel = { settingsOpen = false },
        )
        return
    }

    if (selected != null && html != null) {
        WebAppScreen(
            wisp = selected!!,
            html = html!!,
            onAction = { action ->
                scope.launch {
                    try {
                        html = client.sendAction(server!!, selected!!, action).html
                    } catch (cause: Throwable) {
                        error = cause.message ?: "Unable to send Wisp action"
                    }
                }
            },
            onFileAction = { action ->
                val upload = scope.launch {
                    try {
                        html = client.sendFileAction(server!!, selected!!, action).html
                    } catch (cause: Throwable) {
                        error = cause.message ?: "Unable to send Wisp file action"
                    }
                }
                upload.invokeOnCompletion { action.cleanup() }
            },
            onBack = { selected = null; html = null },
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
                                    html = client.requestState(server!!, wisp).html
                                } catch (cause: Throwable) {
                                    Log.e("WispGate", "Unable to request Wisp state", cause)
                                    error = cause.message ?: "Unable to request Wisp state"
                                    selected = null
                                }
                            }
                        }) {
                            Column(Modifier.padding(16.dp)) {
                                Text(wisp.name, style = MaterialTheme.typography.titleLarge)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SetupScreen(onSave: (String, String, String, String) -> Unit) {
    var host by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    var controlPort by remember { mutableStateOf("443") }
    var relayPort by remember { mutableStateOf("4443") }
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
        OutlinedTextField(controlPort, { controlPort = it }, label = { Text("Control port") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(relayPort, { relayPort = it }, label = { Text("Relay port") }, singleLine = true)
        Spacer(Modifier.height(20.dp))
        Button(enabled = host.isNotBlank() && key.isNotBlank() && controlPort.toIntOrNull() != null && relayPort.toIntOrNull() != null, onClick = { onSave(host, key, controlPort, relayPort) }) {
            Text("Save and connect")
        }
    }
}

@Composable
private fun WebAppScreen(
    wisp: RelayClient.Wisp,
    html: String,
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
    val themedHtml = remember(html, darkTheme) {
        WispHtmlRuntime.apply(WispHtmlTheme.apply(context, html, darkTheme))
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = onBack) { Text("Back") }
            Text(wisp.name, Modifier.padding(start = 12.dp), style = MaterialTheme.typography.titleLarge)
        }
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                WebView(context).apply {
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    webViewClient = WebViewClient()
                    webChromeClient = object : WebChromeClient() {
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
                        fun beginFileAction(action: String, manifest: String): String =
                            fileTransferStager.begin(action, manifest)

                        @JavascriptInterface
                        fun appendFileChunk(transferId: String, fileId: String, offset: Long, data: String): Long =
                            fileTransferStager.append(transferId, fileId, offset, data)

                        @JavascriptInterface
                        fun finishFileAction(transferId: String) = fileTransferStager.finish(transferId)

                        @JavascriptInterface
                        fun cancelFileAction(transferId: String) = fileTransferStager.cancel(transferId)
                    }, "_WispGateNative")
                }
            },
            update = { view -> view.loadDataWithBaseURL("https://wisp.local/", themedHtml, "text/html", "UTF-8", null) },
        )
    }
}
