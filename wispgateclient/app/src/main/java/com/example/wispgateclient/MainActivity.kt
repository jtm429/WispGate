package com.example.wispgateclient

import android.os.Bundle
import android.webkit.WebView
import android.webkit.JavascriptInterface
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.example.wispgateclient.ui.theme.WispGateClientTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WispGateClientTheme {
                WispGateApp(RelayClient(this))
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

    if (server == null) {
        SetupScreen(
            onSave = { host, key ->
                val info = RelayClient.ServerInfo(host.trim(), key.trim())
                client.saveServer(info)
                server = info
            },
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
            onBack = { selected = null; html = null },
        )
        return
    }

    LaunchedEffect(server) {
        loading = true
        error = null
        try {
            wisps = client.listWisps(server!!)
        } catch (cause: Throwable) {
            error = cause.message ?: "Unable to connect to relay"
        } finally {
            loading = false
        }
    }

    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Text("WispGate", style = MaterialTheme.typography.headlineMedium)
        Text("Available Wisps", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))
        if (loading) CircularProgressIndicator()
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (!loading && wisps.isEmpty() && error == null) Text("No Wisps are currently connected.")
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(wisps) { wisp ->
                Card(Modifier.fillMaxWidth().clickable {
                    selected = wisp
                    scope.launch {
                        try {
                            html = client.requestState(server!!, wisp).html
                        } catch (cause: Throwable) {
                            error = cause.message ?: "Unable to request Wisp state"
                            selected = null
                        }
                    }
                }) {
                    Column(Modifier.padding(16.dp)) {
                        Text(wisp.name, style = MaterialTheme.typography.titleLarge)
                        Text(wisp.description)
                    }
                }
            }
        }
    }
}

@Composable
private fun SetupScreen(onSave: (String, String) -> Unit) {
    var host by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Set up relay", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(host, { host = it }, label = { Text("Relay IP or hostname") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(key, { key = it }, label = { Text("Relay public key") }, singleLine = true)
        Spacer(Modifier.height(20.dp))
        Button(enabled = host.isNotBlank() && key.isNotBlank(), onClick = { onSave(host, key) }) {
            Text("Save and connect")
        }
    }
}

@Composable
private fun WebAppScreen(wisp: RelayClient.Wisp, html: String, onAction: (String) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = onBack) { Text("Back") }
            Text(wisp.name, Modifier.padding(start = 12.dp), style = MaterialTheme.typography.titleLarge)
        }
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                WebView(context).apply {
                    settings.javaScriptEnabled = true
                    addJavascriptInterface(object {
                        @JavascriptInterface
                        fun submit(action: String) = onAction(action)
                    }, "WispGate")
                }
            },
            update = { view -> view.loadDataWithBaseURL("https://wisp.local/", html, "text/html", "UTF-8", null) },
        )
    }
}
