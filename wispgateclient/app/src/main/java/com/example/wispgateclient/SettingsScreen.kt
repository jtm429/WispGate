package com.example.wispgateclient

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun SettingsScreen(
    initial: RelayClient.ServerInfo,
    onUpdate: () -> Unit,
    updating: Boolean,
    updateMessage: String?,
    onSave: (RelayClient.ServerInfo) -> Unit,
    onCancel: () -> Unit,
) {
    var host by remember(initial) { mutableStateOf(initial.host) }
    var key by remember(initial) { mutableStateOf(initial.publicKey) }
    var controlPort by remember(initial) { mutableStateOf(initial.controlPort.toString()) }
    var relayPort by remember(initial) { mutableStateOf(initial.relayPort.toString()) }
    var updateToken by remember(initial) { mutableStateOf(initial.updateToken) }
    val valid = host.isNotBlank() && key.isNotBlank() &&
        controlPort.toIntOrNull() != null && relayPort.toIntOrNull() != null

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Relay settings", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(host, { host = it }, label = { Text("Relay IP or hostname") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(key, { key = it }, label = { Text("Relay public key") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(controlPort, { controlPort = it }, label = { Text("Control port") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(relayPort, { relayPort = it }, label = { Text("Relay port") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(updateToken, { updateToken = it }, label = { Text("Server update token") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        Button(enabled = updateToken.isNotBlank() && !updating, onClick = onUpdate) {
            Text(if (updating) "Updating…" else "Update server from GitHub")
        }
        updateMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(20.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onCancel) { Text("Cancel") }
            Button(
                enabled = valid,
                onClick = {
                    onSave(RelayClient.ServerInfo(host.trim(), key.trim(), controlPort.toInt(), relayPort.toInt(), updateToken.trim()))
                },
            ) { Text("Save and reconnect") }
        }
    }
}
