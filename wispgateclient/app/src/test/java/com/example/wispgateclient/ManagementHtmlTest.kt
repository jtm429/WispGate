package com.example.wispgateclient

import com.example.wispgateclient.wisp.*

import org.junit.Assert.assertEquals
import org.junit.Test

class ManagementHtmlTest {
    @Test
    fun managementStateIsOpaqueServerOwnedWebAppContent() {
        val serverHtml = "<main><button>Claim Administrator</button></main>"
        val state = RelayClient.WispState(RelayClient.MANAGEMENT_WISP_ID, serverHtml)
        assertEquals(RelayClient.MANAGEMENT_WISP_ID, state.wispId)
        assertEquals(serverHtml, state.html)
    }
}
