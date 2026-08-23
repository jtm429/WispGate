package com.example.wispgateclient

import com.example.wispgateclient.wisp.*

import org.junit.Assert.assertEquals
import org.junit.Test

class RelayClientTest {
    @Test
    fun managementCatalogEntryUsesExplicitClaimAction() {
        assertEquals("management", RelayClient.MANAGEMENT_WISP_ID)
    }
}
