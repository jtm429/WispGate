package com.example.wispgateclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PendingFileChooserTest {
    @Test
    fun replacingARequestCancelsThePreviousRequest() {
        val chooser = PendingFileChooser<String>()
        val firstResults = mutableListOf<String?>()
        val secondResults = mutableListOf<String?>()

        chooser.replace { firstResults.add(it) }
        chooser.replace { secondResults.add(it) }

        assertEquals(listOf<String?>(null), firstResults)
        assertEquals(emptyList<String?>(), secondResults)
    }

    @Test
    fun completingARequestDeliversOnceAndClearsIt() {
        val chooser = PendingFileChooser<String>()
        val results = mutableListOf<String?>()

        chooser.replace { results.add(it) }
        chooser.complete("content://selected")
        chooser.complete("content://ignored")

        assertEquals(listOf("content://selected"), results)
        assertNull(chooser.pending)
    }

    @Test
    fun cancellingARequestReturnsNullAndClearsIt() {
        val chooser = PendingFileChooser<String>()
        val results = mutableListOf<String?>()

        chooser.replace { results.add(it) }
        chooser.cancel()

        assertEquals(listOf<String?>(null), results)
        assertNull(chooser.pending)
    }
}
