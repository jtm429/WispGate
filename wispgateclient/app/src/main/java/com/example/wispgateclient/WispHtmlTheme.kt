package com.example.wispgateclient

import android.content.Context
import java.util.Locale

object WispHtmlTheme {
    private const val OPT_OUT_MARKER = "wispgate-theme"
    private val htmlTag = Regex("<html\\b[^>]*>", RegexOption.IGNORE_CASE)
    private val headEnd = Regex("</head>", RegexOption.IGNORE_CASE)
    private val optOut = Regex(
        "<meta\\b[^>]*$OPT_OUT_MARKER[^>]*(?:custom|off)[^>]*>",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val explicitHtmlOptOut = Regex(
        "data-wispgate-theme\\s*=\\s*[\\\"'](?:custom|off)[\\\"']",
        setOf(RegexOption.IGNORE_CASE),
    )

    fun apply(context: Context, html: String, darkTheme: Boolean): String {
        if (optOut.containsMatchIn(html) || explicitHtmlOptOut.containsMatchIn(html)) {
            return html
        }

        val css = context.resources.openRawResource(R.raw.wispgate_wisp_theme)
            .bufferedReader()
            .use { it.readText() }
        val theme = if (darkTheme) "dark" else "light"
        val markedHtml = addThemeMarker(html, theme)
        val style = "<style data-wispgate-host-theme>\n$css\n</style>"
        return if (headEnd.containsMatchIn(markedHtml)) {
            headEnd.replaceFirst(markedHtml, "$style</head>")
        } else {
            "$style$markedHtml"
        }
    }

    private fun addThemeMarker(html: String, theme: String): String {
        val match = htmlTag.find(html)
        if (match == null) {
            return "<html data-wispgate-theme=\"$theme\"><head></head><body>$html</body></html>"
        }

        val tag = match.value
        val markedTag = if (tag.contains("data-wispgate-theme", ignoreCase = true)) {
            Regex(
                "data-wispgate-theme\\s*=\\s*[\\\"'][^\\\"']*[\\\"']",
                RegexOption.IGNORE_CASE,
            ).replace(tag, "data-wispgate-theme=\"$theme\"")
        } else {
            tag.dropLast(1) + " data-wispgate-theme=\"$theme\">"
        }
        return html.replaceRange(match.range, markedTag)
    }
}
