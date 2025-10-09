package com.betterauth.implementation

import com.betterauth.interfaces.Timestamper
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

class Rfc3339Nano : Timestamper {
    private val isoFormat =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS").apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

    override fun format(date: Date): String {
        val isoString = isoFormat.format(date)
        // Extend milliseconds (3 digits) to nanoseconds (9 digits) by appending 6 zeros
        return "${isoString}000000Z"
    }

    override fun parse(dateString: String): Date = Date.parse(dateString).let { Date(it) }

    override fun now(): Date = Date()
}
