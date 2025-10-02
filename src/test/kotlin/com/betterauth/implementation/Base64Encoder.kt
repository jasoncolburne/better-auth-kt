package com.betterauth.implementation

import java.util.Base64

object Base64Encoder {
    fun encode(data: ByteArray): String {
        val base64 = Base64.getEncoder().encodeToString(data)
        return base64.replace('/', '_').replace('+', '-')
    }

    fun decode(base64: String): ByteArray = Base64.getDecoder().decode(base64.replace('_', '/').replace('-', '+'))
}
