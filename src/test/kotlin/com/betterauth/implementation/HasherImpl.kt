package com.betterauth.implementation

import com.betterauth.interfaces.Hasher

class HasherImpl : Hasher {
    override suspend fun sum(message: String): String {
        val bytes = message.toByteArray(Charsets.UTF_8)
        val hash = Blake3Hasher.sum256(bytes)
        val padded = byteArrayOf(0) + hash
        val base64 = Base64Encoder.encode(padded)

        return "E${base64.substring(1)}"
    }
}
