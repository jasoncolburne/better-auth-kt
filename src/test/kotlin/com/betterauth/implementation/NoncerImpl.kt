package com.betterauth.implementation

import com.betterauth.interfaces.Noncer
import java.security.SecureRandom

class NoncerImpl : Noncer {
    private val random = SecureRandom()

    override suspend fun generate128(): String {
        val entropy = ByteArray(16)
        random.nextBytes(entropy)

        val padded = byteArrayOf(0, 0) + entropy
        val base64 = Base64Encoder.encode(padded)

        return "0A${base64.substring(2)}"
    }
}
