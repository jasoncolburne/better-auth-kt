package com.betterauth.implementation

import io.github.rctcwyvrn.blake3.Blake3

object Blake3Hasher {
    suspend fun sum256(bytes: ByteArray): ByteArray {
        val hasher = Blake3.newInstance()
        hasher.update(bytes)
        return hasher.digest()
    }
}
