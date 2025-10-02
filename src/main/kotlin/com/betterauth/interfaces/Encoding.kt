package com.betterauth.interfaces

import java.util.Date

interface Timestamper {
    fun format(date: Date): String

    fun parse(dateString: String): Date

    fun now(): Date
}

interface TokenEncoder {
    suspend fun encode(obj: String): String

    suspend fun decode(rawToken: String): String
}

interface IdentityVerifier {
    suspend fun verify(
        identity: String,
        publicKey: String,
        rotationHash: String,
        extraData: String? = null,
    )
}
