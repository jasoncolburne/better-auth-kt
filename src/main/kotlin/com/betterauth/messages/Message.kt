package com.betterauth.messages

import com.betterauth.interfaces.SigningKey
import com.betterauth.interfaces.Verifier

interface MessageSerializable {
    suspend fun serialize(): String
}

abstract class SerializableMessage : MessageSerializable {
    abstract override suspend fun serialize(): String
}

abstract class SignableMessage : SerializableMessage() {
    open var payload: Any? = null
    var signature: String? = null

    abstract fun composePayload(): String

    override suspend fun serialize(): String {
        if (signature == null) {
            throw IllegalStateException("null signature")
        }

        return """{"payload":${composePayload()},"signature":"$signature"}"""
    }

    suspend fun sign(signer: SigningKey) {
        signature = signer.sign(composePayload())
    }

    suspend fun verify(
        verifier: Verifier,
        publicKey: String,
    ) {
        if (signature == null) {
            throw IllegalStateException("null signature")
        }

        verifier.verify(composePayload(), signature!!, publicKey)
    }
}
