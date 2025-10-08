package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class AccessRequestPayload<T>(
    val access: AccessData,
    val request: T,
) {
    @Serializable
    data class AccessData(
        val nonce: String,
        val timestamp: String,
        val token: String,
    )
}

@Serializable
data class AccessRequestData<T>(
    val payload: AccessRequestPayload<T>,
    val signature: String? = null,
)

class AccessRequest<T>(
    val accessPayload: AccessRequestPayload<T>,
    private val payloadSerializer: kotlinx.serialization.KSerializer<AccessRequestPayload<T>>,
) : SignableMessage() {
    init {
        payload = accessPayload
    }

    val accessRequestPayload: AccessRequestPayload<T>
        get() = accessPayload

    override fun composePayload(): String = Json.encodeToString(payloadSerializer, accessPayload)
}
