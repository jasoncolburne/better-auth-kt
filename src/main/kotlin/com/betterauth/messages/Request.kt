package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ClientAccess(
    val nonce: String,
)

@Serializable
data class ClientPayload<T>(
    val access: ClientAccess,
    val request: T,
)

@Serializable
data class ClientRequestData<T>(
    val payload: ClientPayload<T>,
    val signature: String? = null,
)

abstract class ClientRequest<T>(
    request: T,
    nonce: String,
    private val payloadSerializer: kotlinx.serialization.KSerializer<ClientPayload<T>>,
) : SignableMessage() {
    private val clientPayload: ClientPayload<T>

    init {
        val access = ClientAccess(nonce)
        clientPayload =
            ClientPayload(
                access = access,
                request = request,
            )
        payload = clientPayload
    }

    override fun composePayload(): String = Json.encodeToString(payloadSerializer, clientPayload)

    companion object {
        inline fun <reified T, reified U : ClientRequest<T>> parse(
            message: String,
            constructor: (T, String) -> U,
        ): ClientRequest<T> {
            val json = Json.decodeFromString<ClientRequestData<T>>(message)
            val result = constructor(json.payload.request, json.payload.access.nonce)
            result.signature = json.signature

            return result
        }
    }
}
