package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ServerAccess(
    val nonce: String,
    val serverIdentity: String,
)

@Serializable
data class ServerPayload<T>(
    val access: ServerAccess,
    val response: T,
)

@Serializable
data class ServerResponseData<T>(
    val payload: ServerPayload<T>,
    val signature: String? = null,
)

abstract class ServerResponse<T>(
    response: T,
    serverIdentity: String,
    nonce: String,
    private val payloadSerializer: kotlinx.serialization.KSerializer<ServerPayload<T>>,
) : SignableMessage() {
    private val serverPayload: ServerPayload<T>

    init {
        val access = ServerAccess(nonce, serverIdentity)
        serverPayload =
            ServerPayload(
                access = access,
                response = response,
            )
        payload = serverPayload
    }

    override fun composePayload(): String = Json.encodeToString(payloadSerializer, serverPayload)

    companion object {
        inline fun <reified T, reified U : ServerResponse<T>> parse(
            message: String,
            constructor: (T, String, String) -> U,
        ): ServerResponse<T> {
            val jsonParser =
                Json {
                    ignoreUnknownKeys = true
                }
            val json = jsonParser.decodeFromString<ServerResponseData<T>>(message)
            val result =
                constructor(
                    json.payload.response,
                    json.payload.access.serverIdentity,
                    json.payload.access.nonce,
                )
            result.signature = json.signature

            return result
        }
    }
}

@Serializable
class ScannableResponseData

class ScannableResponse(
    response: ScannableResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<ScannableResponseData>(response, serverIdentity, nonce, ServerPayload.serializer(ScannableResponseData.serializer())) {
    companion object {
        fun parse(message: String): ScannableResponse =
            parse<ScannableResponseData, ScannableResponse>(message) { response, serverIdentity, nonce ->
                ScannableResponse(response, serverIdentity, nonce)
            } as ScannableResponse
    }
}
