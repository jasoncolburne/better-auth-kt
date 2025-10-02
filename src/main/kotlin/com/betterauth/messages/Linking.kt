package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class LinkContainerPayload(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
        val publicKey: String,
        val rotationHash: String,
    )
}

@Serializable
data class LinkContainerData(
    val payload: LinkContainerPayload,
    val signature: String? = null,
)

class LinkContainer(
    private val linkPayload: LinkContainerPayload,
) : SignableMessage() {
    init {
        payload = linkPayload
    }

    val linkContainerPayload: LinkContainerPayload
        get() = linkPayload

    override fun composePayload(): String = Json.encodeToString(LinkContainerPayload.serializer(), linkPayload)

    companion object {
        fun parse(message: String): LinkContainer {
            val json = Json.decodeFromString<LinkContainerData>(message)
            val result = LinkContainer(json.payload)
            result.signature = json.signature

            return result
        }
    }
}

@Serializable
data class LinkDeviceRequestData(
    val authentication: AuthenticationData,
    val link: LinkContainerData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
    )
}

class LinkDeviceRequest(
    request: LinkDeviceRequestData,
    nonce: String,
) : ClientRequest<LinkDeviceRequestData>(request, nonce, ClientPayload.serializer(LinkDeviceRequestData.serializer())) {
    companion object {
        fun parse(message: String): LinkDeviceRequest =
            parse<LinkDeviceRequestData, LinkDeviceRequest>(message) { request, nonce ->
                LinkDeviceRequest(request, nonce)
            } as LinkDeviceRequest
    }
}

@Serializable
class LinkDeviceResponseData

class LinkDeviceResponse(
    response: LinkDeviceResponseData,
    responseKeyHash: String,
    nonce: String,
) : ServerResponse<LinkDeviceResponseData>(
        response,
        responseKeyHash,
        nonce,
        ServerPayload.serializer(LinkDeviceResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): LinkDeviceResponse =
            parse<LinkDeviceResponseData, LinkDeviceResponse>(message) { response, responseKeyHash, nonce ->
                LinkDeviceResponse(response, responseKeyHash, nonce)
            } as LinkDeviceResponse
    }
}
