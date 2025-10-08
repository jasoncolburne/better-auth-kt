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
        val publicKey: String,
        val rotationHash: String,
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
    serverIdentity: String,
    nonce: String,
) : ServerResponse<LinkDeviceResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(LinkDeviceResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): LinkDeviceResponse =
            parse<LinkDeviceResponseData, LinkDeviceResponse>(message) { response, serverIdentity, nonce ->
                LinkDeviceResponse(response, serverIdentity, nonce)
            } as LinkDeviceResponse
    }
}

@Serializable
data class UnlinkDeviceRequestData(
    val authentication: AuthenticationData,
    val link: LinkData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
        val publicKey: String,
        val rotationHash: String,
    )

    @Serializable
    data class LinkData(
        val device: String,
    )
}

class UnlinkDeviceRequest(
    request: UnlinkDeviceRequestData,
    nonce: String,
) : ClientRequest<UnlinkDeviceRequestData>(request, nonce, ClientPayload.serializer(UnlinkDeviceRequestData.serializer())) {
    companion object {
        fun parse(message: String): UnlinkDeviceRequest =
            parse<UnlinkDeviceRequestData, UnlinkDeviceRequest>(message) { request, nonce ->
                UnlinkDeviceRequest(request, nonce)
            } as UnlinkDeviceRequest
    }
}

@Serializable
class UnlinkDeviceResponseData

class UnlinkDeviceResponse(
    response: UnlinkDeviceResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<UnlinkDeviceResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(UnlinkDeviceResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): UnlinkDeviceResponse =
            parse<UnlinkDeviceResponseData, UnlinkDeviceResponse>(message) { response, serverIdentity, nonce ->
                UnlinkDeviceResponse(response, serverIdentity, nonce)
            } as UnlinkDeviceResponse
    }
}
