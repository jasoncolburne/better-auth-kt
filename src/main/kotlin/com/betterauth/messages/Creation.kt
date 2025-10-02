package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class CreationRequestData(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
        val publicKey: String,
        val recoveryHash: String,
        val rotationHash: String,
    )
}

class CreationRequest(
    request: CreationRequestData,
    nonce: String,
) : ClientRequest<CreationRequestData>(request, nonce, ClientPayload.serializer(CreationRequestData.serializer())) {
    companion object {
        fun parse(message: String): CreationRequest =
            parse<CreationRequestData, CreationRequest>(message) { request, nonce ->
                CreationRequest(request, nonce)
            } as CreationRequest
    }
}

@Serializable
class CreationResponseData

class CreationResponse(
    response: CreationResponseData,
    responseKeyHash: String,
    nonce: String,
) : ServerResponse<CreationResponseData>(response, responseKeyHash, nonce, ServerPayload.serializer(CreationResponseData.serializer())) {
    companion object {
        fun parse(message: String): CreationResponse =
            parse<CreationResponseData, CreationResponse>(message) { response, responseKeyHash, nonce ->
                CreationResponse(response, responseKeyHash, nonce)
            } as CreationResponse
    }
}
