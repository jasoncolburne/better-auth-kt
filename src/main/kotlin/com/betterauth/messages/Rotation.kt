package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class RotateAuthenticationKeyRequestData(
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

class RotateAuthenticationKeyRequest(
    request: RotateAuthenticationKeyRequestData,
    nonce: String,
) : ClientRequest<RotateAuthenticationKeyRequestData>(
        request,
        nonce,
        ClientPayload.serializer(RotateAuthenticationKeyRequestData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RotateAuthenticationKeyRequest =
            parse<RotateAuthenticationKeyRequestData, RotateAuthenticationKeyRequest>(message) { request, nonce ->
                RotateAuthenticationKeyRequest(request, nonce)
            } as RotateAuthenticationKeyRequest
    }
}

@Serializable
class RotateAuthenticationKeyResponseData

class RotateAuthenticationKeyResponse(
    response: RotateAuthenticationKeyResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<RotateAuthenticationKeyResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(RotateAuthenticationKeyResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RotateAuthenticationKeyResponse =
            parse<RotateAuthenticationKeyResponseData, RotateAuthenticationKeyResponse>(message) { response, serverIdentity, nonce ->
                RotateAuthenticationKeyResponse(response, serverIdentity, nonce)
            } as RotateAuthenticationKeyResponse
    }
}
