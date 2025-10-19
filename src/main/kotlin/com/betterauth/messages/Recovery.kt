package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class ChangeRecoveryKeyRequestData(
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

class ChangeRecoveryKeyRequest(
    request: ChangeRecoveryKeyRequestData,
    nonce: String,
) : ClientRequest<ChangeRecoveryKeyRequestData>(
        request,
        nonce,
        ClientPayload.serializer(ChangeRecoveryKeyRequestData.serializer()),
    ) {
    companion object {
        fun parse(message: String): ChangeRecoveryKeyRequest =
            parse<ChangeRecoveryKeyRequestData, ChangeRecoveryKeyRequest>(message) { request, nonce ->
                ChangeRecoveryKeyRequest(request, nonce)
            } as ChangeRecoveryKeyRequest
    }
}

@Serializable
class ChangeRecoveryKeyResponseData

class ChangeRecoveryKeyResponse(
    response: ChangeRecoveryKeyResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<ChangeRecoveryKeyResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(ChangeRecoveryKeyResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): ChangeRecoveryKeyResponse =
            parse<ChangeRecoveryKeyResponseData, ChangeRecoveryKeyResponse>(message) { response, serverIdentity, nonce ->
                ChangeRecoveryKeyResponse(response, serverIdentity, nonce)
            } as ChangeRecoveryKeyResponse
    }
}
