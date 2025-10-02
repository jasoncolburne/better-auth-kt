package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class RecoverAccountRequestData(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
        val publicKey: String,
        val recoveryKey: String,
        val rotationHash: String,
    )
}

class RecoverAccountRequest(
    request: RecoverAccountRequestData,
    nonce: String,
) : ClientRequest<RecoverAccountRequestData>(request, nonce, ClientPayload.serializer(RecoverAccountRequestData.serializer())) {
    companion object {
        fun parse(message: String): RecoverAccountRequest =
            parse<RecoverAccountRequestData, RecoverAccountRequest>(message) { request, nonce ->
                RecoverAccountRequest(request, nonce)
            } as RecoverAccountRequest
    }
}

@Serializable
class RecoverAccountResponseData

class RecoverAccountResponse(
    response: RecoverAccountResponseData,
    responseKeyHash: String,
    nonce: String,
) : ServerResponse<RecoverAccountResponseData>(
        response,
        responseKeyHash,
        nonce,
        ServerPayload.serializer(RecoverAccountResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RecoverAccountResponse =
            parse<RecoverAccountResponseData, RecoverAccountResponse>(message) { response, responseKeyHash, nonce ->
                RecoverAccountResponse(response, responseKeyHash, nonce)
            } as RecoverAccountResponse
    }
}
