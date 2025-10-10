package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class CreateAccountRequestData(
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

class CreateAccountRequest(
    request: CreateAccountRequestData,
    nonce: String,
) : ClientRequest<CreateAccountRequestData>(request, nonce, ClientPayload.serializer(CreateAccountRequestData.serializer())) {
    companion object {
        fun parse(message: String): CreateAccountRequest =
            parse<CreateAccountRequestData, CreateAccountRequest>(message) { request, nonce ->
                CreateAccountRequest(request, nonce)
            } as CreateAccountRequest
    }
}

@Serializable
class CreateAccountResponseData

class CreateAccountResponse(
    response: CreateAccountResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<CreateAccountResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(CreateAccountResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): CreateAccountResponse =
            parse<CreateAccountResponseData, CreateAccountResponse>(message) { response, serverIdentity, nonce ->
                CreateAccountResponse(response, serverIdentity, nonce)
            } as CreateAccountResponse
    }
}

@Serializable
data class RecoverAccountRequestData(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val device: String,
        val identity: String,
        val publicKey: String,
        val recoveryHash: String,
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
    serverIdentity: String,
    nonce: String,
) : ServerResponse<RecoverAccountResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(RecoverAccountResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RecoverAccountResponse =
            parse<RecoverAccountResponseData, RecoverAccountResponse>(message) { response, serverIdentity, nonce ->
                RecoverAccountResponse(response, serverIdentity, nonce)
            } as RecoverAccountResponse
    }
}

@Serializable
data class DeleteAccountRequestData(
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

class DeleteAccountRequest(
    request: DeleteAccountRequestData,
    nonce: String,
) : ClientRequest<DeleteAccountRequestData>(request, nonce, ClientPayload.serializer(DeleteAccountRequestData.serializer())) {
    companion object {
        fun parse(message: String): DeleteAccountRequest =
            parse<DeleteAccountRequestData, DeleteAccountRequest>(message) { request, nonce ->
                DeleteAccountRequest(request, nonce)
            } as DeleteAccountRequest
    }
}

@Serializable
class DeleteAccountResponseData

class DeleteAccountResponse(
    response: DeleteAccountResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<DeleteAccountResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(DeleteAccountResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): DeleteAccountResponse =
            parse<DeleteAccountResponseData, DeleteAccountResponse>(message) { response, serverIdentity, nonce ->
                DeleteAccountResponse(response, serverIdentity, nonce)
            } as DeleteAccountResponse
    }
}
