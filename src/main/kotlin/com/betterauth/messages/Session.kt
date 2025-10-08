package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class RequestSessionRequestPayload(
    val access: AccessData,
    val request: RequestData,
) {
    @Serializable
    data class AccessData(
        val nonce: String,
    )

    @Serializable
    data class RequestData(
        val authentication: AuthenticationData,
    )

    @Serializable
    data class AuthenticationData(
        val identity: String,
    )
}

@Serializable
data class RequestSessionRequestData(
    val payload: RequestSessionRequestPayload,
)

class RequestSessionRequest(
    val payload: RequestSessionRequestPayload,
) : SerializableMessage() {
    override suspend fun serialize(): String =
        Json.encodeToString(
            RequestSessionRequestData.serializer(),
            RequestSessionRequestData(payload),
        )

    companion object {
        fun parse(message: String): RequestSessionRequest {
            val json = Json.decodeFromString<RequestSessionRequestData>(message)
            return RequestSessionRequest(json.payload)
        }
    }
}

@Serializable
data class RequestSessionResponseData(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val nonce: String,
    )
}

class RequestSessionResponse(
    response: RequestSessionResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<RequestSessionResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(RequestSessionResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RequestSessionResponse =
            parse<RequestSessionResponseData, RequestSessionResponse>(message) { response, serverIdentity, nonce ->
                RequestSessionResponse(response, serverIdentity, nonce)
            } as RequestSessionResponse
    }
}

@Serializable
data class CreateSessionRequestData(
    val access: AccessData,
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AccessData(
        val publicKey: String,
        val rotationHash: String,
    )

    @Serializable
    data class AuthenticationData(
        val device: String,
        val nonce: String,
    )
}

class CreateSessionRequest(
    request: CreateSessionRequestData,
    nonce: String,
) : ClientRequest<CreateSessionRequestData>(request, nonce, ClientPayload.serializer(CreateSessionRequestData.serializer())) {
    companion object {
        fun parse(message: String): CreateSessionRequest =
            parse<CreateSessionRequestData, CreateSessionRequest>(message) { request, nonce ->
                CreateSessionRequest(request, nonce)
            } as CreateSessionRequest
    }
}

@Serializable
data class CreateSessionResponseData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val token: String,
    )
}

class CreateSessionResponse(
    response: CreateSessionResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<CreateSessionResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(CreateSessionResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): CreateSessionResponse =
            parse<CreateSessionResponseData, CreateSessionResponse>(message) { response, serverIdentity, nonce ->
                CreateSessionResponse(response, serverIdentity, nonce)
            } as CreateSessionResponse
    }
}

@Serializable
data class RefreshSessionRequestData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val publicKey: String,
        val rotationHash: String,
        val token: String,
    )
}

class RefreshSessionRequest(
    request: RefreshSessionRequestData,
    nonce: String,
) : ClientRequest<RefreshSessionRequestData>(request, nonce, ClientPayload.serializer(RefreshSessionRequestData.serializer())) {
    companion object {
        fun parse(message: String): RefreshSessionRequest =
            parse<RefreshSessionRequestData, RefreshSessionRequest>(message) { request, nonce ->
                RefreshSessionRequest(request, nonce)
            } as RefreshSessionRequest
    }
}

@Serializable
data class RefreshSessionResponseData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val token: String,
    )
}

class RefreshSessionResponse(
    response: RefreshSessionResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<RefreshSessionResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(RefreshSessionResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RefreshSessionResponse =
            parse<RefreshSessionResponseData, RefreshSessionResponse>(message) { response, serverIdentity, nonce ->
                RefreshSessionResponse(response, serverIdentity, nonce)
            } as RefreshSessionResponse
    }
}
