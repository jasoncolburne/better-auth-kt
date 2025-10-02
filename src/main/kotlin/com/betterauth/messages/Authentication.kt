package com.betterauth.messages

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class StartAuthenticationRequestPayload(
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
data class StartAuthenticationRequestData(
    val payload: StartAuthenticationRequestPayload,
)

class StartAuthenticationRequest(
    val payload: StartAuthenticationRequestPayload,
) : SerializableMessage() {
    override suspend fun serialize(): String =
        Json.encodeToString(
            StartAuthenticationRequestData.serializer(),
            StartAuthenticationRequestData(payload),
        )

    companion object {
        fun parse(message: String): StartAuthenticationRequest {
            val json = Json.decodeFromString<StartAuthenticationRequestData>(message)
            return StartAuthenticationRequest(json.payload)
        }
    }
}

@Serializable
data class StartAuthenticationResponseData(
    val authentication: AuthenticationData,
) {
    @Serializable
    data class AuthenticationData(
        val nonce: String,
    )
}

class StartAuthenticationResponse(
    response: StartAuthenticationResponseData,
    responseKeyHash: String,
    nonce: String,
) : ServerResponse<StartAuthenticationResponseData>(
        response,
        responseKeyHash,
        nonce,
        ServerPayload.serializer(StartAuthenticationResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): StartAuthenticationResponse =
            parse<StartAuthenticationResponseData, StartAuthenticationResponse>(message) { response, responseKeyHash, nonce ->
                StartAuthenticationResponse(response, responseKeyHash, nonce)
            } as StartAuthenticationResponse
    }
}

@Serializable
data class FinishAuthenticationRequestData(
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

class FinishAuthenticationRequest(
    request: FinishAuthenticationRequestData,
    nonce: String,
) : ClientRequest<FinishAuthenticationRequestData>(request, nonce, ClientPayload.serializer(FinishAuthenticationRequestData.serializer())) {
    companion object {
        fun parse(message: String): FinishAuthenticationRequest =
            parse<FinishAuthenticationRequestData, FinishAuthenticationRequest>(message) { request, nonce ->
                FinishAuthenticationRequest(request, nonce)
            } as FinishAuthenticationRequest
    }
}

@Serializable
data class FinishAuthenticationResponseData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val token: String,
    )
}

class FinishAuthenticationResponse(
    response: FinishAuthenticationResponseData,
    responseKeyHash: String,
    nonce: String,
) : ServerResponse<FinishAuthenticationResponseData>(
        response,
        responseKeyHash,
        nonce,
        ServerPayload.serializer(FinishAuthenticationResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): FinishAuthenticationResponse =
            parse<FinishAuthenticationResponseData, FinishAuthenticationResponse>(message) { response, responseKeyHash, nonce ->
                FinishAuthenticationResponse(response, responseKeyHash, nonce)
            } as FinishAuthenticationResponse
    }
}
