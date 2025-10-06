package com.betterauth.messages

import kotlinx.serialization.Serializable

@Serializable
data class RefreshAccessTokenRequestData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val publicKey: String,
        val rotationHash: String,
        val token: String,
    )
}

class RefreshAccessTokenRequest(
    request: RefreshAccessTokenRequestData,
    nonce: String,
) : ClientRequest<RefreshAccessTokenRequestData>(request, nonce, ClientPayload.serializer(RefreshAccessTokenRequestData.serializer())) {
    companion object {
        fun parse(message: String): RefreshAccessTokenRequest =
            parse<RefreshAccessTokenRequestData, RefreshAccessTokenRequest>(message) { request, nonce ->
                RefreshAccessTokenRequest(request, nonce)
            } as RefreshAccessTokenRequest
    }
}

@Serializable
data class RefreshAccessTokenResponseData(
    val access: AccessData,
) {
    @Serializable
    data class AccessData(
        val token: String,
    )
}

class RefreshAccessTokenResponse(
    response: RefreshAccessTokenResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<RefreshAccessTokenResponseData>(
        response,
        serverIdentity,
        nonce,
        ServerPayload.serializer(RefreshAccessTokenResponseData.serializer()),
    ) {
    companion object {
        fun parse(message: String): RefreshAccessTokenResponse =
            parse<RefreshAccessTokenResponseData, RefreshAccessTokenResponse>(message) { response, serverIdentity, nonce ->
                RefreshAccessTokenResponse(response, serverIdentity, nonce)
            } as RefreshAccessTokenResponse
    }
}
