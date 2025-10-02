package com.betterauth.messages

import com.betterauth.interfaces.ServerTimeLockStore
import com.betterauth.interfaces.Timestamper
import com.betterauth.interfaces.TokenEncoder
import com.betterauth.interfaces.Verifier
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Date

@Serializable
data class AccessTokenData<T>(
    val identity: String,
    val publicKey: String,
    val rotationHash: String,
    val issuedAt: String,
    val expiry: String,
    val refreshExpiry: String,
    val attributes: T,
)

class AccessToken<T>(
    val identity: String,
    val publicKey: String,
    val rotationHash: String,
    val issuedAt: String,
    val expiry: String,
    val refreshExpiry: String,
    val attributes: T,
    private val tokenSerializer: kotlinx.serialization.KSerializer<AccessTokenData<T>>,
) : SignableMessage() {
    private val tokenData: AccessTokenData<T>

    init {
        tokenData =
            AccessTokenData(
                identity = identity,
                publicKey = publicKey,
                rotationHash = rotationHash,
                issuedAt = issuedAt,
                expiry = expiry,
                refreshExpiry = refreshExpiry,
                attributes = attributes,
            )
    }

    override fun composePayload(): String = Json.encodeToString(tokenSerializer, tokenData)

    suspend fun serializeToken(tokenEncoder: TokenEncoder): String {
        if (signature == null) {
            throw IllegalStateException("missing signature")
        }

        val token = tokenEncoder.encode(composePayload())
        return signature + token
    }

    suspend fun verifyToken(
        verifier: Verifier,
        publicKey: String,
        timestamper: Timestamper,
    ) {
        verify(verifier, publicKey)

        val now = timestamper.now()
        val issuedAt = timestamper.parse(this.issuedAt)
        val expiry = timestamper.parse(this.expiry)

        if (now < issuedAt) {
            throw IllegalStateException("token from future")
        }

        if (now > expiry) {
            throw IllegalStateException("token expired")
        }
    }

    companion object {
        suspend inline fun <reified T> parse(
            message: String,
            publicKeyLength: Int,
            tokenEncoder: TokenEncoder,
        ): AccessToken<T> {
            val signature = message.substring(0, publicKeyLength)
            val rest = message.substring(publicKeyLength)

            val tokenString = tokenEncoder.decode(rest)

            val json = Json.decodeFromString<AccessTokenData<T>>(tokenString)
            val token =
                AccessToken(
                    json.identity,
                    json.publicKey,
                    json.rotationHash,
                    json.issuedAt,
                    json.expiry,
                    json.refreshExpiry,
                    json.attributes,
                    AccessTokenData.serializer(kotlinx.serialization.serializer()),
                )

            token.signature = signature

            return token
        }
    }
}

@Serializable
data class AccessRequestPayload<T>(
    val access: AccessData,
    val request: T,
) {
    @Serializable
    data class AccessData(
        val nonce: String,
        val timestamp: String,
        val token: String,
    )
}

@Serializable
data class AccessRequestData<T>(
    val payload: AccessRequestPayload<T>,
    val signature: String? = null,
)

class AccessRequest<T>(
    val accessPayload: AccessRequestPayload<T>,
    private val payloadSerializer: kotlinx.serialization.KSerializer<AccessRequestPayload<T>>,
) : SignableMessage() {
    init {
        payload = accessPayload
    }

    val accessRequestPayload: AccessRequestPayload<T>
        get() = accessPayload

    override fun composePayload(): String = Json.encodeToString(payloadSerializer, accessPayload)

    suspend inline fun <reified T> verify(
        nonceStore: ServerTimeLockStore,
        verifier: Verifier,
        tokenVerifier: Verifier,
        serverAccessPublicKey: String,
        tokenEncoder: TokenEncoder,
        timestamper: Timestamper,
    ): Pair<String, T> {
        val accessToken =
            AccessToken.parse<T>(
                accessPayload.access.token,
                tokenVerifier.signatureLength,
                tokenEncoder,
            )

        accessToken.verifyToken(tokenVerifier, serverAccessPublicKey, timestamper)
        verify(verifier, accessToken.publicKey)

        val now = timestamper.now()
        val accessTime = timestamper.parse(accessPayload.access.timestamp)
        val expiry = Date(accessTime.time + nonceStore.lifetimeInSeconds * 1000L)

        if (now > expiry) {
            throw IllegalStateException("stale request")
        }

        if (now < accessTime) {
            throw IllegalStateException("request from future")
        }

        nonceStore.reserve(accessPayload.access.nonce)

        return Pair(accessToken.identity, accessToken.attributes)
    }

    companion object {
        inline fun <reified T> parse(message: String): AccessRequest<T> {
            val json = Json.decodeFromString<AccessRequestData<T>>(message)
            val result = AccessRequest(json.payload, AccessRequestPayload.serializer(kotlinx.serialization.serializer()))
            result.signature = json.signature

            return result
        }
    }
}
