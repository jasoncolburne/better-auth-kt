package com.betterauth.api

import com.betterauth.interfaces.AuthenticationPaths
import com.betterauth.interfaces.ClientRotatingKeyStore
import com.betterauth.interfaces.ClientValueStore
import com.betterauth.interfaces.Hasher
import com.betterauth.interfaces.Network
import com.betterauth.interfaces.Noncer
import com.betterauth.interfaces.SigningKey
import com.betterauth.interfaces.Timestamper
import com.betterauth.interfaces.VerificationKey
import com.betterauth.messages.AccessRequest
import com.betterauth.messages.CreationRequest
import com.betterauth.messages.CreationRequestData
import com.betterauth.messages.CreationResponse
import com.betterauth.messages.FinishAuthenticationRequest
import com.betterauth.messages.FinishAuthenticationRequestData
import com.betterauth.messages.FinishAuthenticationResponse
import com.betterauth.messages.LinkContainer
import com.betterauth.messages.LinkContainerPayload
import com.betterauth.messages.LinkDeviceRequest
import com.betterauth.messages.LinkDeviceRequestData
import com.betterauth.messages.LinkDeviceResponse
import com.betterauth.messages.RecoverAccountRequest
import com.betterauth.messages.RecoverAccountRequestData
import com.betterauth.messages.RecoverAccountResponse
import com.betterauth.messages.RefreshAccessTokenRequest
import com.betterauth.messages.RefreshAccessTokenRequestData
import com.betterauth.messages.RefreshAccessTokenResponse
import com.betterauth.messages.RotateAuthenticationKeyRequest
import com.betterauth.messages.RotateAuthenticationKeyRequestData
import com.betterauth.messages.RotateAuthenticationKeyResponse
import com.betterauth.messages.ScannableResponse
import com.betterauth.messages.SignableMessage
import com.betterauth.messages.StartAuthenticationRequest
import com.betterauth.messages.StartAuthenticationRequestPayload
import com.betterauth.messages.StartAuthenticationResponse

class BetterAuthClient(
    private val crypto: CryptoConfig,
    private val encoding: EncodingConfig,
    private val io: IOConfig,
    private val paths: AuthenticationPaths,
    private val store: StoreConfig,
) {
    data class CryptoConfig(
        val hasher: Hasher,
        val noncer: Noncer,
        val publicKey: PublicKeyConfig,
    )

    data class PublicKeyConfig(
        val response: VerificationKey,
    )

    data class EncodingConfig(
        val timestamper: Timestamper,
    )

    data class IOConfig(
        val network: Network,
    )

    data class StoreConfig(
        val identifier: IdentifierConfig,
        val key: KeyConfig,
        val token: TokenConfig,
    )

    data class IdentifierConfig(
        val device: ClientValueStore,
        val identity: ClientValueStore,
    )

    data class KeyConfig(
        val access: ClientRotatingKeyStore,
        val authentication: ClientRotatingKeyStore,
    )

    data class TokenConfig(
        val access: ClientValueStore,
    )

    suspend fun identity(): String = store.identifier.identity.get()

    suspend fun device(): String = store.identifier.device.get()

    private suspend fun verifyResponse(
        response: SignableMessage,
        publicKeyHash: String,
    ) {
        val publicKey = crypto.publicKey.response.public()
        val hash = crypto.hasher.sum(publicKey)

        if (hash != publicKeyHash) {
            throw IllegalStateException("hash mismatch")
        }

        val verifier = crypto.publicKey.response.verifier()

        response.verify(verifier, publicKey)
    }

    suspend fun createAccount(recoveryHash: String) {
        val (identity, publicKey, rotationHash) =
            store.key.authentication.initialize(recoveryHash)
        val device = crypto.hasher.sum(publicKey)

        val nonce = crypto.noncer.generate128()

        val request =
            CreationRequest(
                CreationRequestData(
                    CreationRequestData.AuthenticationData(
                        device = device,
                        identity = identity,
                        publicKey = publicKey,
                        recoveryHash = recoveryHash,
                        rotationHash = rotationHash,
                    ),
                ),
                nonce,
            )

        request.sign(store.key.authentication.signer())
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.register.create, message)

        val response = CreationResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.CreationResponseData>
        verifyResponse(response, responsePayload.access.responseKeyHash)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.identifier.identity.store(identity)
        store.identifier.device.store(device)
    }

    // happens on the new device
    // send identity by qr code or network from the existing device
    suspend fun generateLinkContainer(identity: String): String {
        val (_, publicKey, rotationHash) = store.key.authentication.initialize()
        val device = crypto.hasher.sum(publicKey)

        store.identifier.identity.store(identity)
        store.identifier.device.store(device)

        val linkContainer =
            LinkContainer(
                LinkContainerPayload(
                    LinkContainerPayload.AuthenticationData(
                        device = device,
                        identity = identity,
                        publicKey = publicKey,
                        rotationHash = rotationHash,
                    ),
                ),
            )

        linkContainer.sign(store.key.authentication.signer())

        return linkContainer.serialize()
    }

    // happens on the existing device (share with qr code + camera)
    // use a 61x61 module layout and a 53x53 module code, centered on the new device, at something
    // like 244x244px (61*4x61*4)
    suspend fun linkDevice(linkContainer: String) {
        val container = LinkContainer.parse(linkContainer)
        val nonce = crypto.noncer.generate128()

        val request =
            LinkDeviceRequest(
                LinkDeviceRequestData(
                    authentication =
                        LinkDeviceRequestData.AuthenticationData(
                            device = store.identifier.device.get(),
                            identity = store.identifier.identity.get(),
                        ),
                    link = com.betterauth.messages.LinkContainerData(container.linkContainerPayload, container.signature),
                ),
                nonce,
            )

        request.sign(store.key.authentication.signer())
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.register.link, message)

        val response = LinkDeviceResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.LinkDeviceResponseData>
        verifyResponse(response, responsePayload.access.responseKeyHash)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }
    }

    suspend fun rotateAuthenticationKey() {
        val (publicKey, rotationHash) = store.key.authentication.rotate()
        val nonce = crypto.noncer.generate128()

        val request =
            RotateAuthenticationKeyRequest(
                RotateAuthenticationKeyRequestData(
                    RotateAuthenticationKeyRequestData.AuthenticationData(
                        device = store.identifier.device.get(),
                        identity = store.identifier.identity.get(),
                        publicKey = publicKey,
                        rotationHash = rotationHash,
                    ),
                ),
                nonce,
            )

        request.sign(store.key.authentication.signer())
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.rotate.authentication, message)

        val response = RotateAuthenticationKeyResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RotateAuthenticationKeyResponseData>
        verifyResponse(response, responsePayload.access.responseKeyHash)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }
    }

    suspend fun authenticate() {
        val startNonce = crypto.noncer.generate128()

        val startRequest =
            StartAuthenticationRequest(
                StartAuthenticationRequestPayload(
                    access = StartAuthenticationRequestPayload.AccessData(startNonce),
                    request =
                        StartAuthenticationRequestPayload.RequestData(
                            authentication =
                                StartAuthenticationRequestPayload.AuthenticationData(
                                    identity = store.identifier.identity.get(),
                                ),
                        ),
                ),
            )

        val startMessage = startRequest.serialize()
        val startReply = io.network.sendRequest(paths.authenticate.start, startMessage)

        val startResponse = StartAuthenticationResponse.parse(startReply)

        @Suppress("UNCHECKED_CAST")
        val startResponsePayload =
            startResponse.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.StartAuthenticationResponseData>
        verifyResponse(startResponse, startResponsePayload.access.responseKeyHash)

        if (startResponsePayload.access.nonce != startNonce) {
            throw IllegalStateException("incorrect nonce")
        }

        val (_, currentKey, nextKeyHash) = store.key.access.initialize()
        val finishNonce = crypto.noncer.generate128()

        val finishRequest =
            FinishAuthenticationRequest(
                FinishAuthenticationRequestData(
                    access =
                        FinishAuthenticationRequestData.AccessData(
                            publicKey = currentKey,
                            rotationHash = nextKeyHash,
                        ),
                    authentication =
                        FinishAuthenticationRequestData.AuthenticationData(
                            device = store.identifier.device.get(),
                            nonce = startResponsePayload.response.authentication.nonce,
                        ),
                ),
                finishNonce,
            )

        finishRequest.sign(store.key.authentication.signer())
        val finishMessage = finishRequest.serialize()
        val finishReply = io.network.sendRequest(paths.authenticate.finish, finishMessage)

        val finishResponse = FinishAuthenticationResponse.parse(finishReply)

        @Suppress("UNCHECKED_CAST")
        val finishResponsePayload =
            finishResponse.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.FinishAuthenticationResponseData>
        verifyResponse(finishResponse, finishResponsePayload.access.responseKeyHash)

        if (finishResponsePayload.access.nonce != finishNonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.token.access.store(finishResponsePayload.response.access.token)
    }

    suspend fun refreshAccessToken() {
        val (publicKey, rotationHash) = store.key.access.rotate()
        val nonce = crypto.noncer.generate128()

        val request =
            RefreshAccessTokenRequest(
                RefreshAccessTokenRequestData(
                    RefreshAccessTokenRequestData.AccessData(
                        publicKey = publicKey,
                        rotationHash = rotationHash,
                        token = store.token.access.get(),
                    ),
                ),
                nonce,
            )

        request.sign(store.key.access.signer())
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.rotate.access, message)

        val response = RefreshAccessTokenResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RefreshAccessTokenResponseData>
        verifyResponse(response, responsePayload.access.responseKeyHash)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.token.access.store(responsePayload.response.access.token)
    }

    suspend fun recoverAccount(
        identity: String,
        recoveryKey: SigningKey,
    ) {
        val (_, current, rotationHash) = store.key.authentication.initialize()
        val device = crypto.hasher.sum(current)
        val nonce = crypto.noncer.generate128()

        val request =
            RecoverAccountRequest(
                RecoverAccountRequestData(
                    RecoverAccountRequestData.AuthenticationData(
                        device = device,
                        identity = identity,
                        publicKey = current,
                        recoveryKey = recoveryKey.public(),
                        rotationHash = rotationHash,
                    ),
                ),
                nonce,
            )

        request.sign(recoveryKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.register.recover, message)

        val response = RecoverAccountResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RecoverAccountResponseData>
        verifyResponse(response, responsePayload.access.responseKeyHash)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.identifier.identity.store(identity)
        store.identifier.device.store(device)
    }

    suspend fun <T> makeAccessRequest(
        path: String,
        request: T,
        requestSerializer: kotlinx.serialization.KSerializer<T>,
    ): String {
        val accessRequest =
            AccessRequest(
                com.betterauth.messages.AccessRequestPayload(
                    access =
                        com.betterauth.messages.AccessRequestPayload.AccessData(
                            nonce = crypto.noncer.generate128(),
                            timestamp = encoding.timestamper.format(encoding.timestamper.now()),
                            token = store.token.access.get(),
                        ),
                    request = request,
                ),
                com.betterauth.messages.AccessRequestPayload
                    .serializer(requestSerializer),
            )

        accessRequest.sign(store.key.access.signer())
        val message = accessRequest.serialize()
        val reply = io.network.sendRequest(path, message)
        val response = ScannableResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.ScannableResponseData>
        if (responsePayload.access.nonce != accessRequest.accessRequestPayload.access.nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        return reply
    }
}
