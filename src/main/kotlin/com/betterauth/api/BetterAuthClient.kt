package com.betterauth.api

import com.betterauth.interfaces.AuthenticationPaths
import com.betterauth.interfaces.ClientRotatingKeyStore
import com.betterauth.interfaces.ClientValueStore
import com.betterauth.interfaces.Hasher
import com.betterauth.interfaces.Network
import com.betterauth.interfaces.Noncer
import com.betterauth.interfaces.SigningKey
import com.betterauth.interfaces.Timestamper
import com.betterauth.interfaces.VerificationKeyStore
import com.betterauth.messages.AccessRequest
import com.betterauth.messages.CreateAccountRequest
import com.betterauth.messages.CreateAccountRequestData
import com.betterauth.messages.CreateAccountResponse
import com.betterauth.messages.CreateSessionRequest
import com.betterauth.messages.CreateSessionRequestData
import com.betterauth.messages.CreateSessionResponse
import com.betterauth.messages.LinkContainer
import com.betterauth.messages.LinkContainerPayload
import com.betterauth.messages.LinkDeviceRequest
import com.betterauth.messages.LinkDeviceRequestData
import com.betterauth.messages.LinkDeviceResponse
import com.betterauth.messages.RecoverAccountRequest
import com.betterauth.messages.RecoverAccountRequestData
import com.betterauth.messages.RecoverAccountResponse
import com.betterauth.messages.RefreshSessionRequest
import com.betterauth.messages.RefreshSessionRequestData
import com.betterauth.messages.RefreshSessionResponse
import com.betterauth.messages.RequestSessionRequest
import com.betterauth.messages.RequestSessionRequestPayload
import com.betterauth.messages.RequestSessionResponse
import com.betterauth.messages.RotateDeviceRequest
import com.betterauth.messages.RotateDeviceRequestData
import com.betterauth.messages.RotateDeviceResponse
import com.betterauth.messages.ScannableResponse
import com.betterauth.messages.SignableMessage

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
        val response: VerificationKeyStore,
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
        serverIdentity: String,
    ) {
        val verificationKey = crypto.publicKey.response.get(serverIdentity)
        val publicKey = verificationKey.public()
        val verifier = verificationKey.verifier()

        response.verify(verifier, publicKey)
    }

    suspend fun createAccount(recoveryHash: String) {
        val (identity, publicKey, rotationHash) =
            store.key.authentication.initialize(recoveryHash)
        val device = crypto.hasher.sum(publicKey)

        val nonce = crypto.noncer.generate128()

        val request =
            CreateAccountRequest(
                CreateAccountRequestData(
                    CreateAccountRequestData.AuthenticationData(
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
        val reply = io.network.sendRequest(paths.account.create, message)

        val response = CreateAccountResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.CreateAccountResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.identifier.identity.store(identity)
        store.identifier.device.store(device)
    }

    suspend fun recoverAccount(
        identity: String,
        recoveryKey: SigningKey,
        recoveryHash: String,
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
                        recoveryHash = recoveryHash,
                        recoveryKey = recoveryKey.public(),
                        rotationHash = rotationHash,
                    ),
                ),
                nonce,
            )

        request.sign(recoveryKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.account.recover, message)

        val response = RecoverAccountResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RecoverAccountResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

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
        val (signingKey, rotationHash) = store.key.authentication.next()

        val request =
            LinkDeviceRequest(
                LinkDeviceRequestData(
                    authentication =
                        LinkDeviceRequestData.AuthenticationData(
                            device = store.identifier.device.get(),
                            identity = store.identifier.identity.get(),
                            publicKey = signingKey.public(),
                            rotationHash = rotationHash,
                        ),
                    link = com.betterauth.messages.LinkContainerData(container.linkContainerPayload, container.signature),
                ),
                nonce,
            )

        request.sign(signingKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.device.link, message)

        val response = LinkDeviceResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.LinkDeviceResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.key.authentication.rotate()
    }

    suspend fun unlinkDevice(device: String) {
        val nonce = crypto.noncer.generate128()
        val (signingKey, rotationHash) = store.key.authentication.next()

        val currentDevice = store.identifier.device.get()
        val hash =
            if (device == currentDevice) {
                // prevent rotation if disabling this device
                crypto.hasher.sum(rotationHash)
            } else {
                rotationHash
            }

        val request =
            com.betterauth.messages.UnlinkDeviceRequest(
                com.betterauth.messages.UnlinkDeviceRequestData(
                    authentication =
                        com.betterauth.messages.UnlinkDeviceRequestData.AuthenticationData(
                            device = currentDevice,
                            identity = store.identifier.identity.get(),
                            publicKey = signingKey.public(),
                            rotationHash = hash,
                        ),
                    link =
                        com.betterauth.messages.UnlinkDeviceRequestData.LinkData(
                            device = device,
                        ),
                ),
                nonce,
            )

        request.sign(signingKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.device.unlink, message)

        val response =
            com.betterauth.messages.UnlinkDeviceResponse
                .parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.UnlinkDeviceResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.key.authentication.rotate()
    }

    suspend fun rotateDevice() {
        val (signingKey, rotationHash) = store.key.authentication.next()
        val nonce = crypto.noncer.generate128()

        val request =
            RotateDeviceRequest(
                RotateDeviceRequestData(
                    RotateDeviceRequestData.AuthenticationData(
                        device = store.identifier.device.get(),
                        identity = store.identifier.identity.get(),
                        publicKey = signingKey.public(),
                        rotationHash = rotationHash,
                    ),
                ),
                nonce,
            )

        request.sign(signingKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.device.rotate, message)

        val response = RotateDeviceResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RotateDeviceResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.key.authentication.rotate()
    }

    suspend fun createSession() {
        val startNonce = crypto.noncer.generate128()

        val startRequest =
            RequestSessionRequest(
                RequestSessionRequestPayload(
                    access = RequestSessionRequestPayload.AccessData(startNonce),
                    request =
                        RequestSessionRequestPayload.RequestData(
                            authentication =
                                RequestSessionRequestPayload.AuthenticationData(
                                    identity = store.identifier.identity.get(),
                                ),
                        ),
                ),
            )

        val startMessage = startRequest.serialize()
        val startReply = io.network.sendRequest(paths.session.request, startMessage)

        val startResponse = RequestSessionResponse.parse(startReply)

        @Suppress("UNCHECKED_CAST")
        val startResponsePayload =
            startResponse.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RequestSessionResponseData>
        verifyResponse(startResponse, startResponsePayload.access.serverIdentity)

        if (startResponsePayload.access.nonce != startNonce) {
            throw IllegalStateException("incorrect nonce")
        }

        val (_, publicKey, rotationHash) = store.key.access.initialize()
        val finishNonce = crypto.noncer.generate128()

        val finishRequest =
            CreateSessionRequest(
                CreateSessionRequestData(
                    access =
                        CreateSessionRequestData.AccessData(
                            publicKey = publicKey,
                            rotationHash = rotationHash,
                        ),
                    authentication =
                        CreateSessionRequestData.AuthenticationData(
                            device = store.identifier.device.get(),
                            nonce = startResponsePayload.response.authentication.nonce,
                        ),
                ),
                finishNonce,
            )

        finishRequest.sign(store.key.authentication.signer())
        val finishMessage = finishRequest.serialize()
        val finishReply = io.network.sendRequest(paths.session.create, finishMessage)

        val finishResponse = CreateSessionResponse.parse(finishReply)

        @Suppress("UNCHECKED_CAST")
        val finishResponsePayload =
            finishResponse.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.CreateSessionResponseData>
        verifyResponse(finishResponse, finishResponsePayload.access.serverIdentity)

        if (finishResponsePayload.access.nonce != finishNonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.token.access.store(finishResponsePayload.response.access.token)
    }

    suspend fun refreshSession() {
        val (signingKey, rotationHash) = store.key.access.next()
        val nonce = crypto.noncer.generate128()

        val request =
            RefreshSessionRequest(
                RefreshSessionRequestData(
                    RefreshSessionRequestData.AccessData(
                        publicKey = signingKey.public(),
                        rotationHash = rotationHash,
                        token = store.token.access.get(),
                    ),
                ),
                nonce,
            )

        request.sign(signingKey)
        val message = request.serialize()
        val reply = io.network.sendRequest(paths.session.refresh, message)

        val response = RefreshSessionResponse.parse(reply)

        @Suppress("UNCHECKED_CAST")
        val responsePayload =
            response.payload as
                com.betterauth.messages.ServerPayload<com.betterauth.messages.RefreshSessionResponseData>
        verifyResponse(response, responsePayload.access.serverIdentity)

        if (responsePayload.access.nonce != nonce) {
            throw IllegalStateException("incorrect nonce")
        }

        store.token.access.store(responsePayload.response.access.token)
        store.key.access.rotate()
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
