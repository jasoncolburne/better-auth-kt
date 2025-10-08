package com.betterauth

import com.betterauth.api.BetterAuthClient
import com.betterauth.implementation.ClientRotatingKeyStoreImpl
import com.betterauth.implementation.ClientValueStoreImpl
import com.betterauth.implementation.HasherImpl
import com.betterauth.implementation.NoncerImpl
import com.betterauth.implementation.Rfc3339Nano
import com.betterauth.implementation.Secp256r1
import com.betterauth.implementation.Secp256r1Verifier
import com.betterauth.interfaces.AccountPaths
import com.betterauth.interfaces.AuthenticationPaths
import com.betterauth.interfaces.DevicePaths
import com.betterauth.interfaces.Network
import com.betterauth.interfaces.SessionPaths
import com.betterauth.interfaces.VerificationKey
import com.betterauth.interfaces.VerificationKeyStore
import com.betterauth.interfaces.Verifier
import com.betterauth.messages.ServerPayload
import com.betterauth.messages.ServerResponse
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals

private const val DEBUG_LOGGING = false

class Secp256r1VerificationKey(
    private val publicKey: String,
) : VerificationKey {
    private val secpVerifier = Secp256r1Verifier()

    override suspend fun public(): String = publicKey

    override fun verifier(): Verifier = secpVerifier

    override suspend fun verify(
        message: String,
        signature: String,
    ) {
        secpVerifier.verify(message, signature, publicKey)
    }
}

class SimpleVerificationKeyStore(
    private val verificationKey: VerificationKey,
) : VerificationKeyStore {
    override suspend fun get(identity: String): VerificationKey = verificationKey
}

val authenticationPaths =
    AuthenticationPaths(
        account =
            AccountPaths(
                create = "/account/create",
                recover = "/account/recover",
            ),
        session =
            SessionPaths(
                request = "/session/request",
                connect = "/session/connect",
                refresh = "/session/refresh",
            ),
        device =
            DevicePaths(
                rotate = "/device/rotate",
                link = "/device/link",
                unlink = "/device/unlink",
            ),
    )

class NetworkImpl : Network {
    private val client = HttpClient.newBuilder().build()

    override suspend fun sendRequest(
        path: String,
        message: String,
    ): String {
        if (DEBUG_LOGGING) {
            println(message)
        }

        val request =
            HttpRequest
                .newBuilder()
                .uri(URI.create("http://localhost:8080$path"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(message))
                .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        val reply = response.body()

        if (DEBUG_LOGGING) {
            println(reply)
        }

        return reply
    }
}

@Serializable
data class FakeRequest(
    val foo: String,
    val bar: String,
)

@Serializable
data class FakeResponseData(
    val wasFoo: String,
    val wasBar: String,
)

class FakeResponse(
    response: FakeResponseData,
    serverIdentity: String,
    nonce: String,
) : ServerResponse<FakeResponseData>(response, serverIdentity, nonce, ServerPayload.serializer(FakeResponseData.serializer())) {
    companion object {
        fun parse(message: String): FakeResponse =
            parse<FakeResponseData, FakeResponse>(message) { response, serverIdentity, nonce ->
                FakeResponse(response, serverIdentity, nonce)
            } as FakeResponse
    }
}

suspend fun executeFlow(
    betterAuthClient: BetterAuthClient,
    eccVerifier: Verifier,
    responseVerificationKey: VerificationKey,
) {
    betterAuthClient.rotateAuthenticationKey()
    betterAuthClient.authenticate()
    betterAuthClient.refreshAccessToken()

    testAccess(betterAuthClient, eccVerifier, responseVerificationKey)
}

suspend fun testAccess(
    betterAuthClient: BetterAuthClient,
    eccVerifier: Verifier,
    responseVerificationKey: VerificationKey,
) {
    val message =
        FakeRequest(
            foo = "bar",
            bar = "foo",
        )
    val reply = betterAuthClient.makeAccessRequest("/foo/bar", message, FakeRequest.serializer())
    val response = FakeResponse.parse(reply)

    @Suppress("UNCHECKED_CAST")
    val responsePayload = response.payload as com.betterauth.messages.ServerPayload<FakeResponseData>
    response.verify(eccVerifier, responseVerificationKey.public())

    assertEquals("bar", responsePayload.response.wasFoo)
    assertEquals("foo", responsePayload.response.wasBar)
}

class IntegrationTest {
    @Test
    fun completesAuthFlows() =
        kotlinx.coroutines.runBlocking {
            val eccVerifier = Secp256r1Verifier()
            val hasher = HasherImpl()
            val noncer = NoncerImpl()

            val recoverySigner = Secp256r1()
            recoverySigner.generate()

            val network = NetworkImpl()

            val responsePublicKey = network.sendRequest("/key/response", "")
            val responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)
            val responseVerificationKeyStore = SimpleVerificationKeyStore(responseVerificationKey)

            val betterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = hasher,
                            noncer = noncer,
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = ClientValueStoreImpl(),
                                ),
                        ),
                )

            val recoveryHash = hasher.sum(recoverySigner.public())
            betterAuthClient.createAccount(recoveryHash)
            executeFlow(betterAuthClient, eccVerifier, responseVerificationKey)
        }

    @Test
    fun recoversFromLoss() =
        kotlinx.coroutines.runBlocking {
            val eccVerifier = Secp256r1Verifier()
            val hasher = HasherImpl()
            val noncer = NoncerImpl()

            val recoverySigner = Secp256r1()
            recoverySigner.generate()

            val network = NetworkImpl()

            val responsePublicKey = network.sendRequest("/key/response", "")
            val responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)
            val responseVerificationKeyStore = SimpleVerificationKeyStore(responseVerificationKey)

            val betterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = hasher,
                            noncer = noncer,
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = ClientValueStoreImpl(),
                                ),
                        ),
                )

            val recoveredBetterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = HasherImpl(),
                            noncer = NoncerImpl(),
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = ClientValueStoreImpl(),
                                ),
                        ),
                )

            val recoveryHash = hasher.sum(recoverySigner.public())
            betterAuthClient.createAccount(recoveryHash)

            val nextRecoverySigner = Secp256r1()
            nextRecoverySigner.generate()
            val nextRecoveryHash = hasher.sum(nextRecoverySigner.public())

            val identity = betterAuthClient.identity()
            recoveredBetterAuthClient.recoverAccount(identity, recoverySigner, nextRecoveryHash)
            executeFlow(recoveredBetterAuthClient, eccVerifier, responseVerificationKey)
        }

    @Test
    fun linksAnotherDevice() =
        kotlinx.coroutines.runBlocking {
            val eccVerifier = Secp256r1Verifier()
            val hasher = HasherImpl()
            val noncer = NoncerImpl()

            val recoverySigner = Secp256r1()
            recoverySigner.generate()

            val network = NetworkImpl()

            val responsePublicKey = network.sendRequest("/key/response", "")
            val responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)
            val responseVerificationKeyStore = SimpleVerificationKeyStore(responseVerificationKey)

            val betterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = hasher,
                            noncer = noncer,
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = ClientValueStoreImpl(),
                                ),
                        ),
                )

            val linkedBetterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = HasherImpl(),
                            noncer = NoncerImpl(),
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = ClientValueStoreImpl(),
                                ),
                        ),
                )

            val recoveryHash = hasher.sum(recoverySigner.public())
            betterAuthClient.createAccount(recoveryHash)
            val identity = betterAuthClient.identity()

            // get link container from the new device
            val linkContainer = linkedBetterAuthClient.generateLinkContainer(identity)
            if (DEBUG_LOGGING) {
                println(linkContainer)
            }

            // submit an endorsed link container with existing device
            betterAuthClient.linkDevice(linkContainer)
            executeFlow(linkedBetterAuthClient, eccVerifier, responseVerificationKey)

            // unlink the original device
            linkedBetterAuthClient.unlinkDevice(betterAuthClient.device())
        }

    @Test
    fun detectsMismatchedAccessNonce() =
        kotlinx.coroutines.runBlocking {
            val hasher = HasherImpl()
            val noncer = NoncerImpl()

            val recoverySigner = Secp256r1()
            recoverySigner.generate()

            val network = NetworkImpl()

            val responsePublicKey = network.sendRequest("/key/response", "")
            val responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)
            val responseVerificationKeyStore = SimpleVerificationKeyStore(responseVerificationKey)

            val accessTokenStore = ClientValueStoreImpl()
            val betterAuthClient =
                BetterAuthClient(
                    crypto =
                        BetterAuthClient.CryptoConfig(
                            hasher = hasher,
                            noncer = noncer,
                            publicKey =
                                BetterAuthClient.PublicKeyConfig(
                                    response = responseVerificationKeyStore,
                                ),
                        ),
                    encoding =
                        BetterAuthClient.EncodingConfig(
                            timestamper = Rfc3339Nano(),
                        ),
                    io =
                        BetterAuthClient.IOConfig(
                            network = network,
                        ),
                    paths = authenticationPaths,
                    store =
                        BetterAuthClient.StoreConfig(
                            identifier =
                                BetterAuthClient.IdentifierConfig(
                                    device = ClientValueStoreImpl(),
                                    identity = ClientValueStoreImpl(),
                                ),
                            key =
                                BetterAuthClient.KeyConfig(
                                    access = ClientRotatingKeyStoreImpl(),
                                    authentication = ClientRotatingKeyStoreImpl(),
                                ),
                            token =
                                BetterAuthClient.TokenConfig(
                                    access = accessTokenStore,
                                ),
                        ),
                )

            val recoveryHash = hasher.sum(recoverySigner.public())
            betterAuthClient.createAccount(recoveryHash)

            try {
                betterAuthClient.authenticate()
                val message =
                    FakeRequest(
                        foo = "bar",
                        bar = "foo",
                    )
                betterAuthClient.makeAccessRequest("/bad/nonce", message, FakeRequest.serializer())

                throw AssertionError("expected a failure")
            } catch (e: IllegalStateException) {
                assertEquals("incorrect nonce", e.message)
            }
        }
}
