package com.betterauth.interfaces

// client

interface ClientValueStore {
    suspend fun store(value: String)

    // throw an exception if:
    // - nothing has been stored
    suspend fun get(): String
}

interface ClientRotatingKeyStore {
    // returns: Triple(identity, publicKey, rotationHash)
    suspend fun initialize(extraData: String? = null): Triple<String, String, String>

    // returns: Pair(key, rotationHash)
    //
    // this should return the _next_ signing key and a hash of the subsequent key
    // if no subsequent key exists yet, it should first be generated
    //
    // this facilitates a failed network request during a rotation operation
    suspend fun next(): Pair<SigningKey, String>

    // throw an exception if:
    // - next() has not been called since the last call to initialize() or rotate()
    //
    // this is the commit operation of next()
    suspend fun rotate()

    // returns: effectively, a handle to a signing key
    suspend fun signer(): SigningKey
}

// server

interface ServerAuthenticationNonceStore {
    val lifetimeInSeconds: Int

    // probably want to implement exponential backoff delay on generation, per identity
    //
    // returns: nonce
    suspend fun generate(identity: String): String

    // throw an exception if:
    // - nonce is not in the store
    //
    // returns: identity
    suspend fun validate(nonce: String): String
}

interface ServerAuthenticationKeyStore {
    // throw exceptions for:
    // - identity exists bool set and identity is not found in data store
    // - identity exists bool unset and identity is found in data store
    // - identity and device combination exists
    suspend fun register(
        identity: String,
        device: String,
        publicKey: String,
        rotationHash: String,
        existingIdentity: Boolean,
    )

    // throw exceptions for:
    // - identity and device combination does not exist
    // - previous next hash doesn't match current hash
    suspend fun rotate(
        identity: String,
        device: String,
        current: String,
        rotationHash: String,
    )

    // returns: encoded key
    suspend fun public(
        identity: String,
        device: String,
    ): String
}

interface ServerRecoveryHashStore {
    suspend fun register(
        identity: String,
        keyHash: String,
    )

    // throw exceptions if:
    // - not found
    // - hash does not match
    suspend fun validate(
        identity: String,
        keyHash: String,
    )
}

interface ServerTimeLockStore {
    val lifetimeInSeconds: Int

    // throw an exception if:
    // - value is still alive in the store
    suspend fun reserve(value: String)
}

interface VerificationKeyStore {
    // throw an exception if:
    // - identity is not found
    //
    // returns: verification key for the given identity
    suspend fun get(identity: String): VerificationKey
}
