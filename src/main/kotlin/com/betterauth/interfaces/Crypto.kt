package com.betterauth.interfaces

interface Hasher {
    suspend fun sum(message: String): String
}

interface Noncer {
    // 128 bits of entropy
    suspend fun generate128(): String
}

interface Verifier {
    val signatureLength: Int

    // this is typically just a verification algorithm
    //
    // throw exceptions when verification fails
    suspend fun verify(
        message: String,
        signature: String,
        publicKey: String,
    )
}

interface VerificationKey {
    // fetches the public key
    suspend fun public(): String

    // returns the algorithm verifier
    fun verifier(): Verifier

    // verifies using the verifier and public key, this ia a convenience method
    //
    // throw exceptions when verification fails
    suspend fun verify(
        message: String,
        signature: String,
    )
}

interface SigningKey : VerificationKey {
    // signs with the key it represents (could be backed by an HSM for instance)
    suspend fun sign(message: String): String
}
