package com.betterauth.implementation

import com.betterauth.interfaces.ClientRotatingKeyStore
import com.betterauth.interfaces.ClientValueStore
import com.betterauth.interfaces.Hasher
import com.betterauth.interfaces.SigningKey

class ClientRotatingKeyStoreImpl : ClientRotatingKeyStore {
    private var current: SigningKey? = null
    private var next: SigningKey? = null
    private val hasher: Hasher = HasherImpl()

    override suspend fun initialize(extraData: String?): Triple<String, String, String> {
        val current = Secp256r1()
        val next = Secp256r1()

        current.generate()
        next.generate()

        this.current = current
        this.next = next

        val suffix = extraData ?: ""

        val publicKey = current.public()
        val rotationHash = hasher.sum(next.public())
        val identity = hasher.sum(publicKey + rotationHash + suffix)

        return Triple(identity, publicKey, rotationHash)
    }

    override suspend fun rotate(): Pair<String, String> {
        if (next == null) {
            throw IllegalStateException("call initialize() first")
        }

        val next = Secp256r1()
        next.generate()

        current = this.next
        this.next = next

        val rotationHash = hasher.sum(next.public())

        return Pair(current!!.public(), rotationHash)
    }

    override suspend fun signer(): SigningKey {
        if (current == null) {
            throw IllegalStateException("call initialize() first")
        }

        return current!!
    }
}

class ClientValueStoreImpl : ClientValueStore {
    private var value: String? = null

    override suspend fun store(value: String) {
        this.value = value
    }

    override suspend fun get(): String {
        if (value == null) {
            throw IllegalStateException("nothing to get")
        }

        return value!!
    }
}
