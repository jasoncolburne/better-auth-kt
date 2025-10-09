package com.betterauth.implementation

import com.betterauth.interfaces.ClientRotatingKeyStore
import com.betterauth.interfaces.ClientValueStore
import com.betterauth.interfaces.Hasher
import com.betterauth.interfaces.SigningKey

class ClientRotatingKeyStoreImpl : ClientRotatingKeyStore {
    private var currentKey: SigningKey? = null
    private var nextKey: SigningKey? = null
    private var futureKey: SigningKey? = null
    private val hasher: Hasher = HasherImpl()

    override suspend fun initialize(extraData: String?): Triple<String, String, String> {
        val current = Secp256r1()
        val next = Secp256r1()

        current.generate()
        next.generate()

        this.currentKey = current
        this.nextKey = next

        val suffix = extraData ?: ""

        val publicKey = current.public()
        val rotationHash = hasher.sum(next.public())
        val identity = hasher.sum(publicKey + rotationHash + suffix)

        return Triple(identity, publicKey, rotationHash)
    }

    override suspend fun next(): Pair<SigningKey, String> {
        if (nextKey == null) {
            throw IllegalStateException("call initialize() first")
        }

        if (futureKey == null) {
            val key = Secp256r1()
            key.generate()
            futureKey = key
        }

        val rotationHash = hasher.sum(futureKey!!.public())

        return Pair(nextKey!!, rotationHash)
    }

    override suspend fun rotate() {
        if (nextKey == null) {
            throw IllegalStateException("call initialize() first")
        }

        if (futureKey == null) {
            throw IllegalStateException("call next() first")
        }

        currentKey = nextKey
        nextKey = futureKey
        futureKey = null
    }

    override suspend fun signer(): SigningKey {
        if (currentKey == null) {
            throw IllegalStateException("call initialize() first")
        }

        return currentKey!!
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
