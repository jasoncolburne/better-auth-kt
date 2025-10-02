package com.betterauth.interfaces

interface Network {
    // returns the network response
    suspend fun sendRequest(
        path: String,
        message: String,
    ): String
}
