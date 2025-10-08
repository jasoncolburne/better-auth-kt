package com.betterauth.interfaces

data class AuthenticationPaths(
    val account: AccountPaths,
    val session: SessionPaths,
    val device: DevicePaths,
)

data class AccountPaths(
    val create: String,
    val recover: String,
)

data class SessionPaths(
    val request: String,
    val connect: String,
    val refresh: String,
)

data class DevicePaths(
    val rotate: String,
    val link: String,
    val unlink: String,
)
