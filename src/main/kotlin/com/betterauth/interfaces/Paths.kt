package com.betterauth.interfaces

data class AuthenticationPaths(
    val account: AccountPaths,
    val session: SessionPaths,
    val device: DevicePaths,
    val recovery: RecoveryPaths,
)

data class AccountPaths(
    val create: String,
    val recover: String,
    val delete: String,
)

data class SessionPaths(
    val request: String,
    val create: String,
    val refresh: String,
)

data class DevicePaths(
    val rotate: String,
    val link: String,
    val unlink: String,
)

data class RecoveryPaths(
    val change: String,
)
