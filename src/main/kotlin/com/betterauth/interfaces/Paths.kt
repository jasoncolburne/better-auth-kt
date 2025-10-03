package com.betterauth.interfaces

data class AuthenticationPaths(
    val account: AccountPaths,
    val authenticate: AuthenticatePaths,
    val rotate: RotatePaths,
)

data class AccountPaths(
    val create: String,
)

data class AuthenticatePaths(
    val start: String,
    val finish: String,
)

data class RotatePaths(
    val authentication: String,
    val access: String,
    val link: String,
    val unlink: String,
    val recover: String,
)
