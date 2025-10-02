package com.betterauth.interfaces

data class AuthenticationPaths(
    val register: RegisterPaths,
    val authenticate: AuthenticatePaths,
    val rotate: RotatePaths,
)

data class RegisterPaths(
    val create: String,
    val link: String,
    val recover: String,
)

data class AuthenticatePaths(
    val start: String,
    val finish: String,
)

data class RotatePaths(
    val authentication: String,
    val access: String,
)
