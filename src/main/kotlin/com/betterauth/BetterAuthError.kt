package com.betterauth

/**
 * Better Auth Error System
 *
 * This file defines the error hierarchy for Better Auth following
 * the specification in ERRORS.md in the root repository.
 */

sealed class BetterAuthError(
    val code: String,
    override val message: String,
    val context: Map<String, Any?>? = null,
) : Exception(message) {
    fun toJson(): Map<String, Any?> =
        mapOf(
            "error" to
                mapOf(
                    "code" to code,
                    "message" to message,
                    "context" to context,
                ),
        )

    // ============================================================================
    // Validation Errors
    // ============================================================================

    /** Message structure is invalid or malformed (BA101) */
    class InvalidMessage(
        field: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA101",
            message = buildMessage(field, details),
            context = buildContext(field, details),
        ) {
        companion object {
            private fun buildMessage(
                field: String?,
                details: String?,
            ): String {
                if (field == null) return "Message structure is invalid or malformed"
                var msg = "Message structure is invalid: $field"
                if (details != null) msg += " ($details)"
                return msg
            }

            private fun buildContext(
                field: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (field == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (field != null) ctx["field"] = field
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    /** Identity verification failed (BA102) */
    class InvalidIdentity(
        provided: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA102",
            message = "Identity verification failed",
            context = buildContext(provided, details),
        ) {
        companion object {
            private fun buildContext(
                provided: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (provided == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (provided != null) ctx["provided"] = provided
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    /** Device hash does not match hash(publicKey || rotationHash) (BA103) */
    class InvalidDevice(
        provided: String? = null,
        calculated: String? = null,
    ) : BetterAuthError(
            code = "BA103",
            message = "Device hash does not match hash(publicKey || rotationHash)",
            context = buildContext(provided, calculated),
        ) {
        companion object {
            private fun buildContext(
                provided: String?,
                calculated: String?,
            ): Map<String, Any?>? {
                if (provided == null && calculated == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (provided != null) ctx["provided"] = provided
                if (calculated != null) ctx["calculated"] = calculated
                return ctx
            }
        }
    }

    /** Hash validation failed (BA104) */
    class InvalidHash(
        expected: String? = null,
        actual: String? = null,
        hashType: String? = null,
    ) : BetterAuthError(
            code = "BA104",
            message = "Hash validation failed",
            context = buildContext(expected, actual, hashType),
        ) {
        companion object {
            private fun buildContext(
                expected: String?,
                actual: String?,
                hashType: String?,
            ): Map<String, Any?>? {
                if (expected == null && actual == null && hashType == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (expected != null) ctx["expected"] = expected
                if (actual != null) ctx["actual"] = actual
                if (hashType != null) ctx["hashType"] = hashType
                return ctx
            }
        }
    }

    // ============================================================================
    // Cryptographic Errors
    // ============================================================================

    /** Response nonce does not match request nonce (BA203) */
    class IncorrectNonce(
        expected: String? = null,
        actual: String? = null,
    ) : BetterAuthError(
            code = "BA203",
            message = "Response nonce does not match request nonce",
            context = buildContext(expected, actual),
        ) {
        companion object {
            private fun buildContext(
                expected: String?,
                actual: String?,
            ): Map<String, Any?>? {
                if (expected == null && actual == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (expected != null) ctx["expected"] = truncate(expected)
                if (actual != null) ctx["actual"] = truncate(actual)
                return ctx
            }

            private fun truncate(s: String) = if (s.length > 16) "${s.substring(0, 16)}..." else s
        }
    }

    // ============================================================================
    // Authentication/Authorization Errors
    // ============================================================================

    /** Link container identity does not match request identity (BA302) */
    class MismatchedIdentities(
        linkContainerIdentity: String? = null,
        requestIdentity: String? = null,
    ) : BetterAuthError(
            code = "BA302",
            message = "Link container identity does not match request identity",
            context = buildContext(linkContainerIdentity, requestIdentity),
        ) {
        companion object {
            private fun buildContext(
                linkContainerIdentity: String?,
                requestIdentity: String?,
            ): Map<String, Any?>? {
                if (linkContainerIdentity == null && requestIdentity == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (linkContainerIdentity != null) ctx["linkContainerIdentity"] = linkContainerIdentity
                if (requestIdentity != null) ctx["requestIdentity"] = requestIdentity
                return ctx
            }
        }
    }

    // ============================================================================
    // Token Errors
    // ============================================================================

    /** Token has expired (BA401) */
    class ExpiredToken(
        expiryTime: String? = null,
        currentTime: String? = null,
        tokenType: String? = null,
    ) : BetterAuthError(
            code = "BA401",
            message = "Token has expired",
            context = buildContext(expiryTime, currentTime, tokenType),
        ) {
        companion object {
            private fun buildContext(
                expiryTime: String?,
                currentTime: String?,
                tokenType: String?,
            ): Map<String, Any?>? {
                if (expiryTime == null && currentTime == null && tokenType == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (expiryTime != null) ctx["expiryTime"] = expiryTime
                if (currentTime != null) ctx["currentTime"] = currentTime
                if (tokenType != null) ctx["tokenType"] = tokenType
                return ctx
            }
        }
    }

    /** Token issued_at timestamp is in the future (BA403) */
    class FutureToken(
        issuedAt: String? = null,
        currentTime: String? = null,
        timeDifference: Double? = null,
    ) : BetterAuthError(
            code = "BA403",
            message = "Token issued_at timestamp is in the future",
            context = buildContext(issuedAt, currentTime, timeDifference),
        ) {
        companion object {
            private fun buildContext(
                issuedAt: String?,
                currentTime: String?,
                timeDifference: Double?,
            ): Map<String, Any?>? {
                if (issuedAt == null && currentTime == null && timeDifference == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (issuedAt != null) ctx["issuedAt"] = issuedAt
                if (currentTime != null) ctx["currentTime"] = currentTime
                if (timeDifference != null) ctx["timeDifference"] = timeDifference
                return ctx
            }
        }
    }

    // ============================================================================
    // Temporal Errors
    // ============================================================================

    /** Request timestamp is too old (BA501) */
    class StaleRequest(
        requestTimestamp: String? = null,
        currentTime: String? = null,
        maximumAge: Int? = null,
    ) : BetterAuthError(
            code = "BA501",
            message = "Request timestamp is too old",
            context = buildContext(requestTimestamp, currentTime, maximumAge),
        ) {
        companion object {
            private fun buildContext(
                requestTimestamp: String?,
                currentTime: String?,
                maximumAge: Int?,
            ): Map<String, Any?>? {
                if (requestTimestamp == null && currentTime == null && maximumAge == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (requestTimestamp != null) ctx["requestTimestamp"] = requestTimestamp
                if (currentTime != null) ctx["currentTime"] = currentTime
                if (maximumAge != null) ctx["maximumAge"] = maximumAge
                return ctx
            }
        }
    }

    /** Request timestamp is in the future (BA502) */
    class FutureRequest(
        requestTimestamp: String? = null,
        currentTime: String? = null,
        timeDifference: Double? = null,
    ) : BetterAuthError(
            code = "BA502",
            message = "Request timestamp is in the future",
            context = buildContext(requestTimestamp, currentTime, timeDifference),
        ) {
        companion object {
            private fun buildContext(
                requestTimestamp: String?,
                currentTime: String?,
                timeDifference: Double?,
            ): Map<String, Any?>? {
                if (requestTimestamp == null && currentTime == null && timeDifference == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (requestTimestamp != null) ctx["requestTimestamp"] = requestTimestamp
                if (currentTime != null) ctx["currentTime"] = currentTime
                if (timeDifference != null) ctx["timeDifference"] = timeDifference
                return ctx
            }
        }
    }

    // ============================================================================
    // Storage Errors
    // ============================================================================

    // ============================================================================
    // Encoding Errors
    // ============================================================================

    // ============================================================================
    // Network Errors
    // ============================================================================

    // ============================================================================
    // Protocol Errors
    // ============================================================================
}
