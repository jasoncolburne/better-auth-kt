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

    /** Signature verification failed (BA201) */
    class SignatureVerificationFailed(
        publicKey: String? = null,
        signedData: String? = null,
    ) : BetterAuthError(
            code = "BA201",
            message = "Signature verification failed",
            context = buildContext(publicKey, signedData),
        ) {
        companion object {
            private fun buildContext(
                publicKey: String?,
                signedData: String?,
            ): Map<String, Any?>? {
                if (publicKey == null && signedData == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (publicKey != null) ctx["publicKey"] = publicKey
                if (signedData != null) ctx["signedData"] = signedData
                return ctx
            }
        }
    }

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

    /** Authentication challenge has expired (BA204) */
    class ExpiredNonce(
        nonceTimestamp: String? = null,
        currentTime: String? = null,
        expirationWindow: String? = null,
    ) : BetterAuthError(
            code = "BA204",
            message = "Authentication challenge has expired",
            context = buildContext(nonceTimestamp, currentTime, expirationWindow),
        ) {
        companion object {
            private fun buildContext(
                nonceTimestamp: String?,
                currentTime: String?,
                expirationWindow: String?,
            ): Map<String, Any?>? {
                if (nonceTimestamp == null && currentTime == null && expirationWindow == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (nonceTimestamp != null) ctx["nonceTimestamp"] = nonceTimestamp
                if (currentTime != null) ctx["currentTime"] = currentTime
                if (expirationWindow != null) ctx["expirationWindow"] = expirationWindow
                return ctx
            }
        }
    }

    /** Nonce has already been used (replay attack detected) (BA205) */
    class NonceReplay(
        nonce: String? = null,
        previousUsageTimestamp: String? = null,
    ) : BetterAuthError(
            code = "BA205",
            message = "Nonce has already been used (replay attack detected)",
            context = buildContext(nonce, previousUsageTimestamp),
        ) {
        companion object {
            private fun buildContext(
                nonce: String?,
                previousUsageTimestamp: String?,
            ): Map<String, Any?>? {
                if (nonce == null && previousUsageTimestamp == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (nonce != null) ctx["nonce"] = truncate(nonce)
                if (previousUsageTimestamp != null) ctx["previousUsageTimestamp"] = previousUsageTimestamp
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

    /** Insufficient permissions for requested operation (BA303) */
    class PermissionDenied(
        requiredPermissions: List<String>? = null,
        actualPermissions: List<String>? = null,
        operation: String? = null,
    ) : BetterAuthError(
            code = "BA303",
            message = "Insufficient permissions for requested operation",
            context = buildContext(requiredPermissions, actualPermissions, operation),
        ) {
        companion object {
            private fun buildContext(
                requiredPermissions: List<String>?,
                actualPermissions: List<String>?,
                operation: String?,
            ): Map<String, Any?>? {
                if (requiredPermissions == null && actualPermissions == null && operation == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (requiredPermissions != null) ctx["requiredPermissions"] = requiredPermissions
                if (actualPermissions != null) ctx["actualPermissions"] = actualPermissions
                if (operation != null) ctx["operation"] = operation
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

    /** Token structure or format is invalid (BA402) */
    class InvalidToken(
        details: String? = null,
    ) : BetterAuthError(
            code = "BA402",
            message = "Token structure or format is invalid",
            context = if (details != null) mapOf("details" to details) else null,
        )

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

    /** Client and server clock difference exceeds tolerance (BA503) */
    class ClockSkew(
        clientTime: String? = null,
        serverTime: String? = null,
        timeDifference: Double? = null,
        maxTolerance: Double? = null,
    ) : BetterAuthError(
            code = "BA503",
            message = "Client and server clock difference exceeds tolerance",
            context = buildContext(clientTime, serverTime, timeDifference, maxTolerance),
        ) {
        companion object {
            private fun buildContext(
                clientTime: String?,
                serverTime: String?,
                timeDifference: Double?,
                maxTolerance: Double?,
            ): Map<String, Any?>? {
                if (clientTime == null && serverTime == null && timeDifference == null && maxTolerance == null) {
                    return null
                }
                val ctx = mutableMapOf<String, Any?>()
                if (clientTime != null) ctx["clientTime"] = clientTime
                if (serverTime != null) ctx["serverTime"] = serverTime
                if (timeDifference != null) ctx["timeDifference"] = timeDifference
                if (maxTolerance != null) ctx["maxTolerance"] = maxTolerance
                return ctx
            }
        }
    }

    // ============================================================================
    // Storage Errors
    // ============================================================================

    /** Resource not found (BA601) */
    class NotFound(
        resourceType: String? = null,
        resourceIdentifier: String? = null,
    ) : BetterAuthError(
            code = "BA601",
            message = buildMessage(resourceType),
            context = buildContext(resourceType, resourceIdentifier),
        ) {
        companion object {
            private fun buildMessage(resourceType: String?) =
                if (resourceType == null) {
                    "Resource not found"
                } else {
                    "Resource not found: $resourceType"
                }

            private fun buildContext(
                resourceType: String?,
                resourceIdentifier: String?,
            ): Map<String, Any?>? {
                if (resourceType == null && resourceIdentifier == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (resourceType != null) ctx["resourceType"] = resourceType
                if (resourceIdentifier != null) ctx["resourceIdentifier"] = resourceIdentifier
                return ctx
            }
        }
    }

    /** Resource already exists (BA602) */
    class AlreadyExists(
        resourceType: String? = null,
        resourceIdentifier: String? = null,
    ) : BetterAuthError(
            code = "BA602",
            message = buildMessage(resourceType),
            context = buildContext(resourceType, resourceIdentifier),
        ) {
        companion object {
            private fun buildMessage(resourceType: String?) =
                if (resourceType == null) {
                    "Resource already exists"
                } else {
                    "Resource already exists: $resourceType"
                }

            private fun buildContext(
                resourceType: String?,
                resourceIdentifier: String?,
            ): Map<String, Any?>? {
                if (resourceType == null && resourceIdentifier == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (resourceType != null) ctx["resourceType"] = resourceType
                if (resourceIdentifier != null) ctx["resourceIdentifier"] = resourceIdentifier
                return ctx
            }
        }
    }

    /** Storage backend is unavailable (BA603) */
    class StorageUnavailable(
        backendType: String? = null,
        connectionDetails: String? = null,
        backendError: String? = null,
    ) : BetterAuthError(
            code = "BA603",
            message = "Storage backend is unavailable",
            context = buildContext(backendType, connectionDetails, backendError),
        ) {
        companion object {
            private fun buildContext(
                backendType: String?,
                connectionDetails: String?,
                backendError: String?,
            ): Map<String, Any?>? {
                if (backendType == null && connectionDetails == null && backendError == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (backendType != null) ctx["backendType"] = backendType
                if (connectionDetails != null) ctx["connectionDetails"] = connectionDetails
                if (backendError != null) ctx["backendError"] = backendError
                return ctx
            }
        }
    }

    /** Stored data is corrupted or invalid (BA604) */
    class StorageCorruption(
        resourceType: String? = null,
        resourceIdentifier: String? = null,
        corruptionDetails: String? = null,
    ) : BetterAuthError(
            code = "BA604",
            message = "Stored data is corrupted or invalid",
            context = buildContext(resourceType, resourceIdentifier, corruptionDetails),
        ) {
        companion object {
            private fun buildContext(
                resourceType: String?,
                resourceIdentifier: String?,
                corruptionDetails: String?,
            ): Map<String, Any?>? {
                if (resourceType == null && resourceIdentifier == null && corruptionDetails == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (resourceType != null) ctx["resourceType"] = resourceType
                if (resourceIdentifier != null) ctx["resourceIdentifier"] = resourceIdentifier
                if (corruptionDetails != null) ctx["corruptionDetails"] = corruptionDetails
                return ctx
            }
        }
    }

    // ============================================================================
    // Encoding Errors
    // ============================================================================

    /** Failed to serialize message (BA701) */
    class SerializationError(
        messageType: String? = null,
        format: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA701",
            message = "Failed to serialize message",
            context = buildContext(messageType, format, details),
        ) {
        companion object {
            private fun buildContext(
                messageType: String?,
                format: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (messageType == null && format == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (messageType != null) ctx["messageType"] = messageType
                if (format != null) ctx["format"] = format
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    /** Failed to deserialize message (BA702) */
    class DeserializationError(
        messageType: String? = null,
        rawData: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA702",
            message = "Failed to deserialize message",
            context = buildContext(messageType, rawData, details),
        ) {
        companion object {
            private fun buildContext(
                messageType: String?,
                rawData: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (messageType == null && rawData == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (messageType != null) ctx["messageType"] = messageType
                if (rawData != null) ctx["rawData"] = truncateData(rawData)
                if (details != null) ctx["details"] = details
                return ctx
            }

            private fun truncateData(s: String) = if (s.length > 100) "${s.substring(0, 100)}..." else s
        }
    }

    /** Failed to compress or decompress data (BA703) */
    class CompressionError(
        operation: String? = null,
        dataSize: Int? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA703",
            message = "Failed to compress or decompress data",
            context = buildContext(operation, dataSize, details),
        ) {
        companion object {
            private fun buildContext(
                operation: String?,
                dataSize: Int?,
                details: String?,
            ): Map<String, Any?>? {
                if (operation == null && dataSize == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (operation != null) ctx["operation"] = operation
                if (dataSize != null) ctx["dataSize"] = dataSize
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    // ============================================================================
    // Network Errors
    // ============================================================================

    /** Failed to connect to server (BA801) */
    class ConnectionError(
        serverUrl: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA801",
            message = "Failed to connect to server",
            context = buildContext(serverUrl, details),
        ) {
        companion object {
            private fun buildContext(
                serverUrl: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (serverUrl == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (serverUrl != null) ctx["serverUrl"] = serverUrl
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    /** Request timed out (BA802) */
    class TimeoutError(
        timeoutDuration: Int? = null,
        endpoint: String? = null,
    ) : BetterAuthError(
            code = "BA802",
            message = "Request timed out",
            context = buildContext(timeoutDuration, endpoint),
        ) {
        companion object {
            private fun buildContext(
                timeoutDuration: Int?,
                endpoint: String?,
            ): Map<String, Any?>? {
                if (timeoutDuration == null && endpoint == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (timeoutDuration != null) ctx["timeoutDuration"] = timeoutDuration
                if (endpoint != null) ctx["endpoint"] = endpoint
                return ctx
            }
        }
    }

    /** Invalid HTTP response or protocol violation (BA803) */
    class ProtocolError(
        httpStatusCode: Int? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA803",
            message = "Invalid HTTP response or protocol violation",
            context = buildContext(httpStatusCode, details),
        ) {
        companion object {
            private fun buildContext(
                httpStatusCode: Int?,
                details: String?,
            ): Map<String, Any?>? {
                if (httpStatusCode == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (httpStatusCode != null) ctx["httpStatusCode"] = httpStatusCode
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    // ============================================================================
    // Protocol Errors
    // ============================================================================

    /** Operation not allowed in current state (BA901) */
    class InvalidState(
        currentState: String? = null,
        attemptedOperation: String? = null,
        requiredState: String? = null,
    ) : BetterAuthError(
            code = "BA901",
            message = "Operation not allowed in current state",
            context = buildContext(currentState, attemptedOperation, requiredState),
        ) {
        companion object {
            private fun buildContext(
                currentState: String?,
                attemptedOperation: String?,
                requiredState: String?,
            ): Map<String, Any?>? {
                if (currentState == null && attemptedOperation == null && requiredState == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (currentState != null) ctx["currentState"] = currentState
                if (attemptedOperation != null) ctx["attemptedOperation"] = attemptedOperation
                if (requiredState != null) ctx["requiredState"] = requiredState
                return ctx
            }
        }
    }

    /** Key rotation failed (BA902) */
    class RotationError(
        rotationType: String? = null,
        details: String? = null,
    ) : BetterAuthError(
            code = "BA902",
            message = "Key rotation failed",
            context = buildContext(rotationType, details),
        ) {
        companion object {
            private fun buildContext(
                rotationType: String?,
                details: String?,
            ): Map<String, Any?>? {
                if (rotationType == null && details == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (rotationType != null) ctx["rotationType"] = rotationType
                if (details != null) ctx["details"] = details
                return ctx
            }
        }
    }

    /** Account recovery failed (BA903) */
    class RecoveryError(
        details: String? = null,
    ) : BetterAuthError(
            code = "BA903",
            message = "Account recovery failed",
            context = if (details != null) mapOf("details" to details) else null,
        )

    /** Device has been revoked (BA904) */
    class DeviceRevoked(
        deviceIdentifier: String? = null,
        revocationTimestamp: String? = null,
    ) : BetterAuthError(
            code = "BA904",
            message = "Device has been revoked",
            context = buildContext(deviceIdentifier, revocationTimestamp),
        ) {
        companion object {
            private fun buildContext(
                deviceIdentifier: String?,
                revocationTimestamp: String?,
            ): Map<String, Any?>? {
                if (deviceIdentifier == null && revocationTimestamp == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (deviceIdentifier != null) ctx["deviceIdentifier"] = deviceIdentifier
                if (revocationTimestamp != null) ctx["revocationTimestamp"] = revocationTimestamp
                return ctx
            }
        }
    }

    /** Identity has been deleted (BA905) */
    class IdentityDeleted(
        identityIdentifier: String? = null,
        deletionTimestamp: String? = null,
    ) : BetterAuthError(
            code = "BA905",
            message = "Identity has been deleted",
            context = buildContext(identityIdentifier, deletionTimestamp),
        ) {
        companion object {
            private fun buildContext(
                identityIdentifier: String?,
                deletionTimestamp: String?,
            ): Map<String, Any?>? {
                if (identityIdentifier == null && deletionTimestamp == null) return null
                val ctx = mutableMapOf<String, Any?>()
                if (identityIdentifier != null) ctx["identityIdentifier"] = identityIdentifier
                if (deletionTimestamp != null) ctx["deletionTimestamp"] = deletionTimestamp
                return ctx
            }
        }
    }
}
