# Better Auth - Kotlin Implementation

## Project Context

This is a **Kotlin client-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation provides **client-side only** components for Kotlin/JVM and Android applications. For server functionality, use one of the server implementations (TypeScript, Python, Rust, Go, or Ruby).

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript - Client + Server)

**Other Implementations:**
- Full (Client + Server): [Python](https://github.com/jasoncolburne/better-auth-py), [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go), [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart)

## Architecture

### Directory Structure

```
src/
├── main/kotlin/com/betterauth/
│   ├── api/                    # Client API implementation
│   │   └── BetterAuthClient.kt # BetterAuthClient class
│   ├── interfaces/             # Interface definitions
│   │   ├── Crypto.kt           # Hasher, Noncer, Verifier, SigningKey, VerificationKey
│   │   ├── Encoding.kt         # Timestamper, Base64Encoder interfaces
│   │   ├── Network.kt          # Network interface
│   │   └── Storage.kt          # Client storage interfaces
│   └── messages/               # Protocol message types
│       ├── Message.kt          # Base message types
│       ├── Request.kt          # Base request types
│       ├── Response.kt         # Base response types
│       ├── Account.kt          # Account protocol messages
│       ├── Device.kt           # Device protocol messages
│       ├── Session.kt          # Session protocol messages
│       └── Access.kt           # Access protocol messages
└── test/kotlin/com/betterauth/
    ├── IntegrationTest.kt      # Integration tests
    └── implementation/         # Reference implementations
        ├── Blake3Hasher.kt
        ├── Secp256r1.kt
        ├── NoncerImpl.kt
        ├── Rfc3339Nano.kt
        ├── Base64Encoder.kt
        ├── HasherImpl.kt
        └── Storage.kt
```

### Key Components

**BetterAuthClient** (`src/main/kotlin/com/betterauth/api/BetterAuthClient.kt`)
- Implements all client-side protocol operations
- Manages authentication state and key rotation
- Handles token lifecycle
- Composes crypto, storage, and encoding interfaces

**Message Types** (`src/main/kotlin/com/betterauth/messages/`)
- Kotlin data classes with JSON serialization
- Type-safe request/response pairs
- kotlinx.serialization support

**Interface Definitions** (`src/main/kotlin/com/betterauth/interfaces/`)
- Kotlin interfaces define contracts
- Enable dependency injection
- Platform-agnostic abstractions

## Kotlin-Specific Patterns

### Interface-Based Architecture

This implementation uses Kotlin interfaces:
- `Hasher`, `Noncer`, `Verifier` for crypto operations
- `SigningKey`, `VerificationKey` for key operations
- Storage interfaces for client state management
- `Network`, `Timestamper`, `Base64Encoder`, etc.

Interfaces provide:
- Clear contracts
- Type safety
- Testability
- Dependency injection

### Data Classes for Messages

All message types are data classes:
- Immutable by default (val properties)
- Automatic `equals()`, `hashCode()`, `toString()`, `copy()`
- JSON serialization with kotlinx.serialization
- Type-safe and concise

### Coroutines for Async

All async operations use Kotlin coroutines:
- `suspend` functions
- Structured concurrency
- `async` / `await` patterns
- Flow for streams
- Exception handling with try-catch

### Null Safety

Leverages Kotlin's null safety:
- Non-nullable types by default
- `?` for nullable types
- `!!` for null assertion
- `?.` for safe calls
- `?:` for Elvis operator
- Compile-time null safety

### Error Handling

Kotlin-style error handling:
- Custom exception classes
- `throw` to raise exceptions
- `try-catch` to handle exceptions
- Sealed classes for typed errors
- Result type for functional error handling

### JSON Serialization

Uses kotlinx.serialization:
- `@Serializable` annotation on data classes
- JSON encoder/decoder
- Custom serializers when needed
- Type-safe serialization

## Testing

### Kotlin Tests
Tests use JUnit and Kotlin Test:
- Test all client protocol operations
- Mock implementations for dependencies
- Integration tests

Run with: `./gradlew test`

### Running Tests
```bash
./gradlew test                # Run all tests
./gradlew test --info         # Verbose output
./gradlew test --tests IntegrationTest  # Specific test
./gradlew test --rerun-tasks  # Force rerun
```

## Usage Patterns

### Client Initialization

```kotlin
import com.betterauth.api.BetterAuthClient

val client = BetterAuthClient(
    crypto = CryptoConfig(
        hasher = yourHasher,
        noncer = yourNoncer,
        responsePublicKey = serverPublicKey
    ),
    encoding = EncodingConfig(
        timestamper = yourTimestamper,
        base64Encoder = yourBase64Encoder
    ),
    io = IOConfig(
        network = yourNetwork
    ),
    store = StoreConfig(
        identity = identityStore,
        device = deviceStore,
        key = KeyStoreConfig(
            authentication = authKeyStore,
            access = accessKeyStore
        ),
        token = TokenStoreConfig(
            access = tokenStore
        )
    )
)
```

### Client Operations

```kotlin
// Create account
client.createAccount(recoveryHash = recoveryHash)

// Authenticate
client.authenticate()

// Make access request
val response = client.makeAccessRequest(
    path = "/api/resource",
    payload = mapOf("data" to "value")
)

// Rotate authentication key
client.rotateAuthenticationKey()

// Refresh access token
client.refreshAccessToken()
```

### Error Handling

```kotlin
try {
    client.authenticate()
} catch (e: BetterAuthException) {
    // Handle specific error
    println("Authentication failed: ${e.message}")
} catch (e: Exception) {
    // Handle generic error
    println("Unexpected error: ${e.message}")
    e.printStackTrace()
}
```

## Development Workflow

### Building
```bash
./gradlew build               # Build the project
./gradlew assemble            # Assemble artifacts
./gradlew clean build         # Clean and build
```

### Testing
```bash
./gradlew test                # Run all tests
./gradlew test --info         # Verbose output
./gradlew check               # Run checks and tests
```

### Linting & Formatting
```bash
./gradlew ktlintCheck         # Check code style
./gradlew ktlintFormat        # Format code
./gradlew detekt              # Static analysis (if configured)
```

### Publishing
```bash
./gradlew publishToMavenLocal # Publish to local Maven
./gradlew publish             # Publish to repository
```

## Platform Support

This Kotlin library supports:
- **JVM** (Java 11+)
- **Android** (API 21+)
- Potentially **Kotlin Multiplatform** (with modifications)

Platform-specific considerations:
- Android Keystore for secure storage
- SharedPreferences for simple storage
- OkHttp or Ktor for networking
- Java Security or BouncyCastle for cryptography

## Integration with Server Implementations

This Kotlin client is designed to work with any Better Auth server:
- Go server (`better-auth-go`)
- Ruby server (`better-auth-rb`)
- TypeScript server (`better-auth-ts`)
- Python server (`better-auth-py`)
- Rust server (`better-auth-rs`)

## Android Usage

When using with Android:
```kotlin
// build.gradle.kts
dependencies {
    implementation("com.betterauth:better-auth-kt:1.0.0")
    // Or use local build
}
```

Example Android integration:
```kotlin
class AuthRepository(private val client: BetterAuthClient) {
    suspend fun login(): Result<Unit> = runCatching {
        client.authenticate()
    }

    suspend fun makeRequest(path: String, data: Map<String, Any>): Result<ServerResponse> =
        runCatching {
            client.makeAccessRequest(path, data)
        }
}
```

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `./gradlew test`
3. Format code: `./gradlew ktlintFormat`
4. Build: `./gradlew build`
5. If protocol changes: sync with the TypeScript reference implementation
6. If breaking changes: update documentation and version
7. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `src/main/kotlin/com/betterauth/api/BetterAuthClient.kt` - All client logic
- `src/main/kotlin/com/betterauth/messages/` - Protocol message definitions
- `src/main/kotlin/com/betterauth/interfaces/` - Interface definitions
- `src/test/kotlin/com/betterauth/IntegrationTest.kt` - Integration tests
- `src/test/kotlin/com/betterauth/implementation/` - Reference implementations
- `build.gradle.kts` - Gradle build configuration

## Gradle Configuration

This is a Gradle-based Kotlin project:
- `build.gradle.kts` defines build configuration
- Kotlin DSL for type-safe build scripts
- Add as dependency:
  ```kotlin
  dependencies {
      implementation("com.betterauth:better-auth-kt:1.0.0")
  }
  ```

## Example Implementations

Reference implementations for interfaces should use:
- **Java Security** or **BouncyCastle** for cryptography
- **OkHttp** or **Ktor** for networking
- **Android Keystore** for secure storage (Android)
- **SharedPreferences** for simple storage (Android)
- **kotlinx.serialization** for JSON
- **kotlinx.coroutines** for async operations

## Kotlin Version

Requires Kotlin 1.9+ for:
- Modern coroutines
- Stable APIs
- Performance improvements
- Enhanced type system
