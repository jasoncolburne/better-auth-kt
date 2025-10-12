# better-auth-kt

**Kotlin client-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This implementation provides client-side protocol handling for Kotlin/JVM and Android applications. For server functionality, use TypeScript, Python, Rust, Go, or Ruby implementations.

## What's Included

- ✅ **Client Only** - All client-side protocol operations
- ✅ **Kotlin/JVM + Android** - Works with JVM and Android projects
- ✅ **Coroutines** - Built with Kotlin coroutines for async operations
- ✅ **Null-Safe** - Leverages Kotlin's null safety
- ✅ **JSON Serialization** - kotlinx.serialization for type-safe serialization
- ✅ **Gradle Package** - Distributed via Maven/Gradle

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # gradle assemble --refresh-dependencies
```

### Running Tests

```bash
make test           # Run gradle test
make lint           # Run ktlint
make format-check   # Check code formatting
```

### Integration Testing

```bash
# Start a server (TypeScript, Python, Rust, Go, or Ruby)
# In the server repository:
make server

# In this repository, run integration tests:
make test-integration
```

## Development

This implementation uses:
- **Kotlin 1.9+** for modern Kotlin features
- **Gradle** for dependency management
- **Kotlin interfaces** for protocol definitions
- **kotlinx.serialization** for JSON serialization
- **Coroutines** for all async operations

All development commands use standardized `make` targets:

```bash
make setup          # gradle assemble --refresh-dependencies
make test           # gradle test
make lint           # gradle ktlintCheck
make format         # gradle ktlintFormat
make format-check   # gradle ktlintCheck
make build          # gradle build
make clean          # gradle clean
make test-integration  # gradle test --tests IntegrationTest
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Kotlin-specific patterns (interfaces, data classes, coroutines, null safety)
- Message types and interface definitions
- Usage examples and API patterns

### Key Features

- **Interface-Based Architecture**: Hasher, Noncer, Verifier, SigningKey, VerificationKey interfaces
- **Data Classes for Messages**: Immutable with automatic equals(), hashCode(), toString(), copy()
- **Coroutines for Async**: suspend functions with structured concurrency
- **Null Safety**: Non-nullable types by default with `?` for nullable types
- **JSON Serialization**: kotlinx.serialization with @Serializable annotation

### Platform Support

- **JVM** (Java 11+)
- **Android** (API 21+)
- Potentially **Kotlin Multiplatform** (with modifications)

### Reference Implementations

Reference implementations should use:
- **Java Security** or **BouncyCastle** for cryptography
- **OkHttp** or **Ktor** for networking
- **Android Keystore** for secure storage (Android)
- **SharedPreferences** for simple storage (Android)
- **kotlinx.serialization** for JSON
- **kotlinx.coroutines** for async operations

## Integration with Server Implementations

This Kotlin client is designed to work with any Better Auth server:
- **TypeScript server** (better-auth-ts)
- **Python server** (better-auth-py)
- **Rust server** (better-auth-rs)
- **Go server** (better-auth-go)
- **Ruby server** (better-auth-rb)

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt) - **This repository**

## License

MIT
