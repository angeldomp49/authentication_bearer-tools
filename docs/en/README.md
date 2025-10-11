# Bearer Authentication Tools

A lightweight Java library for JWT token generation and validation with additional cryptographic utilities. This library provides stateless helper functions for secure token management without external dependencies.

## Features

- **JWT Token Generation**: Create secure JWT tokens with custom headers and payloads
- **JWT Token Validation**: Validate token signatures and extract claims
- **Multiple Algorithms Support**: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- **Zero Dependencies**: Pure Java implementation without external framework dependencies
- **Stateless Design**: All functions are stateless for maximum flexibility
- **Security Utilities**: Additional tools for password hashing, encryption, and CSRF protection

## Quick Start

### Basic Token Generation

```java
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;

JWTTokenGenerator generator = new JWTTokenGenerator();

var header = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();

var payload = ObjectLeafBuilder.builder()
    .put("sub", "user123")
    .put("exp", System.currentTimeMillis() + 3600000)
    .build();

String token = generator.generateJWT("your-secret-key-32-chars-minimum", header, payload);
```

### Basic Token Validation

```java
JWTTokenGenerator generator = new JWTTokenGenerator();

boolean isValid = generator.isValidSignature(token, "your-secret-key-32-chars-minimum");

if (isValid) {
    JSONObject payload = generator.getJWTPayload(token);
    JSONObject header = generator.getJWTHeader(token);
}
```

## Installation

### Manual JAR Inclusion

1. Build the project using Gradle:
   ```bash
   ./gradlew build
   ```

2. Include the generated JAR file in your project classpath:
   ```
   lib/build/libs/lib-1.4.3.jar
   ```

### Build from Source

1. Clone the repository
2. Navigate to the project directory
3. Run the build command:
   ```bash
   ./gradlew build
   ```

## Core Components

### JWTTokenGenerator

The main class for JWT token operations:
- `generateJWT(secretKey, header, payload)`: Creates a new JWT token
- `isValidSignature(token, secretKey)`: Validates token signature
- `getJWTPayload(token)`: Extracts payload from token
- `getJWTHeader(token)`: Extracts header from token

### JWTTokenHandler

High-level token management for session-based authentication:
- `createTokenForSession(session, secretKey)`: Creates tokens with predefined session structure
- `isValidSignature(token, secretKey)`: Validates session tokens

### Supported Algorithms

- **HMAC-SHA256**: Default algorithm for token signing
- **HMAC-SHA384**: Enhanced security option
- **HMAC-SHA512**: Maximum security option

## Security Considerations

1. **Secret Key Requirements**: Minimum 32 characters for security
2. **Token Expiration**: Always set expiration times for tokens
3. **Signature Validation**: Validate signatures before trusting token content
4. **Secure Storage**: Store secret keys securely and rotate regularly

## Additional Documentation

- [Getting Started Guide](getting-started.md)
- [Token Generation](token-generation.md)
- [Token Validation](token-validation.md)
- [Cryptography](cryptography.md)
- [Examples](examples.md)

## License

This project is part of the MakechTec Bearer Authentication Tools suite.
