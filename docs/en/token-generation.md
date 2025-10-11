# Token Generation Guide

This guide covers comprehensive JWT token generation using the Bearer Authentication Tools library.

## Basic Token Generation

### Using JWTTokenGenerator

The `JWTTokenGenerator` class provides the core functionality for creating JWT tokens:

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
String token = generator.generateJWT(secretKey, header, payload);
```

### Header Configuration

Standard JWT headers should include algorithm and token type:

```java
var header = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Payload Structure

#### Standard Claims

```java
var payload = ObjectLeafBuilder.builder()
    .put("iss", "your-issuer")           // Issuer
    .put("sub", "user-identifier")       // Subject
    .put("aud", "your-audience")         // Audience
    .put("exp", expirationTimestamp)     // Expiration
    .put("nbf", notBeforeTimestamp)      // Not Before
    .put("iat", issuedAtTimestamp)       // Issued At
    .put("jti", UUID.randomUUID().toString()) // JWT ID
    .build();
```

#### Custom Claims

```java
var payload = ObjectLeafBuilder.builder()
    .put("userId", "12345")
    .put("role", "admin")
    .put("permissions", permissionsArray)
    .put("department", "engineering")
    .put("level", 5)
    .build();
```

## Session-Based Token Generation

### Using JWTTokenHandler

For session management, use `JWTTokenHandler` with predefined session structures:

```java
JWTTokenHandler handler = new JWTTokenHandler();

SessionInformation session = new SessionInformation(
    userId,
    expirationDate,
    false,  // isClosed
    Arrays.asList("read", "write", "admin")
);

String token = handler.createTokenForSession(session, secretKey);
```

### SessionInformation Structure

```java
public record SessionInformation(
    long userId,
    Calendar expirationDate,
    boolean isClosed,
    List<String> permissions
) {}
```

## Algorithm Selection

### HMAC Algorithms

The library uses HMAC-SHA512 by default for signing:

```java
// Default algorithm (HMAC-SHA512)
var header = ObjectLeafBuilder.builder()
    .put("alg", "SHA256")  // Internal reference
    .put("typ", "jwt")
    .build();
```

## Key Management

### Secret Key Requirements

```java
// Minimum 32 characters required
String secretKey = "your-secret-key-must-be-32-chars-minimum";

// Example secure key generation
String secureKey = generateSecureKey(32);
```

### Key Security Best Practices

1. **Length**: Minimum 32 characters
2. **Randomness**: Use cryptographically secure random generation
3. **Storage**: Store keys securely (environment variables, key vaults)
4. **Rotation**: Implement regular key rotation

## Advanced Token Generation

### Tokens with Complex Payloads

```java
public String createComplexToken(User user, List<Role> roles) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var rolesArray = ArrayStringLeafBuilder.builder();
    roles.stream()
        .map(Role::getName)
        .forEach(rolesArray::add);
    
    var permissionsArray = ArrayStringLeafBuilder.builder();
    roles.stream()
        .flatMap(role -> role.getPermissions().stream())
        .distinct()
        .forEach(permissionsArray::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", user.getId())
        .put("email", user.getEmail())
        .put("name", user.getFullName())
        .put("roles", rolesArray.build())
        .put("permissions", permissionsArray.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + Duration.ofHours(1).toMillis())
        .put("jti", UUID.randomUUID().toString())
        .build();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
    
    return generator.generateJWT(secretKey, header, payload);
}
```

### Conditional Token Generation

```java
public String createConditionalToken(User user, boolean includePermissions) {
    var payloadBuilder = ObjectLeafBuilder.builder()
        .put("sub", user.getId())
        .put("name", user.getName())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000);
    
    if (includePermissions) {
        var permissions = ArrayStringLeafBuilder.builder();
        user.getPermissions().forEach(permissions::add);
        payloadBuilder.put("permissions", permissions.build());
    }
    
    return generator.generateJWT(secretKey, header, payloadBuilder.build());
}
```

## Error Handling

### Validation Errors

The library validates inputs and throws `IllegalArgumentException` for invalid data:

```java
try {
    String token = generator.generateJWT(secretKey, header, payload);
} catch (IllegalArgumentException e) {
    // Handle validation errors
    System.err.println("Token generation failed: " + e.getMessage());
}
```

### Common Validation Issues

1. **Secret Key Too Short**: Must be at least 32 characters
2. **Null Values**: Headers and payloads cannot be null
3. **Empty JSON**: Headers and payloads must contain valid JSON
4. **Invalid Session**: Session validation failures

## Performance Considerations

### Token Generation Optimization

```java
// Reuse generator instances
private static final JWTTokenGenerator GENERATOR = new JWTTokenGenerator();

// Pre-build common headers
private static final ObjectLeaf STANDARD_HEADER = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Batch Token Generation

```java
public List<String> generateTokensForUsers(List<User> users, String secretKey) {
    return users.stream()
        .map(user -> createTokenForUser(user, secretKey))
        .collect(Collectors.toList());
}
```

## Integration Examples

### Web Application Integration

```java
@Service
public class TokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    public String authenticateUser(String username, String password) {
        User user = userService.authenticate(username, password);
        
        if (user != null) {
            return createTokenForUser(user);
        }
        
        throw new AuthenticationException("Invalid credentials");
    }
    
    private String createTokenForUser(User user) {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", user.getId())
            .put("username", user.getUsername())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(secretKey, STANDARD_HEADER, payload);
    }
}
```
