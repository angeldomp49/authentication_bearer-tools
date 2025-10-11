# Cryptography and Security Guide

This guide covers the cryptographic aspects and security considerations of the Bearer Authentication Tools library.

## Supported Algorithms

### HMAC Algorithms

The library uses HMAC (Hash-based Message Authentication Code) for token signing:

#### HMAC-SHA512 (Default)
- **Internal Implementation**: Uses Google Guava's Hashing.hmacSha512()
- **Key Size**: Minimum 32 characters (256 bits recommended)
- **Security Level**: High
- **Performance**: Good

```java
// Default algorithm used by SignaturePrinter
SignaturePrinter signer = new SignaturePrinter(secretKey);
String signature = signer.sign(message);
```

#### Algorithm Selection

The library internally uses HMAC-SHA512 for all signing operations, providing strong cryptographic security:

```java
// Internal implementation (from SignaturePrinter class)
public String sign(String message) {
    return Hashing.hmacSha512(secretKey.getBytes(StandardCharsets.UTF_8))
            .hashString(message, StandardCharsets.UTF_8)
            .toString();
}
```

## Key Management

### Secret Key Requirements

#### Minimum Security Standards
- **Length**: Minimum 32 characters (256 bits)
- **Character Set**: Use full ASCII character set for maximum entropy
- **Randomness**: Generate using cryptographically secure random number generators

```java
// Example secure key generation
public String generateSecureKey(int length) {
    SecureRandom random = new SecureRandom();
    StringBuilder key = new StringBuilder(length);
    String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    
    for (int i = 0; i < length; i++) {
        key.append(charset.charAt(random.nextInt(charset.length())));
    }
    
    return key.toString();
}
```

#### Key Storage Best Practices

```java
// Environment variable storage
String secretKey = System.getenv("JWT_SECRET_KEY");

// Properties file (encrypted)
Properties props = new Properties();
props.load(new FileInputStream("secure.properties"));
String secretKey = decrypt(props.getProperty("jwt.secret.encrypted"));

// Key management service integration
String secretKey = keyManagementService.getKey("jwt-signing-key");
```

### Key Rotation

Implement regular key rotation for enhanced security:

```java
public class KeyRotationService {
    
    private final Map<String, String> activeKeys = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public String createTokenWithCurrentKey(ObjectLeaf header, ObjectLeaf payload) {
        String currentKeyId = getCurrentKeyId();
        String secretKey = activeKeys.get(currentKeyId);
        
        // Add key ID to header
        var headerWithKeyId = ObjectLeafBuilder.builder()
            .putAll(header.asMap())
            .put("kid", currentKeyId)
            .build();
        
        return generator.generateJWT(secretKey, headerWithKeyId, payload);
    }
    
    public boolean validateTokenWithKeyRotation(String token, String keyId) {
        String secretKey = activeKeys.get(keyId);
        if (secretKey == null) {
            return false; // Key not found or expired
        }
        
        return generator.isValidSignature(token, secretKey);
    }
    
    public void rotateKey() {
        String newKeyId = generateNewKeyId();
        String newSecretKey = generateSecureKey(64);
        activeKeys.put(newKeyId, newSecretKey);
        
        // Keep old keys for grace period
        scheduleKeyCleanup(newKeyId);
    }
}
```

## Security Considerations

### Token Security

#### Expiration Management
Always set appropriate expiration times:

```java
public long calculateExpirationTime(TokenType tokenType) {
    return switch (tokenType) {
        case ACCESS_TOKEN -> System.currentTimeMillis() + Duration.ofMinutes(15).toMillis();
        case REFRESH_TOKEN -> System.currentTimeMillis() + Duration.ofDays(30).toMillis();
        case SESSION_TOKEN -> System.currentTimeMillis() + Duration.ofHours(8).toMillis();
    };
}
```

#### Signature Validation
Always validate signatures before processing token content:

```java
public ProcessingResult processToken(String token, String secretKey) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    // NEVER extract payload without signature validation
    if (!generator.isValidSignature(token, secretKey)) {
        throw new SecurityException("Invalid token signature");
    }
    
    // Safe to process payload after validation
    JSONObject payload = generator.getJWTPayload(token);
    return processValidatedPayload(payload);
}
```

### Threat Mitigation

#### Algorithm Confusion Attacks
Prevent algorithm substitution:

```java
public boolean validateTokenAlgorithm(String token, String expectedAlgorithm) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    JSONObject header = generator.getJWTHeader(token);
    
    String algorithm = header.optString("alg", "");
    return expectedAlgorithm.equals(algorithm);
}
```

#### Timing Attacks
Use constant-time comparison for sensitive operations:

```java
public boolean constantTimeEquals(String a, String b) {
    if (a.length() != b.length()) {
        return false;
    }
    
    int result = 0;
    for (int i = 0; i < a.length(); i++) {
        result |= a.charAt(i) ^ b.charAt(i);
    }
    
    return result == 0;
}
```

#### Token Replay Attacks
Implement token uniqueness checks:

```java
public class TokenReplayPrevention {
    
    private final Set<String> usedTokens = ConcurrentHashMap.newKeySet();
    
    public boolean isTokenUsed(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (jti.isEmpty()) {
            return false; // No JTI claim
        }
        
        return !usedTokens.add(jti); // Returns true if already used
    }
    
    public void markTokenAsUsed(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (!jti.isEmpty()) {
            usedTokens.add(jti);
        }
    }
}
```

## Advanced Cryptographic Features

### Additional Security Utilities

The library includes additional cryptographic utilities:

#### Password Hashing (Argon2)
```java
// Note: Available in the library but focus on JWT functionality
PasswordHasher hasher = new PasswordHasherNative();
String hashedPassword = hasher.hash("userPassword", salt);
```

#### Text Encryption (AES)
```java
// Note: Available in the library but focus on JWT functionality  
TextCipher cipher = new TextCipher();
String encrypted = cipher.encrypt("sensitive data", key);
```

#### CSRF Token Generation
```java
// Note: Available in the library but focus on JWT functionality
CSRFTokenGenerator csrfGenerator = new CSRFTokenGenerator();
String csrfToken = csrfGenerator.generate();
```

### Secure Token Handling

#### Memory Management
Clear sensitive data from memory:

```java
public class SecureTokenHandler {
    
    public String processTokenSecurely(char[] tokenChars, char[] secretKeyChars) {
        try {
            String token = new String(tokenChars);
            String secretKey = new String(secretKeyChars);
            
            JWTTokenGenerator generator = new JWTTokenGenerator();
            boolean isValid = generator.isValidSignature(token, secretKey);
            
            return isValid ? "VALID" : "INVALID";
            
        } finally {
            // Clear sensitive data
            Arrays.fill(tokenChars, '\0');
            Arrays.fill(secretKeyChars, '\0');
        }
    }
}
```

#### Secure Transport
Ensure tokens are transmitted securely:

```java
public class SecureTokenTransport {
    
    public void sendTokenSecurely(String token, HttpServletResponse response) {
        // Use secure, HTTP-only cookies
        Cookie tokenCookie = new Cookie("auth_token", token);
        tokenCookie.setHttpOnly(true);
        tokenCookie.setSecure(true);
        tokenCookie.setPath("/");
        tokenCookie.setMaxAge(3600);
        
        response.addCookie(tokenCookie);
    }
}
```

## Security Validation

### Input Validation
The library provides comprehensive input validation:

```java
// Secret key validation
SECRET_KEY_MIN_32_CHARS    // Ensures minimum key length
STRING_NOT_NULL           // Prevents null values
STRING_NOT_EMPTY          // Prevents empty strings
JSON_NOT_EMPTY           // Validates JSON content
```

### Custom Validation
Implement additional validation layers:

```java
public class EnhancedTokenValidator {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ValidationResult validateEnhanced(String token, String secretKey, SecurityContext context) {
        // Basic signature validation
        if (!generator.isValidSignature(token, secretKey)) {
            return ValidationResult.failure("INVALID_SIGNATURE");
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        
        // Enhanced security checks
        if (!validateTokenAge(payload)) {
            return ValidationResult.failure("TOKEN_TOO_OLD");
        }
        
        if (!validateIpAddress(payload, context.getClientIp())) {
            return ValidationResult.failure("IP_MISMATCH");
        }
        
        if (!validateUserAgent(payload, context.getUserAgent())) {
            return ValidationResult.failure("USER_AGENT_MISMATCH");
        }
        
        return ValidationResult.success();
    }
}
```

## Performance and Security Balance

### Optimized Secure Operations
Balance security with performance:

```java
public class OptimizedSecureValidator {
    
    private final LoadingCache<String, Boolean> signatureCache;
    
    public OptimizedSecureValidator() {
        this.signatureCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(Duration.ofMinutes(5))
            .build(this::validateSignatureUncached);
    }
    
    private Boolean validateSignatureUncached(String cacheKey) {
        String[] parts = cacheKey.split(":");
        String token = parts[0];
        String secretKey = parts[1];
        
        return new JWTTokenGenerator().isValidSignature(token, secretKey);
    }
}
```
