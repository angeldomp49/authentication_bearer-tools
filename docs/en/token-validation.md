# Token Validation Guide

This guide covers comprehensive JWT token validation using the Bearer Authentication Tools library.

## Basic Token Validation

### Signature Verification

The primary validation method checks if a token's signature is valid:

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
boolean isValid = generator.isValidSignature(token, secretKey);

if (isValid) {
    // Token signature is valid - proceed with claims extraction
} else {
    // Invalid signature - reject the token
}
```

### Claims Extraction

After signature validation, extract claims from the token:

```java
// Extract payload claims
JSONObject payload = generator.getJWTPayload(token);
String subject = payload.getString("sub");
long expiration = payload.getLong("exp");

// Extract header information
JSONObject header = generator.getJWTHeader(token);
String algorithm = header.getString("alg");
String tokenType = header.getString("typ");
```

## Comprehensive Validation

### Complete Token Validation Process

```java
public TokenValidationResult validateToken(String token, String secretKey) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    try {
        // Step 1: Validate signature
        if (!generator.isValidSignature(token, secretKey)) {
            return TokenValidationResult.invalid("Invalid signature");
        }
        
        // Step 2: Extract and validate claims
        JSONObject payload = generator.getJWTPayload(token);
        
        // Step 3: Check expiration
        if (payload.has("exp")) {
            long expiration = payload.getLong("exp");
            if (System.currentTimeMillis() > expiration) {
                return TokenValidationResult.invalid("Token expired");
            }
        }
        
        // Step 4: Check not-before time
        if (payload.has("nbf")) {
            long notBefore = payload.getLong("nbf");
            if (System.currentTimeMillis() < notBefore) {
                return TokenValidationResult.invalid("Token not yet valid");
            }
        }
        
        // Step 5: Validate required claims
        if (!payload.has("sub")) {
            return TokenValidationResult.invalid("Missing subject claim");
        }
        
        return TokenValidationResult.valid(payload);
        
    } catch (Exception e) {
        return TokenValidationResult.invalid("Token parsing error: " + e.getMessage());
    }
}
```

### Session Token Validation

For session-based tokens created with `JWTTokenHandler`:

```java
JWTTokenHandler handler = new JWTTokenHandler();
boolean isValidSession = handler.isValidSignature(token, secretKey);

if (isValidSession) {
    JSONObject payload = new JWTTokenGenerator().getJWTPayload(token);
    
    long userId = payload.getLong("uid");
    boolean isClosed = payload.getBoolean("isClosed");
    JSONArray permissions = payload.getJSONArray("permissions");
    
    if (isClosed) {
        // Session is closed - reject token
        return false;
    }
}
```

## Claims Validation

### Standard Claims Validation

```java
public class ClaimsValidator {
    
    public boolean validateStandardClaims(JSONObject payload) {
        // Validate issuer
        if (payload.has("iss")) {
            String issuer = payload.getString("iss");
            if (!isValidIssuer(issuer)) {
                return false;
            }
        }
        
        // Validate audience
        if (payload.has("aud")) {
            String audience = payload.getString("aud");
            if (!isValidAudience(audience)) {
                return false;
            }
        }
        
        // Validate subject
        if (payload.has("sub")) {
            String subject = payload.getString("sub");
            if (subject.isEmpty()) {
                return false;
            }
        }
        
        return true;
    }
    
    private boolean isValidIssuer(String issuer) {
        return "your-app-issuer".equals(issuer);
    }
    
    private boolean isValidAudience(String audience) {
        return "your-app-audience".equals(audience);
    }
}
```

### Custom Claims Validation

```java
public boolean validateCustomClaims(JSONObject payload, User requestingUser) {
    // Validate user ID matches
    if (payload.has("userId")) {
        String tokenUserId = payload.getString("userId");
        if (!tokenUserId.equals(requestingUser.getId())) {
            return false;
        }
    }
    
    // Validate role permissions
    if (payload.has("role")) {
        String role = payload.getString("role");
        if (!requestingUser.hasRole(role)) {
            return false;
        }
    }
    
    // Validate specific permissions
    if (payload.has("permissions")) {
        JSONArray permissions = payload.getJSONArray("permissions");
        for (int i = 0; i < permissions.length(); i++) {
            String permission = permissions.getString(i);
            if (!requestingUser.hasPermission(permission)) {
                return false;
            }
        }
    }
    
    return true;
}
```

## Expiration Checking

### Time-Based Validation

```java
public class ExpirationValidator {
    
    public TokenTimeValidation validateTokenTiming(JSONObject payload) {
        long currentTime = System.currentTimeMillis();
        
        // Check expiration
        if (payload.has("exp")) {
            long expiration = payload.getLong("exp");
            if (currentTime > expiration) {
                return TokenTimeValidation.expired();
            }
        }
        
        // Check not-before
        if (payload.has("nbf")) {
            long notBefore = payload.getLong("nbf");
            if (currentTime < notBefore) {
                return TokenTimeValidation.notYetValid();
            }
        }
        
        // Check issued-at for clock skew
        if (payload.has("iat")) {
            long issuedAt = payload.getLong("iat");
            long clockSkewTolerance = 300000; // 5 minutes
            
            if (currentTime < (issuedAt - clockSkewTolerance)) {
                return TokenTimeValidation.clockSkew();
            }
        }
        
        return TokenTimeValidation.valid();
    }
}
```

### Grace Period Validation

```java
public boolean isTokenValidWithGracePeriod(String token, String secretKey, long gracePeriodMs) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, secretKey)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    if (payload.has("exp")) {
        long expiration = payload.getLong("exp");
        long currentTime = System.currentTimeMillis();
        
        // Allow grace period after expiration
        return currentTime <= (expiration + gracePeriodMs);
    }
    
    return true;
}
```

## Error Handling

### Validation Exception Handling

```java
public class TokenValidator {
    
    public ValidationResult safeValidateToken(String token, String secretKey) {
        try {
            JWTTokenGenerator generator = new JWTTokenGenerator();
            
            boolean isValid = generator.isValidSignature(token, secretKey);
            if (!isValid) {
                return ValidationResult.failure("INVALID_SIGNATURE");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return ValidationResult.success(payload);
            
        } catch (IllegalArgumentException e) {
            return ValidationResult.failure("INVALID_TOKEN_FORMAT");
        } catch (Exception e) {
            return ValidationResult.failure("VALIDATION_ERROR");
        }
    }
}
```

### Common Validation Errors

```java
public enum ValidationError {
    INVALID_SIGNATURE("Token signature is invalid"),
    TOKEN_EXPIRED("Token has expired"),
    TOKEN_NOT_YET_VALID("Token is not yet valid"), 
    MISSING_CLAIMS("Required claims are missing"),
    INVALID_FORMAT("Token format is invalid"),
    PARSING_ERROR("Error parsing token");
    
    private final String message;
    
    ValidationError(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
}
```

## Advanced Validation Scenarios

### Multi-Key Validation

```java
public boolean validateWithMultipleKeys(String token, List<String> secretKeys) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return secretKeys.stream()
        .anyMatch(key -> {
            try {
                return generator.isValidSignature(token, key);
            } catch (Exception e) {
                return false;
            }
        });
}
```

### Conditional Validation

```java
public boolean validateConditionally(String token, String secretKey, ValidationContext context) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, secretKey)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    // Apply context-specific validations
    if (context.requiresAdminRole()) {
        return payload.has("role") && "admin".equals(payload.getString("role"));
    }
    
    if (context.requiresSpecificPermission()) {
        JSONArray permissions = payload.optJSONArray("permissions");
        return permissions != null && 
               containsPermission(permissions, context.getRequiredPermission());
    }
    
    return true;
}
```

## Performance Optimization

### Validation Caching

```java
public class CachedTokenValidator {
    
    private final Map<String, ValidationResult> validationCache = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ValidationResult validateWithCache(String token, String secretKey) {
        String cacheKey = generateCacheKey(token, secretKey);
        
        return validationCache.computeIfAbsent(cacheKey, key -> {
            boolean isValid = generator.isValidSignature(token, secretKey);
            return isValid ? ValidationResult.valid() : ValidationResult.invalid();
        });
    }
    
    private String generateCacheKey(String token, String secretKey) {
        return token.hashCode() + ":" + secretKey.hashCode();
    }
}
```

### Batch Validation

```java
public List<ValidationResult> validateTokens(List<String> tokens, String secretKey) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return tokens.parallelStream()
        .map(token -> {
            try {
                boolean isValid = generator.isValidSignature(token, secretKey);
                return ValidationResult.of(token, isValid);
            } catch (Exception e) {
                return ValidationResult.error(token, e.getMessage());
            }
        })
        .collect(Collectors.toList());
}
```
