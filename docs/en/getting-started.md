# Getting Started with Bearer Authentication Tools

This guide will help you get started with the Bearer Authentication Tools library for JWT token management in Java.

## Prerequisites

- Java 17 or higher
- Basic understanding of JWT concepts
- Familiarity with JSON structures

## Installation Steps

### Step 1: Build the Library

Clone or download the project and build it:

```bash
cd bearer_authentication/tools
./gradlew build
```

### Step 2: Include in Your Project

Add the generated JAR to your project classpath:
```
lib/build/libs/lib-1.4.3.jar
```

### Step 3: Import Required Classes

```java
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.json.JSONObject;
```

## Your First JWT Token

### Creating a Simple Token

```java
public class TokenExample {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
            
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "user123")
            .put("name", "John Doe")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
            
        String secretKey = "my-super-secret-key-32-characters";
        String token = generator.generateJWT(secretKey, header, payload);
        
        System.out.println("Generated Token: " + token);
    }
}
```

### Validating the Token

```java
public class ValidationExample {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        String token = "your.jwt.token";
        String secretKey = "my-super-secret-key-32-characters";
        
        if (generator.isValidSignature(token, secretKey)) {
            JSONObject payload = generator.getJWTPayload(token);
            String subject = payload.getString("sub");
            String name = payload.getString("name");
            long expiration = payload.getLong("exp");
            
            System.out.println("Valid token for user: " + name);
            System.out.println("Subject: " + subject);
            System.out.println("Expires at: " + new Date(expiration));
        } else {
            System.out.println("Invalid token signature");
        }
    }
}
```

## Common Patterns

### Token with Expiration Check

```java
public boolean isTokenValidAndNotExpired(String token, String secretKey) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, secretKey)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    long expiration = payload.getLong("exp");
    
    return System.currentTimeMillis() < expiration;
}
```

### Custom Claims Handling

```java
public String createUserToken(String userId, String role, List<String> permissions) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
        
    var permissionsArray = ArrayStringLeafBuilder.builder();
    permissions.forEach(permissionsArray::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", userId)
        .put("role", role)
        .put("permissions", permissionsArray.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000)
        .build();
        
    return generator.generateJWT("your-secret-key", header, payload);
}
```

## Best Practices

1. **Always Validate Signatures**: Never trust token content without signature validation
2. **Check Expiration**: Always verify token expiration dates
3. **Secure Secret Keys**: Use strong, randomly generated secret keys
4. **Handle Exceptions**: Wrap token operations in proper exception handling
5. **Log Security Events**: Log failed validations for security monitoring

## Next Steps

- Learn about [Token Generation](token-generation.md) in detail
- Explore [Token Validation](token-validation.md) techniques
- Review [Security Best Practices](cryptography.md)
- See more [Examples](examples.md)
