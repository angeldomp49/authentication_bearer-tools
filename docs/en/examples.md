# Examples and Use Cases

This guide provides practical examples and common use cases for the Bearer Authentication Tools library.

## Basic Examples

### Simple Authentication Flow

```java
public class SimpleAuthenticationExample {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String secretKey = "my-super-secret-key-32-characters";
    
    public String authenticateUser(String username, String password) {
        User user = validateCredentials(username, password);
        
        if (user == null) {
            throw new AuthenticationException("Invalid credentials");
        }
        
        return createTokenForUser(user);
    }
    
    private String createTokenForUser(User user) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", user.getId())
            .put("username", user.getUsername())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .put("iat", System.currentTimeMillis())
            .build();
        
        return generator.generateJWT(secretKey, header, payload);
    }
    
    public boolean validateToken(String token) {
        return generator.isValidSignature(token, secretKey);
    }
}
```

### Session Management Example

```java
public class SessionManagementExample {
    
    private final JWTTokenHandler handler = new JWTTokenHandler();
    private final String secretKey = "session-secret-key-32-characters";
    
    public String createUserSession(User user, List<String> permissions) {
        Calendar expirationDate = Calendar.getInstance();
        expirationDate.add(Calendar.HOUR, 12);
        
        SessionInformation session = new SessionInformation(
            user.getId(),
            expirationDate,
            false,
            permissions
        );
        
        return handler.createTokenForSession(session, secretKey);
    }
    
    public SessionInfo validateAndExtractSession(String token) {
        if (!handler.isValidSignature(token, secretKey)) {
            throw new InvalidTokenException("Invalid session token");
        }
        
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        return new SessionInfo(
            payload.getLong("uid"),
            payload.getBoolean("isClosed"),
            extractPermissions(payload.getJSONArray("permissions")),
            payload.getLong("exp")
        );
    }
}
```

## Web Application Integration

### Spring Boot Integration

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final TokenService tokenService;
    
    @Autowired
    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        try {
            String token = tokenService.authenticateUser(
                request.getUsername(), 
                request.getPassword()
            );
            
            return ResponseEntity.ok(new LoginResponse(token, "success"));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new LoginResponse(null, "Invalid credentials"));
        }
    }
    
    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validateToken(@RequestHeader("Authorization") String authHeader) {
        String token = extractTokenFromHeader(authHeader);
        
        if (tokenService.isTokenValid(token)) {
            UserInfo userInfo = tokenService.getUserInfoFromToken(token);
            return ResponseEntity.ok(new ValidationResponse(true, userInfo));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ValidationResponse(false, null));
        }
    }
}

@Service
public class TokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    public String authenticateUser(String username, String password) {
        User user = userRepository.findByUsernameAndPassword(username, hashPassword(password));
        
        if (user == null) {
            throw new AuthenticationException("Invalid credentials");
        }
        
        return createToken(user);
    }
    
    public boolean isTokenValid(String token) {
        try {
            return generator.isValidSignature(token, secretKey) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isTokenExpired(String token) {
        JSONObject payload = generator.getJWTPayload(token);
        long expiration = payload.getLong("exp");
        return System.currentTimeMillis() > expiration;
    }
}
```

### Servlet Filter Integration

```java
@WebFilter("/*")
public class JWTAuthenticationFilter implements Filter {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private String secretKey;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        secretKey = filterConfig.getInitParameter("jwt.secret");
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String token = extractTokenFromRequest(httpRequest);
        
        if (token != null && generator.isValidSignature(token, secretKey)) {
            JSONObject payload = generator.getJWTPayload(token);
            
            // Add user context to request
            httpRequest.setAttribute("userId", payload.getString("sub"));
            httpRequest.setAttribute("username", payload.getString("username"));
        }
        
        chain.doFilter(request, response);
    }
    
    private String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
```

## Microservices Architecture

### Service-to-Service Authentication

```java
@Service
public class MicroserviceTokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String serviceSecretKey = "service-to-service-secret-key";
    
    public String createServiceToken(String serviceId, List<String> scopes) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var scopesArray = ArrayStringLeafBuilder.builder();
        scopes.forEach(scopesArray::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", serviceId)
            .put("aud", "internal-services")
            .put("scopes", scopesArray.build())
            .put("iat", System.currentTimeMillis())
            .put("exp", System.currentTimeMillis() + Duration.ofMinutes(10).toMillis())
            .build();
        
        return generator.generateJWT(serviceSecretKey, header, payload);
    }
    
    public boolean validateServiceToken(String token, String expectedServiceId) {
        if (!generator.isValidSignature(token, serviceSecretKey)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        String serviceId = payload.getString("sub");
        
        return expectedServiceId.equals(serviceId);
    }
}
```

### API Gateway Integration

```java
@Component
public class APIGatewayTokenValidator {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${gateway.jwt.secret}")
    private String gatewaySecret;
    
    public RouteDecision validateAndRoute(String token, String targetService) {
        if (!generator.isValidSignature(token, gatewaySecret)) {
            return RouteDecision.reject("Invalid token");
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        
        // Check service permissions
        JSONArray permissions = payload.optJSONArray("permissions");
        if (!hasServiceAccess(permissions, targetService)) {
            return RouteDecision.reject("Insufficient permissions");
        }
        
        // Check rate limiting
        String userId = payload.getString("sub");
        if (isRateLimited(userId, targetService)) {
            return RouteDecision.reject("Rate limit exceeded");
        }
        
        return RouteDecision.allow(userId);
    }
    
    private boolean hasServiceAccess(JSONArray permissions, String service) {
        if (permissions == null) return false;
        
        for (int i = 0; i < permissions.length(); i++) {
            String permission = permissions.getString(i);
            if (permission.equals("access:" + service) || permission.equals("admin")) {
                return true;
            }
        }
        return false;
    }
}
```

## Advanced Use Cases

### Multi-Tenant Application

```java
@Service
public class MultiTenantTokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final Map<String, String> tenantSecrets = new ConcurrentHashMap<>();
    
    public String createTenantToken(String tenantId, User user, List<String> roles) {
        String tenantSecret = getTenantSecret(tenantId);
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .put("tenant", tenantId)
            .build();
        
        var rolesArray = ArrayStringLeafBuilder.builder();
        roles.forEach(rolesArray::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", user.getId())
            .put("tenant", tenantId)
            .put("roles", rolesArray.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(tenantSecret, header, payload);
    }
    
    public TenantValidationResult validateTenantToken(String token, String expectedTenantId) {
        try {
            // Extract tenant from header first
            JSONObject header = generator.getJWTHeader(token);
            String tokenTenantId = header.getString("tenant");
            
            if (!expectedTenantId.equals(tokenTenantId)) {
                return TenantValidationResult.failure("Tenant mismatch");
            }
            
            String tenantSecret = getTenantSecret(tokenTenantId);
            if (!generator.isValidSignature(token, tenantSecret)) {
                return TenantValidationResult.failure("Invalid signature");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return TenantValidationResult.success(payload);
            
        } catch (Exception e) {
            return TenantValidationResult.failure("Validation error");
        }
    }
}
```

### Permission-Based Access Control

```java
@Service
public class PermissionBasedTokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    public String createPermissionToken(User user, Set<Permission> permissions) {
        var permissionMap = ObjectLeafBuilder.builder();
        
        // Group permissions by resource
        Map<String, List<String>> resourcePermissions = permissions.stream()
            .collect(Collectors.groupingBy(
                Permission::getResource,
                Collectors.mapping(Permission::getAction, Collectors.toList())
            ));
        
        resourcePermissions.forEach((resource, actions) -> {
            var actionsArray = ArrayStringLeafBuilder.builder();
            actions.forEach(actionsArray::add);
            permissionMap.put(resource, actionsArray.build());
        });
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", user.getId())
            .put("permissions", permissionMap.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        return generator.generateJWT(secretKey, header, payload);
    }
    
    public boolean hasPermission(String token, String resource, String action) {
        if (!generator.isValidSignature(token, secretKey)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        JSONObject permissions = payload.optJSONObject("permissions");
        
        if (permissions == null || !permissions.has(resource)) {
            return false;
        }
        
        JSONArray actions = permissions.getJSONArray(resource);
        for (int i = 0; i < actions.length(); i++) {
            if (action.equals(actions.getString(i))) {
                return true;
            }
        }
        
        return false;
    }
}
```

## Error Handling Examples

### Comprehensive Error Handling

```java
@Service
public class RobustTokenService {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public TokenProcessingResult processToken(String token, String secretKey) {
        try {
            // Step 1: Basic validation
            if (token == null || token.trim().isEmpty()) {
                return TokenProcessingResult.error(ErrorCode.MISSING_TOKEN);
            }
            
            // Step 2: Format validation
            if (!isValidJWTFormat(token)) {
                return TokenProcessingResult.error(ErrorCode.INVALID_FORMAT);
            }
            
            // Step 3: Signature validation
            if (!generator.isValidSignature(token, secretKey)) {
                return TokenProcessingResult.error(ErrorCode.INVALID_SIGNATURE);
            }
            
            // Step 4: Claims extraction and validation
            JSONObject payload = generator.getJWTPayload(token);
            
            if (!payload.has("exp")) {
                return TokenProcessingResult.error(ErrorCode.MISSING_EXPIRATION);
            }
            
            long expiration = payload.getLong("exp");
            if (System.currentTimeMillis() > expiration) {
                return TokenProcessingResult.error(ErrorCode.TOKEN_EXPIRED);
            }
            
            return TokenProcessingResult.success(payload);
            
        } catch (IllegalArgumentException e) {
            return TokenProcessingResult.error(ErrorCode.INVALID_INPUT, e.getMessage());
        } catch (JSONException e) {
            return TokenProcessingResult.error(ErrorCode.JSON_PARSING_ERROR, e.getMessage());
        } catch (Exception e) {
            return TokenProcessingResult.error(ErrorCode.UNEXPECTED_ERROR, e.getMessage());
        }
    }
    
    private boolean isValidJWTFormat(String token) {
        String[] parts = token.split("\\.");
        return parts.length == 3;
    }
}

public enum ErrorCode {
    MISSING_TOKEN("Token is missing"),
    INVALID_FORMAT("Invalid JWT format"),
    INVALID_SIGNATURE("Invalid token signature"),
    MISSING_EXPIRATION("Token missing expiration"),
    TOKEN_EXPIRED("Token has expired"),
    INVALID_INPUT("Invalid input parameters"),
    JSON_PARSING_ERROR("Error parsing JSON"),
    UNEXPECTED_ERROR("Unexpected error occurred");
    
    private final String message;
    
    ErrorCode(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
}
```

## Testing Examples

### Unit Testing Token Operations

```java
@ExtendWith(MockitoExtension.class)
class TokenServiceTest {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String testSecretKey = "test-secret-key-32-characters-long";
    
    @Test
    void shouldCreateValidToken() {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "test-user")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
        
        String token = generator.generateJWT(testSecretKey, header, payload);
        
        assertThat(token).isNotNull();
        assertThat(generator.isValidSignature(token, testSecretKey)).isTrue();
    }
    
    @Test
    void shouldRejectInvalidSignature() {
        String invalidToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature";
        
        assertThat(generator.isValidSignature(invalidToken, testSecretKey)).isFalse();
    }
    
    @Test
    void shouldExtractPayloadCorrectly() {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "test-user")
            .put("role", "admin")
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .build();
        
        String token = generator.generateJWT(testSecretKey, header, payload);
        JSONObject extractedPayload = generator.getJWTPayload(token);
        
        assertThat(extractedPayload.getString("sub")).isEqualTo("test-user");
        assertThat(extractedPayload.getString("role")).isEqualTo("admin");
    }
}
```
