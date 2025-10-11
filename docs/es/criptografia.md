# Guía de Criptografía y Seguridad

Esta guía cubre los aspectos criptográficos y consideraciones de seguridad de la biblioteca Bearer Authentication Tools.

## Algoritmos Soportados

### Algoritmos HMAC

La biblioteca usa HMAC (Código de Autenticación de Mensaje basado en Hash) para firma de tokens:

#### HMAC-SHA512 (Por Defecto)
- **Implementación Interna**: Usa Hashing.hmacSha512() de Google Guava
- **Tamaño de Clave**: Mínimo 32 caracteres (se recomienda 256 bits)
- **Nivel de Seguridad**: Alto
- **Rendimiento**: Bueno

```java
// Algoritmo por defecto usado por SignaturePrinter
SignaturePrinter firmador = new SignaturePrinter(claveSecreta);
String firma = firmador.sign(mensaje);
```

#### Selección de Algoritmo

La biblioteca usa internamente HMAC-SHA512 para todas las operaciones de firma, proporcionando fuerte seguridad criptográfica:

```java
// Implementación interna (de la clase SignaturePrinter)
public String sign(String mensaje) {
    return Hashing.hmacSha512(claveSecreta.getBytes(StandardCharsets.UTF_8))
            .hashString(mensaje, StandardCharsets.UTF_8)
            .toString();
}
```

## Gestión de Claves

### Requisitos de Clave Secreta

#### Estándares Mínimos de Seguridad
- **Longitud**: Mínimo 32 caracteres (se recomienda 256 bits)
- **Conjunto de Caracteres**: Usar conjunto completo de caracteres ASCII para máxima entropía
- **Aleatoriedad**: Generar usando generadores de números aleatorios criptográficamente seguros

```java
// Ejemplo de generación de clave segura
public String generarClaveSegura(int longitud) {
    SecureRandom random = new SecureRandom();
    StringBuilder clave = new StringBuilder(longitud);
    String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    
    for (int i = 0; i < longitud; i++) {
        clave.append(charset.charAt(random.nextInt(charset.length())));
    }
    
    return clave.toString();
}
```

#### Mejores Prácticas de Almacenamiento de Claves

```java
// Almacenamiento en variable de entorno
String claveSecreta = System.getenv("JWT_SECRET_KEY");

// Archivo de propiedades (cifrado)
Properties props = new Properties();
props.load(new FileInputStream("secure.properties"));
String claveSecreta = descifrar(props.getProperty("jwt.secret.encrypted"));

// Integración con servicio de gestión de claves
String claveSecreta = servicioGestionClaves.getClave("jwt-signing-key");
```

### Rotación de Claves

Implementa rotación regular de claves para seguridad mejorada:

```java
public class ServicioRotacionClaves {
    
    private final Map<String, String> clavesActivas = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public String crearTokenConClaveActual(ObjectLeaf header, ObjectLeaf payload) {
        String idClaveActual = getIdClaveActual();
        String claveSecreta = clavesActivas.get(idClaveActual);
        
        // Añadir ID de clave al header
        var headerConIdClave = ObjectLeafBuilder.builder()
            .putAll(header.asMap())
            .put("kid", idClaveActual)
            .build();
        
        return generator.generateJWT(claveSecreta, headerConIdClave, payload);
    }
    
    public boolean validarTokenConRotacionClave(String token, String idClave) {
        String claveSecreta = clavesActivas.get(idClave);
        if (claveSecreta == null) {
            return false; // Clave no encontrada o expirada
        }
        
        return generator.isValidSignature(token, claveSecreta);
    }
    
    public void rotarClave() {
        String nuevoIdClave = generarNuevoIdClave();
        String nuevaClaveSecreta = generarClaveSegura(64);
        clavesActivas.put(nuevoIdClave, nuevaClaveSecreta);
        
        // Mantener claves antiguas por período de gracia
        programarLimpiezaClave(nuevoIdClave);
    }
}
```

## Consideraciones de Seguridad

### Seguridad de Tokens

#### Gestión de Expiración
Siempre establece tiempos de expiración apropiados:

```java
public long calcularTiempoExpiracion(TipoToken tipoToken) {
    return switch (tipoToken) {
        case TOKEN_ACCESO -> System.currentTimeMillis() + Duration.ofMinutes(15).toMillis();
        case TOKEN_REFRESCO -> System.currentTimeMillis() + Duration.ofDays(30).toMillis();
        case TOKEN_SESION -> System.currentTimeMillis() + Duration.ofHours(8).toMillis();
    };
}
```

#### Validación de Firma
Siempre valida firmas antes de procesar el contenido del token:

```java
public ResultadoProcesamiento procesarToken(String token, String claveSecreta) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    // NUNCA extraer payload sin validación de firma
    if (!generator.isValidSignature(token, claveSecreta)) {
        throw new SecurityException("Firma de token inválida");
    }
    
    // Seguro procesar payload después de validación
    JSONObject payload = generator.getJWTPayload(token);
    return procesarPayloadValidado(payload);
}
```

### Mitigación de Amenazas

#### Ataques de Confusión de Algoritmo
Prevenir sustitución de algoritmo:

```java
public boolean validarAlgoritmoToken(String token, String algoritmoEsperado) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    JSONObject header = generator.getJWTHeader(token);
    
    String algoritmo = header.optString("alg", "");
    return algoritmoEsperado.equals(algoritmo);
}
```

#### Ataques de Temporización
Usar comparación de tiempo constante para operaciones sensibles:

```java
public boolean igualTiempoConstante(String a, String b) {
    if (a.length() != b.length()) {
        return false;
    }
    
    int resultado = 0;
    for (int i = 0; i < a.length(); i++) {
        resultado |= a.charAt(i) ^ b.charAt(i);
    }
    
    return resultado == 0;
}
```

#### Ataques de Repetición de Token
Implementar verificaciones de unicidad de token:

```java
public class PrevencionReproduccionToken {
    
    private final Set<String> tokensUsados = ConcurrentHashMap.newKeySet();
    
    public boolean esTokenUsado(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (jti.isEmpty()) {
            return false; // Sin claim JTI
        }
        
        return !tokensUsados.add(jti); // Retorna true si ya fue usado
    }
    
    public void marcarTokenComoUsado(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (!jti.isEmpty()) {
            tokensUsados.add(jti);
        }
    }
}
```

## Características Criptográficas Avanzadas

### Utilidades de Seguridad Adicionales

La biblioteca incluye utilidades criptográficas adicionales:

#### Hash de Contraseñas (Argon2)
```java
// Nota: Disponible en la biblioteca pero enfoque en funcionalidad JWT
PasswordHasher hasher = new PasswordHasherNative();
String contrasenaHasheada = hasher.hash("contrasenaUsuario", salt);
```

#### Cifrado de Texto (AES)
```java
// Nota: Disponible en la biblioteca pero enfoque en funcionalidad JWT  
TextCipher cipher = new TextCipher();
String cifrado = cipher.encrypt("datos sensibles", clave);
```

#### Generación de Token CSRF
```java
// Nota: Disponible en la biblioteca pero enfoque en funcionalidad JWT
CSRFTokenGenerator generadorCsrf = new CSRFTokenGenerator();
String tokenCsrf = generadorCsrf.generate();
```

### Manejo Seguro de Tokens

#### Gestión de Memoria
Limpiar datos sensibles de la memoria:

```java
public class ManejadorTokenSeguro {
    
    public String procesarTokenSeguramente(char[] charsToken, char[] charsClaveSecreta) {
        try {
            String token = new String(charsToken);
            String claveSecreta = new String(charsClaveSecreta);
            
            JWTTokenGenerator generator = new JWTTokenGenerator();
            boolean esValido = generator.isValidSignature(token, claveSecreta);
            
            return esValido ? "VALIDO" : "INVALIDO";
            
        } finally {
            // Limpiar datos sensibles
            Arrays.fill(charsToken, '\0');
            Arrays.fill(charsClaveSecreta, '\0');
        }
    }
}
```

#### Transporte Seguro
Asegurar que los tokens se transmitan de forma segura:

```java
public class TransporteTokenSeguro {
    
    public void enviarTokenSeguramente(String token, HttpServletResponse response) {
        // Usar cookies seguras, solo HTTP
        Cookie cookieToken = new Cookie("auth_token", token);
        cookieToken.setHttpOnly(true);
        cookieToken.setSecure(true);
        cookieToken.setPath("/");
        cookieToken.setMaxAge(3600);
        
        response.addCookie(cookieToken);
    }
}
```

## Validación de Seguridad

### Validación de Entrada
La biblioteca proporciona validación integral de entrada:

```java
// Validación de clave secreta
SECRET_KEY_MIN_32_CHARS    // Asegura longitud mínima de clave
STRING_NOT_NULL           // Previene valores nulos
STRING_NOT_EMPTY          // Previene cadenas vacías
JSON_NOT_EMPTY           // Valida contenido JSON
```

### Validación Personalizada
Implementar capas adicionales de validación:

```java
public class ValidadorTokenMejorado {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultadoValidacion validarMejorado(String token, String claveSecreta, ContextoSeguridad contexto) {
        // Validación básica de firma
        if (!generator.isValidSignature(token, claveSecreta)) {
            return ResultadoValidacion.fallo("FIRMA_INVALIDA");
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        
        // Verificaciones de seguridad mejoradas
        if (!validarEdadToken(payload)) {
            return ResultadoValidacion.fallo("TOKEN_MUY_VIEJO");
        }
        
        if (!validarDireccionIP(payload, contexto.getIpCliente())) {
            return ResultadoValidacion.fallo("IP_NO_COINCIDE");
        }
        
        if (!validarUserAgent(payload, contexto.getUserAgent())) {
            return ResultadoValidacion.fallo("USER_AGENT_NO_COINCIDE");
        }
        
        return ResultadoValidacion.exito();
    }
}
```

## Balance entre Rendimiento y Seguridad

### Operaciones Seguras Optimizadas
Balancear seguridad con rendimiento:

```java
public class ValidadorSeguroOptimizado {
    
    private final LoadingCache<String, Boolean> cacheFirma;
    
    public ValidadorSeguroOptimizado() {
        this.cacheFirma = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(Duration.ofMinutes(5))
            .build(this::validarFirmaSinCache);
    }
    
    private Boolean validarFirmaSinCache(String claveCacheado) {
        String[] partes = claveCacheado.split(":");
        String token = partes[0];
        String claveSecreta = partes[1];
        
        return new JWTTokenGenerator().isValidSignature(token, claveSecreta);
    }
}
```
