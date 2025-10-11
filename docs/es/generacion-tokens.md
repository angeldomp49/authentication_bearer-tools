# Guía de Generación de Tokens

Esta guía cubre la generación integral de tokens JWT utilizando la biblioteca Bearer Authentication Tools.

## Generación Básica de Tokens

### Usando JWTTokenGenerator

La clase `JWTTokenGenerator` proporciona la funcionalidad principal para crear tokens JWT:

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
String token = generator.generateJWT(claveSecreta, header, payload);
```

### Configuración del Header

Los headers JWT estándar deben incluir algoritmo y tipo de token:

```java
var header = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Estructura del Payload

#### Claims Estándar

```java
var payload = ObjectLeafBuilder.builder()
    .put("iss", "tu-emisor")                    // Emisor
    .put("sub", "identificador-usuario")        // Sujeto
    .put("aud", "tu-audiencia")                 // Audiencia
    .put("exp", timestampExpiracion)            // Expiración
    .put("nbf", timestampNoAntes)               // No Antes De
    .put("iat", timestampEmision)               // Emitido En
    .put("jti", UUID.randomUUID().toString())   // ID JWT
    .build();
```

#### Claims Personalizados

```java
var payload = ObjectLeafBuilder.builder()
    .put("idUsuario", "12345")
    .put("rol", "administrador")
    .put("permisos", arrayPermisos)
    .put("departamento", "ingenieria")
    .put("nivel", 5)
    .build();
```

## Generación de Tokens Basada en Sesiones

### Usando JWTTokenHandler

Para gestión de sesiones, usa `JWTTokenHandler` con estructuras de sesión predefinidas:

```java
JWTTokenHandler handler = new JWTTokenHandler();

SessionInformation sesion = new SessionInformation(
    idUsuario,
    fechaExpiracion,
    false,  // estaCerrada
    Arrays.asList("lectura", "escritura", "admin")
);

String token = handler.createTokenForSession(sesion, claveSecreta);
```

### Estructura de SessionInformation

```java
public record SessionInformation(
    long idUsuario,
    Calendar fechaExpiracion,
    boolean estaCerrada,
    List<String> permisos
) {}
```

## Selección de Algoritmo

### Algoritmos HMAC

La biblioteca usa HMAC-SHA512 por defecto para firma:

```java
// Algoritmo por defecto (HMAC-SHA512)
var header = ObjectLeafBuilder.builder()
    .put("alg", "SHA256")  // Referencia interna
    .put("typ", "jwt")
    .build();
```

## Gestión de Claves

### Requisitos de Clave Secreta

```java
// Mínimo 32 caracteres requeridos
String claveSecreta = "tu-clave-secreta-debe-tener-32-caracteres-minimo";

// Ejemplo de generación de clave segura
String claveSegura = generarClaveSegura(32);
```

### Mejores Prácticas de Seguridad de Claves

1. **Longitud**: Mínimo 32 caracteres
2. **Aleatoriedad**: Usa generación criptográficamente segura y aleatoria
3. **Almacenamiento**: Almacena claves de forma segura (variables de entorno, vaults de claves)
4. **Rotación**: Implementa rotación regular de claves

## Generación Avanzada de Tokens

### Tokens con Payloads Complejos

```java
public String crearTokenComplejo(Usuario usuario, List<Rol> roles) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var arrayRoles = ArrayStringLeafBuilder.builder();
    roles.stream()
        .map(Rol::getNombre)
        .forEach(arrayRoles::add);
    
    var arrayPermisos = ArrayStringLeafBuilder.builder();
    roles.stream()
        .flatMap(rol -> rol.getPermisos().stream())
        .distinct()
        .forEach(arrayPermisos::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", usuario.getId())
        .put("email", usuario.getEmail())
        .put("nombre", usuario.getNombreCompleto())
        .put("roles", arrayRoles.build())
        .put("permisos", arrayPermisos.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + Duration.ofHours(1).toMillis())
        .put("jti", UUID.randomUUID().toString())
        .build();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
    
    return generator.generateJWT(claveSecreta, header, payload);
}
```

### Generación Condicional de Tokens

```java
public String crearTokenCondicional(Usuario usuario, boolean incluirPermisos) {
    var constructorPayload = ObjectLeafBuilder.builder()
        .put("sub", usuario.getId())
        .put("nombre", usuario.getNombre())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000);
    
    if (incluirPermisos) {
        var permisos = ArrayStringLeafBuilder.builder();
        usuario.getPermisos().forEach(permisos::add);
        constructorPayload.put("permisos", permisos.build());
    }
    
    return generator.generateJWT(claveSecreta, header, constructorPayload.build());
}
```

## Manejo de Errores

### Errores de Validación

La biblioteca valida entradas y lanza `IllegalArgumentException` para datos inválidos:

```java
try {
    String token = generator.generateJWT(claveSecreta, header, payload);
} catch (IllegalArgumentException e) {
    // Manejar errores de validación
    System.err.println("Falló la generación de token: " + e.getMessage());
}
```

### Problemas Comunes de Validación

1. **Clave Secreta Muy Corta**: Debe tener al menos 32 caracteres
2. **Valores Nulos**: Headers y payloads no pueden ser nulos
3. **JSON Vacío**: Headers y payloads deben contener JSON válido
4. **Sesión Inválida**: Fallos de validación de sesión

## Consideraciones de Rendimiento

### Optimización de Generación de Tokens

```java
// Reutilizar instancias del generador
private static final JWTTokenGenerator GENERADOR = new JWTTokenGenerator();

// Pre-construir headers comunes
private static final ObjectLeaf HEADER_ESTANDAR = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Generación de Tokens por Lotes

```java
public List<String> generarTokensParaUsuarios(List<Usuario> usuarios, String claveSecreta) {
    return usuarios.stream()
        .map(usuario -> crearTokenParaUsuario(usuario, claveSecreta))
        .collect(Collectors.toList());
}
```

## Ejemplos de Integración

### Integración con Aplicación Web

```java
@Service
public class ServicioToken {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String claveSecreta;
    
    public String autenticarUsuario(String nombreUsuario, String contrasena) {
        Usuario usuario = servicioUsuario.autenticar(nombreUsuario, contrasena);
        
        if (usuario != null) {
            return crearTokenParaUsuario(usuario);
        }
        
        throw new ExcepcionAutenticacion("Credenciales inválidas");
    }
    
    private String crearTokenParaUsuario(Usuario usuario) {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", usuario.getId())
            .put("nombreUsuario", usuario.getNombreUsuario())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(claveSecreta, HEADER_ESTANDAR, payload);
    }
}
```
