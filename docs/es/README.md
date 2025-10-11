# Bearer Authentication Tools

Una biblioteca Java ligera para la generación y validación de tokens JWT con utilidades criptográficas adicionales. Esta biblioteca proporciona funciones auxiliares sin estado para la gestión segura de tokens sin dependencias externas.

## Características

- **Generación de Tokens JWT**: Crea tokens JWT seguros con headers y payloads personalizados
- **Validación de Tokens JWT**: Valida firmas de tokens y extrae claims
- **Soporte de Múltiples Algoritmos**: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- **Cero Dependencias**: Implementación Java pura sin dependencias de frameworks externos
- **Diseño Sin Estado**: Todas las funciones son sin estado para máxima flexibilidad
- **Utilidades de Seguridad**: Herramientas adicionales para hash de contraseñas, cifrado y protección CSRF

## Inicio Rápido

### Generación Básica de Tokens

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

String token = generator.generateJWT("tu-clave-secreta-32-caracteres-minimo", header, payload);
```

### Validación Básica de Tokens

```java
JWTTokenGenerator generator = new JWTTokenGenerator();

boolean esValido = generator.isValidSignature(token, "tu-clave-secreta-32-caracteres-minimo");

if (esValido) {
    JSONObject payload = generator.getJWTPayload(token);
    JSONObject header = generator.getJWTHeader(token);
}
```

## Instalación

### Inclusión Manual del JAR

1. Construye el proyecto usando Gradle:
   ```bash
   ./gradlew build
   ```

2. Incluye el archivo JAR generado en el classpath de tu proyecto:
   ```
   lib/build/libs/lib-1.4.3.jar
   ```

### Construir desde Código Fuente

1. Clona el repositorio
2. Navega al directorio del proyecto
3. Ejecuta el comando de construcción:
   ```bash
   ./gradlew build
   ```

## Componentes Principales

### JWTTokenGenerator

La clase principal para operaciones de tokens JWT:
- `generateJWT(secretKey, header, payload)`: Crea un nuevo token JWT
- `isValidSignature(token, secretKey)`: Valida la firma del token
- `getJWTPayload(token)`: Extrae el payload del token
- `getJWTHeader(token)`: Extrae el header del token

### JWTTokenHandler

Gestión de tokens de alto nivel para autenticación basada en sesiones:
- `createTokenForSession(session, secretKey)`: Crea tokens con estructura de sesión predefinida
- `isValidSignature(token, secretKey)`: Valida tokens de sesión

### Algoritmos Soportados

- **HMAC-SHA256**: Algoritmo por defecto para firma de tokens
- **HMAC-SHA384**: Opción de seguridad mejorada
- **HMAC-SHA512**: Opción de seguridad máxima

## Consideraciones de Seguridad

1. **Requisitos de Clave Secreta**: Mínimo 32 caracteres por seguridad
2. **Expiración de Tokens**: Siempre establece tiempos de expiración para los tokens
3. **Validación de Firma**: Valida las firmas antes de confiar en el contenido del token
4. **Almacenamiento Seguro**: Almacena las claves secretas de forma segura y rota regularmente

## Documentación Adicional

- [Guía de Inicio Rápido](inicio-rapido.md)
- [Generación de Tokens](generacion-tokens.md)
- [Validación de Tokens](validacion-tokens.md)
- [Criptografía](criptografia.md)
- [Ejemplos](ejemplos.md)

## Licencia

Este proyecto es parte de la suite MakechTec Bearer Authentication Tools.
