# Inicio Rápido con Bearer Authentication Tools

Esta guía te ayudará a comenzar con la biblioteca Bearer Authentication Tools para la gestión de tokens JWT en Java.

## Prerequisitos

- Java 17 o superior
- Comprensión básica de conceptos JWT
- Familiaridad con estructuras JSON

## Pasos de Instalación

### Paso 1: Construir la Biblioteca

Clona o descarga el proyecto y constrúyelo:

```bash
cd bearer_authentication/tools
./gradlew build
```

### Paso 2: Incluir en tu Proyecto

Añade el JAR generado al classpath de tu proyecto:
```
lib/build/libs/lib-1.4.3.jar
```

### Paso 3: Importar Clases Requeridas

```java
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.json.JSONObject;
```

## Tu Primer Token JWT

### Creando un Token Simple

```java
public class EjemploToken {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
            
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "usuario123")
            .put("nombre", "Juan Pérez")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
            
        String claveSecreta = "mi-clave-super-secreta-32-caracteres";
        String token = generator.generateJWT(claveSecreta, header, payload);
        
        System.out.println("Token Generado: " + token);
    }
}
```

### Validando el Token

```java
public class EjemploValidacion {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        String token = "tu.token.jwt";
        String claveSecreta = "mi-clave-super-secreta-32-caracteres";
        
        if (generator.isValidSignature(token, claveSecreta)) {
            JSONObject payload = generator.getJWTPayload(token);
            String sujeto = payload.getString("sub");
            String nombre = payload.getString("nombre");
            long expiracion = payload.getLong("exp");
            
            System.out.println("Token válido para usuario: " + nombre);
            System.out.println("Sujeto: " + sujeto);
            System.out.println("Expira en: " + new Date(expiracion));
        } else {
            System.out.println("Firma de token inválida");
        }
    }
}
```

## Patrones Comunes

### Token con Verificación de Expiración

```java
public boolean esTokenValidoYNoExpirado(String token, String claveSecreta) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, claveSecreta)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    long expiracion = payload.getLong("exp");
    
    return System.currentTimeMillis() < expiracion;
}
```

### Manejo de Claims Personalizados

```java
public String crearTokenUsuario(String idUsuario, String rol, List<String> permisos) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
        
    var arrayPermisos = ArrayStringLeafBuilder.builder();
    permisos.forEach(arrayPermisos::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", idUsuario)
        .put("rol", rol)
        .put("permisos", arrayPermisos.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000)
        .build();
        
    return generator.generateJWT("tu-clave-secreta", header, payload);
}
```

## Mejores Prácticas

1. **Siempre Validar Firmas**: Nunca confíes en el contenido del token sin validación de firma
2. **Verificar Expiración**: Siempre verifica las fechas de expiración de los tokens
3. **Claves Secretas Seguras**: Usa claves secretas fuertes, generadas aleatoriamente
4. **Manejar Excepciones**: Envuelve las operaciones de tokens en manejo adecuado de excepciones
5. **Registrar Eventos de Seguridad**: Registra validaciones fallidas para monitoreo de seguridad

## Siguientes Pasos

- Aprende sobre [Generación de Tokens](generacion-tokens.md) en detalle
- Explora técnicas de [Validación de Tokens](validacion-tokens.md)
- Revisa [Mejores Prácticas de Seguridad](criptografia.md)
- Ve más [Ejemplos](ejemplos.md)
