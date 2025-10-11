# Guía de Validación de Tokens

Esta guía cubre la validación integral de tokens JWT utilizando la biblioteca Bearer Authentication Tools.

## Validación Básica de Tokens

### Verificación de Firma

El método principal de validación verifica si la firma de un token es válida:

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
boolean esValido = generator.isValidSignature(token, claveSecreta);

if (esValido) {
    // La firma del token es válida - proceder con extracción de claims
} else {
    // Firma inválida - rechazar el token
}
```

### Extracción de Claims

Después de la validación de firma, extrae claims del token:

```java
// Extraer claims del payload
JSONObject payload = generator.getJWTPayload(token);
String sujeto = payload.getString("sub");
long expiracion = payload.getLong("exp");

// Extraer información del header
JSONObject header = generator.getJWTHeader(token);
String algoritmo = header.getString("alg");
String tipoToken = header.getString("typ");
```

## Validación Integral

### Proceso Completo de Validación de Token

```java
public ResultadoValidacionToken validarToken(String token, String claveSecreta) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    try {
        // Paso 1: Validar firma
        if (!generator.isValidSignature(token, claveSecreta)) {
            return ResultadoValidacionToken.invalido("Firma inválida");
        }
        
        // Paso 2: Extraer y validar claims
        JSONObject payload = generator.getJWTPayload(token);
        
        // Paso 3: Verificar expiración
        if (payload.has("exp")) {
            long expiracion = payload.getLong("exp");
            if (System.currentTimeMillis() > expiracion) {
                return ResultadoValidacionToken.invalido("Token expirado");
            }
        }
        
        // Paso 4: Verificar tiempo no-antes-de
        if (payload.has("nbf")) {
            long noAntesDe = payload.getLong("nbf");
            if (System.currentTimeMillis() < noAntesDe) {
                return ResultadoValidacionToken.invalido("Token aún no válido");
            }
        }
        
        // Paso 5: Validar claims requeridos
        if (!payload.has("sub")) {
            return ResultadoValidacionToken.invalido("Falta claim de sujeto");
        }
        
        return ResultadoValidacionToken.valido(payload);
        
    } catch (Exception e) {
        return ResultadoValidacionToken.invalido("Error de parseo de token: " + e.getMessage());
    }
}
```

### Validación de Token de Sesión

Para tokens basados en sesiones creados con `JWTTokenHandler`:

```java
JWTTokenHandler handler = new JWTTokenHandler();
boolean esSesionValida = handler.isValidSignature(token, claveSecreta);

if (esSesionValida) {
    JSONObject payload = new JWTTokenGenerator().getJWTPayload(token);
    
    long idUsuario = payload.getLong("uid");
    boolean estaCerrada = payload.getBoolean("isClosed");
    JSONArray permisos = payload.getJSONArray("permissions");
    
    if (estaCerrada) {
        // Sesión está cerrada - rechazar token
        return false;
    }
}
```

## Validación de Claims

### Validación de Claims Estándar

```java
public class ValidadorClaims {
    
    public boolean validarClaimsEstandar(JSONObject payload) {
        // Validar emisor
        if (payload.has("iss")) {
            String emisor = payload.getString("iss");
            if (!esEmisorValido(emisor)) {
                return false;
            }
        }
        
        // Validar audiencia
        if (payload.has("aud")) {
            String audiencia = payload.getString("aud");
            if (!esAudienciaValida(audiencia)) {
                return false;
            }
        }
        
        // Validar sujeto
        if (payload.has("sub")) {
            String sujeto = payload.getString("sub");
            if (sujeto.isEmpty()) {
                return false;
            }
        }
        
        return true;
    }
    
    private boolean esEmisorValido(String emisor) {
        return "emisor-de-tu-app".equals(emisor);
    }
    
    private boolean esAudienciaValida(String audiencia) {
        return "audiencia-de-tu-app".equals(audiencia);
    }
}
```

### Validación de Claims Personalizados

```java
public boolean validarClaimsPersonalizados(JSONObject payload, Usuario usuarioSolicitante) {
    // Validar que el ID de usuario coincida
    if (payload.has("idUsuario")) {
        String idUsuarioToken = payload.getString("idUsuario");
        if (!idUsuarioToken.equals(usuarioSolicitante.getId())) {
            return false;
        }
    }
    
    // Validar permisos de rol
    if (payload.has("rol")) {
        String rol = payload.getString("rol");
        if (!usuarioSolicitante.tieneRol(rol)) {
            return false;
        }
    }
    
    // Validar permisos específicos
    if (payload.has("permisos")) {
        JSONArray permisos = payload.getJSONArray("permisos");
        for (int i = 0; i < permisos.length(); i++) {
            String permiso = permisos.getString(i);
            if (!usuarioSolicitante.tienePermiso(permiso)) {
                return false;
            }
        }
    }
    
    return true;
}
```

## Verificación de Expiración

### Validación Basada en Tiempo

```java
public class ValidadorExpiracion {
    
    public ValidacionTiempoToken validarTiempoToken(JSONObject payload) {
        long tiempoActual = System.currentTimeMillis();
        
        // Verificar expiración
        if (payload.has("exp")) {
            long expiracion = payload.getLong("exp");
            if (tiempoActual > expiracion) {
                return ValidacionTiempoToken.expirado();
            }
        }
        
        // Verificar no-antes-de
        if (payload.has("nbf")) {
            long noAntesDe = payload.getLong("nbf");
            if (tiempoActual < noAntesDe) {
                return ValidacionTiempoToken.aunNoValido();
            }
        }
        
        // Verificar emitido-en para desviación de reloj
        if (payload.has("iat")) {
            long emitidoEn = payload.getLong("iat");
            long toleranciaDesviacion = 300000; // 5 minutos
            
            if (tiempoActual < (emitidoEn - toleranciaDesviacion)) {
                return ValidacionTiempoToken.desviacionReloj();
            }
        }
        
        return ValidacionTiempoToken.valido();
    }
}
```

### Validación con Período de Gracia

```java
public boolean esTokenValidoConPeriodoGracia(String token, String claveSecreta, long periodoGraciaMs) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, claveSecreta)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    if (payload.has("exp")) {
        long expiracion = payload.getLong("exp");
        long tiempoActual = System.currentTimeMillis();
        
        // Permitir período de gracia después de expiración
        return tiempoActual <= (expiracion + periodoGraciaMs);
    }
    
    return true;
}
```

## Manejo de Errores

### Manejo de Excepciones de Validación

```java
public class ValidadorToken {
    
    public ResultadoValidacion validarTokenSeguro(String token, String claveSecreta) {
        try {
            JWTTokenGenerator generator = new JWTTokenGenerator();
            
            boolean esValido = generator.isValidSignature(token, claveSecreta);
            if (!esValido) {
                return ResultadoValidacion.fallo("FIRMA_INVALIDA");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return ResultadoValidacion.exito(payload);
            
        } catch (IllegalArgumentException e) {
            return ResultadoValidacion.fallo("FORMATO_TOKEN_INVALIDO");
        } catch (Exception e) {
            return ResultadoValidacion.fallo("ERROR_VALIDACION");
        }
    }
}
```

### Errores Comunes de Validación

```java
public enum ErrorValidacion {
    FIRMA_INVALIDA("La firma del token es inválida"),
    TOKEN_EXPIRADO("El token ha expirado"),
    TOKEN_AUN_NO_VALIDO("El token aún no es válido"), 
    CLAIMS_FALTANTES("Faltan claims requeridos"),
    FORMATO_INVALIDO("El formato del token es inválido"),
    ERROR_PARSEO("Error al parsear el token");
    
    private final String mensaje;
    
    ErrorValidacion(String mensaje) {
        this.mensaje = mensaje;
    }
    
    public String getMensaje() {
        return mensaje;
    }
}
```

## Escenarios Avanzados de Validación

### Validación Multi-Clave

```java
public boolean validarConMultiplesClaves(String token, List<String> clavesSecretas) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return clavesSecretas.stream()
        .anyMatch(clave -> {
            try {
                return generator.isValidSignature(token, clave);
            } catch (Exception e) {
                return false;
            }
        });
}
```

### Validación Condicional

```java
public boolean validarCondicionalmente(String token, String claveSecreta, ContextoValidacion contexto) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, claveSecreta)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    // Aplicar validaciones específicas del contexto
    if (contexto.requiereRolAdmin()) {
        return payload.has("rol") && "admin".equals(payload.getString("rol"));
    }
    
    if (contexto.requierePermisoEspecifico()) {
        JSONArray permisos = payload.optJSONArray("permisos");
        return permisos != null && 
               contienePermiso(permisos, contexto.getPermisoRequerido());
    }
    
    return true;
}
```

## Optimización de Rendimiento

### Caché de Validación

```java
public class ValidadorTokenEnCache {
    
    private final Map<String, ResultadoValidacion> cacheValidacion = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultadoValidacion validarConCache(String token, String claveSecreta) {
        String claveCache = generarClaveCache(token, claveSecreta);
        
        return cacheValidacion.computeIfAbsent(claveCache, clave -> {
            boolean esValido = generator.isValidSignature(token, claveSecreta);
            return esValido ? ResultadoValidacion.valido() : ResultadoValidacion.invalido();
        });
    }
    
    private String generarClaveCache(String token, String claveSecreta) {
        return token.hashCode() + ":" + claveSecreta.hashCode();
    }
}
```

### Validación por Lotes

```java
public List<ResultadoValidacion> validarTokens(List<String> tokens, String claveSecreta) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return tokens.parallelStream()
        .map(token -> {
            try {
                boolean esValido = generator.isValidSignature(token, claveSecreta);
                return ResultadoValidacion.de(token, esValido);
            } catch (Exception e) {
                return ResultadoValidacion.error(token, e.getMessage());
            }
        })
        .collect(Collectors.toList());
}
```
