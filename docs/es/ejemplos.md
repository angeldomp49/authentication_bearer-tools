# Ejemplos y Casos de Uso

Esta guía proporciona ejemplos prácticos y casos de uso comunes para la biblioteca Bearer Authentication Tools.

## Ejemplos Básicos

### Flujo de Autenticación Simple

```java
public class EjemploAutenticacionSimple {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String claveSecreta = "mi-clave-super-secreta-32-caracteres";
    
    public String autenticarUsuario(String nombreUsuario, String contrasena) {
        Usuario usuario = validarCredenciales(nombreUsuario, contrasena);
        
        if (usuario == null) {
            throw new ExcepcionAutenticacion("Credenciales inválidas");
        }
        
        return crearTokenParaUsuario(usuario);
    }
    
    private String crearTokenParaUsuario(Usuario usuario) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", usuario.getId())
            .put("nombreUsuario", usuario.getNombreUsuario())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .put("iat", System.currentTimeMillis())
            .build();
        
        return generator.generateJWT(claveSecreta, header, payload);
    }
    
    public boolean validarToken(String token) {
        return generator.isValidSignature(token, claveSecreta);
    }
}
```

### Ejemplo de Gestión de Sesiones

```java
public class EjemploGestionSesiones {
    
    private final JWTTokenHandler handler = new JWTTokenHandler();
    private final String claveSecreta = "clave-secreta-sesion-32-caracteres";
    
    public String crearSesionUsuario(Usuario usuario, List<String> permisos) {
        Calendar fechaExpiracion = Calendar.getInstance();
        fechaExpiracion.add(Calendar.HOUR, 12);
        
        SessionInformation sesion = new SessionInformation(
            usuario.getId(),
            fechaExpiracion,
            false,
            permisos
        );
        
        return handler.createTokenForSession(sesion, claveSecreta);
    }
    
    public InfoSesion validarYExtraerSesion(String token) {
        if (!handler.isValidSignature(token, claveSecreta)) {
            throw new ExcepcionTokenInvalido("Token de sesión inválido");
        }
        
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        return new InfoSesion(
            payload.getLong("uid"),
            payload.getBoolean("isClosed"),
            extraerPermisos(payload.getJSONArray("permissions")),
            payload.getLong("exp")
        );
    }
}
```

## Integración con Aplicaciones Web

### Integración con Spring Boot

```java
@RestController
@RequestMapping("/api/auth")
public class ControladorAuth {
    
    private final ServicioToken servicioToken;
    
    @Autowired
    public ControladorAuth(ServicioToken servicioToken) {
        this.servicioToken = servicioToken;
    }
    
    @PostMapping("/login")
    public ResponseEntity<RespuestaLogin> login(@RequestBody SolicitudLogin solicitud) {
        try {
            String token = servicioToken.autenticarUsuario(
                solicitud.getNombreUsuario(), 
                solicitud.getContrasena()
            );
            
            return ResponseEntity.ok(new RespuestaLogin(token, "exitoso"));
        } catch (ExcepcionAutenticacion e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new RespuestaLogin(null, "Credenciales inválidas"));
        }
    }
    
    @PostMapping("/validar")
    public ResponseEntity<RespuestaValidacion> validarToken(@RequestHeader("Authorization") String headerAuth) {
        String token = extraerTokenDelHeader(headerAuth);
        
        if (servicioToken.esTokenValido(token)) {
            InfoUsuario infoUsuario = servicioToken.getInfoUsuarioDelToken(token);
            return ResponseEntity.ok(new RespuestaValidacion(true, infoUsuario));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new RespuestaValidacion(false, null));
        }
    }
}

@Service
public class ServicioToken {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String claveSecreta;
    
    public String autenticarUsuario(String nombreUsuario, String contrasena) {
        Usuario usuario = repositorioUsuario.findByNombreUsuarioAndContrasena(nombreUsuario, hashearContrasena(contrasena));
        
        if (usuario == null) {
            throw new ExcepcionAutenticacion("Credenciales inválidas");
        }
        
        return crearToken(usuario);
    }
    
    public boolean esTokenValido(String token) {
        try {
            return generator.isValidSignature(token, claveSecreta) && !esTokenExpirado(token);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean esTokenExpirado(String token) {
        JSONObject payload = generator.getJWTPayload(token);
        long expiracion = payload.getLong("exp");
        return System.currentTimeMillis() > expiracion;
    }
}
```

### Integración con Filtro de Servlet

```java
@WebFilter("/*")
public class FiltroAutenticacionJWT implements Filter {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private String claveSecreta;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        claveSecreta = filterConfig.getInitParameter("jwt.secret");
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String token = extraerTokenDeSolicitud(httpRequest);
        
        if (token != null && generator.isValidSignature(token, claveSecreta)) {
            JSONObject payload = generator.getJWTPayload(token);
            
            // Añadir contexto de usuario a la solicitud
            httpRequest.setAttribute("idUsuario", payload.getString("sub"));
            httpRequest.setAttribute("nombreUsuario", payload.getString("nombreUsuario"));
        }
        
        chain.doFilter(request, response);
    }
    
    private String extraerTokenDeSolicitud(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}
```

## Arquitectura de Microservicios

### Autenticación Servicio-a-Servicio

```java
@Service
public class ServicioTokenMicroservicio {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String claveSecretaServicio = "clave-secreta-servicio-a-servicio";
    
    public String crearTokenServicio(String idServicio, List<String> alcances) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var arrayAlcances = ArrayStringLeafBuilder.builder();
        alcances.forEach(arrayAlcances::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", idServicio)
            .put("aud", "servicios-internos")
            .put("scopes", arrayAlcances.build())
            .put("iat", System.currentTimeMillis())
            .put("exp", System.currentTimeMillis() + Duration.ofMinutes(10).toMillis())
            .build();
        
        return generator.generateJWT(claveSecretaServicio, header, payload);
    }
    
    public boolean validarTokenServicio(String token, String idServicioEsperado) {
        if (!generator.isValidSignature(token, claveSecretaServicio)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        String idServicio = payload.getString("sub");
        
        return idServicioEsperado.equals(idServicio);
    }
}
```

## Casos de Uso Avanzados

### Aplicación Multi-Inquilino

```java
@Service
public class ServicioTokenMultiInquilino {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final Map<String, String> secretosInquilino = new ConcurrentHashMap<>();
    
    public String crearTokenInquilino(String idInquilino, Usuario usuario, List<String> roles) {
        String secretoInquilino = getSecretoInquilino(idInquilino);
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .put("inquilino", idInquilino)
            .build();
        
        var arrayRoles = ArrayStringLeafBuilder.builder();
        roles.forEach(arrayRoles::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", usuario.getId())
            .put("inquilino", idInquilino)
            .put("roles", arrayRoles.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(secretoInquilino, header, payload);
    }
    
    public ResultadoValidacionInquilino validarTokenInquilino(String token, String idInquilinoEsperado) {
        try {
            // Extraer inquilino del header primero
            JSONObject header = generator.getJWTHeader(token);
            String idInquilinoToken = header.getString("inquilino");
            
            if (!idInquilinoEsperado.equals(idInquilinoToken)) {
                return ResultadoValidacionInquilino.fallo("Inquilino no coincide");
            }
            
            String secretoInquilino = getSecretoInquilino(idInquilinoToken);
            if (!generator.isValidSignature(token, secretoInquilino)) {
                return ResultadoValidacionInquilino.fallo("Firma inválida");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return ResultadoValidacionInquilino.exito(payload);
            
        } catch (Exception e) {
            return ResultadoValidacionInquilino.fallo("Error de validación");
        }
    }
}
```

### Control de Acceso Basado en Permisos

```java
@Service
public class ServicioTokenBasadoPermisos {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String claveSecreta;
    
    public String crearTokenPermiso(Usuario usuario, Set<Permiso> permisos) {
        var mapaPermisos = ObjectLeafBuilder.builder();
        
        // Agrupar permisos por recurso
        Map<String, List<String>> permisosRecurso = permisos.stream()
            .collect(Collectors.groupingBy(
                Permiso::getRecurso,
                Collectors.mapping(Permiso::getAccion, Collectors.toList())
            ));
        
        permisosRecurso.forEach((recurso, acciones) -> {
            var arrayAcciones = ArrayStringLeafBuilder.builder();
            acciones.forEach(arrayAcciones::add);
            mapaPermisos.put(recurso, arrayAcciones.build());
        });
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", usuario.getId())
            .put("permisos", mapaPermisos.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        return generator.generateJWT(claveSecreta, header, payload);
    }
    
    public boolean tienePermiso(String token, String recurso, String accion) {
        if (!generator.isValidSignature(token, claveSecreta)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        JSONObject permisos = payload.optJSONObject("permisos");
        
        if (permisos == null || !permisos.has(recurso)) {
            return false;
        }
        
        JSONArray acciones = permisos.getJSONArray(recurso);
        for (int i = 0; i < acciones.length(); i++) {
            if (accion.equals(acciones.getString(i))) {
                return true;
            }
        }
        
        return false;
    }
}
```

## Ejemplos de Manejo de Errores

### Manejo Integral de Errores

```java
@Service
public class ServicioTokenRobusto {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultadoProcesamientoToken procesarToken(String token, String claveSecreta) {
        try {
            // Paso 1: Validación básica
            if (token == null || token.trim().isEmpty()) {
                return ResultadoProcesamientoToken.error(CodigoError.TOKEN_FALTANTE);
            }
            
            // Paso 2: Validación de formato
            if (!esFormatoJWTValido(token)) {
                return ResultadoProcesamientoToken.error(CodigoError.FORMATO_INVALIDO);
            }
            
            // Paso 3: Validación de firma
            if (!generator.isValidSignature(token, claveSecreta)) {
                return ResultadoProcesamientoToken.error(CodigoError.FIRMA_INVALIDA);
            }
            
            // Paso 4: Extracción y validación de claims
            JSONObject payload = generator.getJWTPayload(token);
            
            if (!payload.has("exp")) {
                return ResultadoProcesamientoToken.error(CodigoError.EXPIRACION_FALTANTE);
            }
            
            long expiracion = payload.getLong("exp");
            if (System.currentTimeMillis() > expiracion) {
                return ResultadoProcesamientoToken.error(CodigoError.TOKEN_EXPIRADO);
            }
            
            return ResultadoProcesamientoToken.exito(payload);
            
        } catch (IllegalArgumentException e) {
            return ResultadoProcesamientoToken.error(CodigoError.ENTRADA_INVALIDA, e.getMessage());
        } catch (JSONException e) {
            return ResultadoProcesamientoToken.error(CodigoError.ERROR_PARSEO_JSON, e.getMessage());
        } catch (Exception e) {
            return ResultadoProcesamientoToken.error(CodigoError.ERROR_INESPERADO, e.getMessage());
        }
    }
    
    private boolean esFormatoJWTValido(String token) {
        String[] partes = token.split("\\.");
        return partes.length == 3;
    }
}

public enum CodigoError {
    TOKEN_FALTANTE("El token está faltante"),
    FORMATO_INVALIDO("Formato JWT inválido"),
    FIRMA_INVALIDA("Firma de token inválida"),
    EXPIRACION_FALTANTE("Token sin expiración"),
    TOKEN_EXPIRADO("El token ha expirado"),
    ENTRADA_INVALIDA("Parámetros de entrada inválidos"),
    ERROR_PARSEO_JSON("Error al parsear JSON"),
    ERROR_INESPERADO("Error inesperado ocurrido");
    
    private final String mensaje;
    
    CodigoError(String mensaje) {
        this.mensaje = mensaje;
    }
    
    public String getMensaje() {
        return mensaje;
    }
}
```

## Ejemplos de Pruebas

### Pruebas Unitarias de Operaciones de Token

```java
@ExtendWith(MockitoExtension.class)
class PruebaServicioToken {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String claveSecretaPrueba = "clave-secreta-prueba-32-caracteres";
    
    @Test
    void deberiaCrearTokenValido() {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "usuario-prueba")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
        
        String token = generator.generateJWT(claveSecretaPrueba, header, payload);
        
        assertThat(token).isNotNull();
        assertThat(generator.isValidSignature(token, claveSecretaPrueba)).isTrue();
    }
    
    @Test
    void deberiaRechazarFirmaInvalida() {
        String tokenInvalido = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalido.firma";
        
        assertThat(generator.isValidSignature(tokenInvalido, claveSecretaPrueba)).isFalse();
    }
    
    @Test
    void deberiaExtraerPayloadCorrectamente() {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "usuario-prueba")
            .put("rol", "admin")
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .build();
        
        String token = generator.generateJWT(claveSecretaPrueba, header, payload);
        JSONObject payloadExtraido = generator.getJWTPayload(token);
        
        assertThat(payloadExtraido.getString("sub")).isEqualTo("usuario-prueba");
        assertThat(payloadExtraido.getString("rol")).isEqualTo("admin");
    }
}
```
