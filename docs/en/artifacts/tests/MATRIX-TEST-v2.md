# Matrix Test v2 #

```markdown
Status: draft
Owner: @angeldomp49
Source Model: Claude Opus 4.1 (Ask Mode)
Last Sync: 2024-11-14T12:45:00Z
```

# Especificación de Pruebas de Integración con Concordion - Actualizada

## Información del Proyecto

- **Nombre del Proyecto**: Bearer Authentication Tools
- **Versión**: 1.4.3
- **Lenguaje**: Java 17
- **Build Tool**: Gradle

## Alcance de la Implementación

### 1. Configuración de Dependencias

#### Gradle Configuration (`lib/build.gradle.kts`)

```kotlin
dependencies {
    testImplementation("org.concordion:concordion:4.1.0")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.1")
    testImplementation("org.mockito:mockito-core:5.7.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.7.0")
    testImplementation("org.assertj:assertj-core:3.24.2")
    testImplementation("org.jacoco:org.jacoco.core:0.8.11")
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
    systemProperty("concordion.output.dir", "$buildDir/reports/spec")
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        html.outputLocation.set(layout.buildDirectory.dir("reports/jacoco"))
    }
}

jacoco {
    toolVersion = "0.8.11"
}
```

### 2. Matriz de Pruebas Actualizada

#### Componentes Criptográficos Principales

| Componente                     | Casos de Prueba                             | Validaciones Requeridas                                                                                                  | Prioridad | Tipo          |
|--------------------------------|---------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|-----------|---------------|
| **TextCipher (AES-256-GCM)**   |                                             |                                                                                                                          | Alta      | Integración   |
| - Cifrado/Descifrado simétrico | Texto plano ↔ Texto cifrado                 | - Integridad del texto descifrado<br>- Unicidad del IV<br>- Longitud de clave correcta (256 bits)                        | Alta      | Funcional     |
| - Validación de entrada        | Null, vacío, clave inválida                 | - IllegalArgumentException esperada<br>- Mensaje de error descriptivo                                                    | Alta      | Validación    |
| - Datos binarios               | Archivos, streams, byte arrays              | - Preservación de bytes<br>- No corrupción de datos                                                                      | Alta      | Funcional     |
| - Autenticación GCM            | Tag de autenticación                        | - Verificación de integridad<br>- Detección de manipulación                                                              | Alta      | Seguridad     |
| - Vectores de inicialización   | IV único por operación                      | - No reutilización de IV<br>- Aleatoriedad del IV                                                                        | Alta      | Seguridad     |
| **Argon2id Password Hashing**  |                                             |                                                                                                                          | Alta      | Integración   |
| - Hash generation              | Password → Hash                             | - Format: $argon2id$v=19$...<br>- Salt incluido en hash<br>- Longitud consistente                                        | Alta      | Funcional     |
| - Verificación timing-safe     | Hash vs password                            | - Tiempo constante<br>- No vulnerable a timing attacks                                                                   | Alta      | Seguridad     |
| - Parámetros configurables     | Memory: 64MB, Iterations: 3, Parallelism: 1 | - Valores dentro de rangos seguros<br>- Configuración persistente                                                        | Alta      | Configuración |
| - Salt generation              | 16 bytes aleatorios                         | - Entropía suficiente<br>- No predecible<br>- Único por hash                                                             | Alta      | Seguridad     |
| - Resistencia a ataques        | Rainbow tables, dictionary                  | - No reversible<br>- Costo computacional alto                                                                            | Alta      | Seguridad     |
| **JWT Bearer Token**           |                                             |                                                                                                                          | Alta      | Integración   |
| - Generación de token          | Claims → JWT                                | - Estructura válida (header.payload.signature)<br>- Algoritmo HS256/RS256<br>- Claims estándar (iss, sub, aud, exp, iat) | Alta      | Funcional     |
| - Validación de firma          | JWT → Verificación                          | - Detección de alteración<br>- Clave correcta requerida                                                                  | Alta      | Seguridad     |
| - Expiración de token          | exp claim                                   | - Token rechazado post-expiración<br>- Grace period configurable                                                         | Alta      | Funcional     |
| - Claims personalizados        | Custom data                                 | - Serialización correcta<br>- Tipos de datos soportados                                                                  | Media     | Funcional     |
| - Rotación de claves           | Key management                              | - Soporte múltiples claves<br>- Transición suave                                                                         | Media     | Operacional   |
| **Key Derivation (PBKDF2)**    |                                             |                                                                                                                          | Media     | Integración   |
| - Derivación de clave          | Password + Salt → Key                       | - Longitud de clave configurable<br>- Iteraciones mínimas: 100,000                                                       | Media     | Funcional     |
| - Compatibilidad               | HMAC-SHA256                                 | - Vectores de prueba NIST<br>- Interoperabilidad                                                                         | Media     | Estándar      |
| **Secure Random Generation**   |                                             |                                                                                                                          | Alta      | Unitaria      |
| - Generación de bytes          | SecureRandom                                | - Distribución uniforme<br>- No predecible                                                                               | Alta      | Seguridad     |
| - Generación de tokens         | URL-safe tokens                             | - Base64 URL encoding<br>- Longitud configurable                                                                         | Alta      | Funcional     |

### 3. Casos de Prueba de Validación

#### Validaciones de Entrada/Salida

| Validación         | Componente | Entrada             | Resultado Esperado             | Aserción                       |
|--------------------|------------|---------------------|--------------------------------|--------------------------------|
| Null safety        | TextCipher | null text           | IllegalArgumentException       | Message: "Text cannot be null" |
| Empty input        | TextCipher | ""                  | Cifrado válido de string vacío | Descifrado == ""               |
| Key validation     | TextCipher | key.length != 32    | IllegalArgumentException       | Message: "Invalid key length"  |
| Password strength  | Argon2     | password.length < 8 | Warning log                    | Continúa pero advierte         |
| Token format       | Bearer     | Malformed JWT       | InvalidTokenException          | Parsing fails gracefully       |
| Expired token      | Bearer     | exp < now           | TokenExpiredException          | Clear expiration message       |
| Algorithm mismatch | Bearer     | HS256 vs RS256      | InvalidAlgorithmException      | Security validation            |

### 4. Pruebas de Integración Entre Componentes

| Escenario                     | Componentes         | Flujo                                                                               | Validaciones                                                                                               |
|-------------------------------|---------------------|-------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| Secure credential storage     | Argon2 + TextCipher | 1. Hash password con Argon2<br>2. Cifrar hash con AES<br>3. Almacenar cifrado       | - Hash no reversible<br>- Cifrado adicional de hash<br>- Doble protección                                  |
| Token payload encryption      | Bearer + TextCipher | 1. Crear claims<br>2. Cifrar claims sensibles<br>3. Generar JWT con payload cifrado | - Claims sensibles protegidos<br>- Token válido con payload cifrado<br>- Descifrado correcto en validación |
| Key derivation for encryption | PBKDF2 + TextCipher | 1. Derivar clave de password<br>2. Usar clave para AES<br>3. Cifrar/Descifrar datos | - Clave derivada correctamente<br>- Compatible con AES-256<br>- Reproducible con mismos parámetros         |

### 5. Estructura de Archivos de Prueba Actualizada

```
lib/src/test/
├── java/
│   └── org/makechtec/bearer_authentication/tools/
│       ├── concordion/
│       │   ├── cipher/
│       │   │   ├── TextCipherFixture.java
│       │   │   ├── KeyValidationFixture.java
│       │   │   └── GCMAuthenticationFixture.java
│       │   ├── hashing/
│       │   │   ├── Argon2Fixture.java
│       │   │   ├── SaltGenerationFixture.java
│       │   │   └── TimingAttackFixture.java
│       │   ├── token/
│       │   │   ├── BearerTokenFixture.java
│       │   │   ├── ClaimsValidationFixture.java
│       │   │   └── TokenExpirationFixture.java
│       │   └── integration/
│       │       ├── CryptoIntegrationFixture.java
│       │       └── ValidationIntegrationFixture.java
│       └── support/
│           ├── TestVectors.java
│           ├── CryptoAssertions.java
│           ├── TimingMeasurement.java
│           └── RandomDataGenerator.java
└── resources/
    └── org/makechtec/bearer_authentication/tools/
        └── concordion/
            ├── cipher/
            │   ├── TextCipher.html
            │   ├── KeyValidation.html
            │   └── GCMAuthentication.html
            ├── hashing/
            │   ├── Argon2.html
            │   ├── SaltGeneration.html
            │   └── TimingAttack.html
            ├── token/
            │   ├── BearerToken.html
            │   ├── ClaimsValidation.html
            │   └── TokenExpiration.html
            ├── integration/
            │   ├── CryptoIntegration.html
            │   └── ValidationIntegration.html
            └── css/
                └── concordion-custom.css
```

### 6. Vectores de Prueba Criptográficos

| Algoritmo   | Vector | Entrada                                                    | Salida Esperada | Fuente          |
|-------------|--------|------------------------------------------------------------|-----------------|-----------------|
| AES-256-GCM | TV1    | Key: 0x000...000<br>Plaintext: "Test"                      | Conocido        | NIST SP 800-38D |
| Argon2id    | TV1    | Password: "password"<br>Salt: 0x000...000                  | $argon2id$...   | RFC 9106        |
| HMAC-SHA256 | TV1    | Key: "key"<br>Message: "message"                           | 0x6e9ef29b...   | RFC 4231        |
| PBKDF2      | TV1    | Password: "password"<br>Salt: "salt"<br>Iterations: 100000 | Conocido        | RFC 8018        |

### 7. Métricas de Cobertura Objetivo

- **Cobertura total**: ≥85%
- **Cobertura de ramas**: ≥80%
- **Cobertura de validaciones**: 100%
- **Cobertura de manejo de errores**: 100%
- **Cobertura de algoritmos criptográficos**: 100%

### 8. Validaciones Mínimas por Prueba

1. **Pre-condición**: Estado inicial válido
2. **Ejecución**: Operación sin excepciones inesperadas
3. **Post-condición**: Estado final esperado
4. **Invariantes**: Propiedades que no cambian
5. **Seguridad**: No exposición de información sensible

### 9. Criterios de Aceptación

- ✅ Concordion reporta 100% de pruebas pasadas
- ✅ JaCoCo muestra ≥85% cobertura de código
- ✅ Reportes HTML generados en `build/reports/spec`
- ✅ Sin warnings de seguridad en análisis estático
- ✅ Tiempo de ejecución total < 30 segundos
- ✅ Sin dependencias de red externa
- ✅ Reproducible en cualquier entorno

### 10. Exclusiones de Pruebas

No se crearán pruebas para:
- Lógica interna de bibliotecas externas
- Código de configuración de build
- Métodos getter/setter simples sin lógica
- Constructores vacíos o triviales
- Código de prueba probando otro código de prueba
