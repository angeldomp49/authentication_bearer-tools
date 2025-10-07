```markdown
Status: draft
Owner: @angeldomp49
Source Model: Claude Opus 4.1 (Ask Mode)
Last Sync: 2024-11-14T10:30:00Z
```

# Especificación de Pruebas de Integración con Concordion

## Información del Proyecto

- **Nombre del Proyecto**: Bearer Authentication Tools
- **Versión**: 1.4.3
- **Lenguaje**: Java 17
- **Build Tool**: Gradle

## Alcance de la Implementación

### 1. Configuración de Dependencias

#### Gradle Configuration (`lib/build.gradle.kts`)

Agregar las siguientes dependencias de prueba:

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

### 2. Matriz de Pruebas

#### Componentes Identificados

Basado en los archivos de prueba existentes y la estructura del proyecto:

| Componente                    | Casos de Prueba                        | Prioridad | Tipo          |
|-------------------------------|----------------------------------------|-----------|---------------|
| **TextCipher (AES)**          |                                        | Alta      | Integración   |
| - Cifrado básico              | Texto plano → Texto cifrado            | Alta      | Funcional     |
| - Descifrado básico           | Texto cifrado → Texto plano            | Alta      | Funcional     |
| - Claves inválidas            | Null, vacío, formato incorrecto        | Alta      | Error         |
| - Textos especiales           | UTF-8, caracteres especiales, emojis   | Media     | Edge case     |
| - Textos largos               | >1MB, >10MB                            | Media     | Performance   |
| - Preservación de formato     | Base64, hex encoding                   | Media     | Funcional     |
| **Argon2 Password Hashing**   |                                        | Alta      | Integración   |
| - Hash básico                 | Password → Hash seguro                 | Alta      | Funcional     |
| - Verificación de password    | Hash vs password correcto/incorrecto   | Alta      | Funcional     |
| - Parámetros de configuración | Memory, iterations, parallelism        | Alta      | Configuración |
| - Passwords especiales        | UTF-8, caracteres especiales, espacios | Media     | Edge case     |
| - Passwords largos            | >100 chars, >1000 chars                | Media     | Performance   |
| - Salt generation             | Unicidad y aleatoriedad                | Alta      | Seguridad     |
| - Timing attacks resistance   | Tiempo constante de verificación       | Alta      | Seguridad     |
| **Bearer Token Generation**   |                                        | Alta      | Integración   |
| - Generación de token         | Creación con payload válido            | Alta      | Funcional     |
| - Validación de token         | Token válido/inválido/expirado         | Alta      | Funcional     |
| - Firma de token              | Verificación de integridad             | Alta      | Seguridad     |
| - Claims personalizados       | Agregar/leer claims específicos        | Media     | Funcional     |
| - Refresh tokens              | Renovación de tokens expirados         | Media     | Funcional     |
| - Token revocation            | Invalidación de tokens activos         | Media     | Seguridad     |
| **Integration Tests**         |                                        | Alta      | End-to-End    |
| - Bearer + Argon2             | Login flow completo                    | Alta      | Integración   |
| - Bearer + AES                | Payload cifrado en tokens              | Alta      | Integración   |
| - Argon2 + AES                | Password cifrado antes de hash         | Media     | Integración   |

### 3. Estructura de Archivos de Prueba

```
lib/src/test/
├── java/
│   └── org/makechtec/bearer_authentication/tools/
│       ├── concordion/
│       │   ├── CryptographyTestFixture.java
│       │   ├── Argon2TestFixture.java
│       │   ├── BearerTokenTestFixture.java
│       │   └── IntegrationTestFixture.java
│       └── support/
│           ├── TestDataGenerator.java
│           ├── AssertionHelper.java
│           ├── CryptoTestHelper.java
│           └── PasswordTestHelper.java
└── resources/
    └── org/makechtec/bearer_authentication/tools/
        └── concordion/
            ├── Cryptography.html
            ├── Argon2.html
            ├── BearerToken.html
            ├── Integration.html
            └── css/
                └── custom-style.css
```

### 4. Implementación de Pruebas Concordion

#### Ejemplo de Especificación HTML (`Argon2.html`)

```html
<!DOCTYPE html>
<html xmlns:concordion="http://www.concordion.org/2007/concordion">
<head>
    <title>Argon2 Password Hashing Tests</title>
    <link href="css/custom-style.css" rel="stylesheet"/>
</head>
<body>
    <h1>Argon2 Password Hashing Specification</h1>
    
    <h2>Basic Hashing</h2>
    <div concordion:example="basicHashing">
        <p>Given a password <span concordion:set="#password">MySecurePassword123!</span></p>
        <p>When hashing the password</p>
        <p>Then the hash <span concordion:assert-not-equals="#password" 
           concordion:execute="#hash = hashPassword(#password)">should be different from password</span></p>
        <p>And verification with correct password returns <span concordion:assert-equals="true"
           concordion:execute="#verified = verifyPassword(#password, #hash)">true</span></p>
        <p>And verification with wrong password returns <span concordion:assert-equals="false"
           concordion:execute="#wrongVerified = verifyPassword('WrongPassword', #hash)">false</span></p>
    </div>
    
    <h2>Security Properties</h2>
    <table concordion:execute="#result = testPasswordHashing(#password, #testCase)">
        <tr>
            <th concordion:set="#password">Password</th>
            <th concordion:set="#testCase">Test Case</th>
            <th concordion:assert-equals="#result">Expected Result</th>
        </tr>
        <tr>
            <td>SimplePass</td>
            <td>UNIQUE_SALT</td>
            <td>PASS</td>
        </tr>
        <tr>
            <td>UTF8: パスワード</td>
            <td>UTF8_SUPPORT</td>
            <td>PASS</td>
        </tr>
        <tr>
            <td>LongPassword...1000chars</td>
            <td>LONG_PASSWORD</td>
            <td>PASS</td>
        </tr>
        <tr>
            <td>Special: !@#$%^&*()</td>
            <td>SPECIAL_CHARS</td>
            <td>PASS</td>
        </tr>
    </table>
</body>
</html>
```

### 5. Fixture Java Implementation

#### Argon2TestFixture.java

```java
package org.makechtec.bearer_authentication.tools.concordion;

import org.concordion.integration.junit.jupiter.ConcordionTestFactory;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ConcordionTestFactory.class)
public class Argon2TestFixture {
    
    private final Argon2PasswordHasher hasher;
    
    public Argon2TestFixture() {
        this.hasher = new Argon2PasswordHasher();
    }
    
    public String hashPassword(String password) {
        return hasher.hash(password);
    }
    
    public boolean verifyPassword(String password, String hash) {
        return hasher.verify(password, hash);
    }
    
    public String testPasswordHashing(String password, String testCase) {
        switch (testCase) {
            case "UNIQUE_SALT":
                String hash1 = hasher.hash(password);
                String hash2 = hasher.hash(password);
                return !hash1.equals(hash2) ? "PASS" : "FAIL";
            
            case "UTF8_SUPPORT":
            case "SPECIAL_CHARS":
            case "LONG_PASSWORD":
                try {
                    String hash = hasher.hash(password);
                    return hasher.verify(password, hash) ? "PASS" : "FAIL";
                } catch (Exception e) {
                    return "ERROR";
                }
            
            default:
                return "UNKNOWN";
        }
    }
}
```

### 6. Métricas de Cobertura Esperadas

- **Cobertura de código objetivo**: ≥85%
- **Cobertura de ramas**: ≥75%
- **Cobertura de casos críticos**: 100%
- **Cobertura de funciones criptográficas**: 100%

### 7. Validaciones Requeridas

Cada prueba debe incluir:
1. Aserciones de estado inicial
2. Validación de resultado esperado
3. Verificación de efectos secundarios (si aplica)
4. Validación de excepciones para casos de error
5. Validación de propiedades de seguridad (para componentes criptográficos)

### 8. Criterios de Éxito

- ✅ Todas las pruebas Concordion pasan exitosamente
- ✅ Reportes HTML generados en `build/reports/spec`
- ✅ Reporte JaCoCo generado con cobertura ≥85%
- ✅ Sin uso de reflexión en el código de prueba
- ✅ Mínimo uso de mocks (solo para dependencias externas)
- ✅ Código siguiendo principios SOLID y Clean Code
- ✅ Java 17 utilizado exclusivamente
- ✅ Todas las funciones criptográficas validadas contra vectores de prueba conocidos

### 9. Notas de Implementación

- No usar Kotlin para código fuente, solo para archivos de configuración Gradle
- Evitar comentarios en el código, hacer que sea autodocumentado
- Usar guard clauses para reducir anidamiento
- Usar `Objects.isNull()` y `Objects.nonNull()` para verificaciones null
- Preferir composición sobre herencia
- Documentar nuevas funcionalidades en carpeta `docs/`
- Asegurar que las pruebas de timing attacks usan mediciones estadísticas
