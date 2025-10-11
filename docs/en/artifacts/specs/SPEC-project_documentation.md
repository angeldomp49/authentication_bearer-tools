Basándome en la estructura del proyecto y los tests existentes, aquí está la especificación detallada para la documentación:

```markdown
Status: draft
Owner: @angeldomp49
Source Model: Claude Opus 4.1 (Ask Mode)
Last Sync: 2024-12-28 10:00:00
```

# Project Documentation Specification

## Project Information

- **Project Name**: Bearer Authentication Tools
- **Purpose**: Java library for facilitating JWT token generation and validation
- **Architecture**: Stateless helper functions without external dependencies

## Documentation Structure

```
docs/
├── en/
│   ├── README.md
│   ├── getting-started.md
│   ├── token-generation.md
│   ├── token-validation.md
│   ├── cryptography.md
│   └── examples.md
├── es/
│   ├── README.md
│   ├── inicio-rapido.md
│   ├── generacion-tokens.md
│   ├── validacion-tokens.md
│   ├── criptografia.md
│   └── ejemplos.md
└── fr/
├── README.md
├── demarrage-rapide.md
├── generation-jetons.md
├── validation-jetons.md
├── cryptographie.md
└── exemples.md
```

## Documentation Content Requirements

### README.md (Main Documentation)

Each language version must include:

1. **Project Overview**
   - Brief description of Bearer Authentication Tools
   - Key features and benefits
   - No external dependencies approach

2. **Installation**
   - Manual JAR inclusion instructions
   - Build from source instructions

3. **Quick Start**
   - Simple token generation example
   - Basic validation example

4. **Core Components**
   - JwtGenerator description
   - JwtValidator description
   - Supported algorithms (HS256, HS384, HS512, RS256, RS384, RS512)

### Token Generation Documentation

Must cover:
- Creating JWT tokens with different algorithms
- Setting standard claims (iss, sub, aud, exp, nbf, iat, jti)
- Adding custom claims
- Key management for HMAC and RSA algorithms
- Code examples for each scenario

### Token Validation Documentation

Must cover:
- Parsing and validating JWT tokens
- Signature verification
- Claims validation
- Expiration checking
- Error handling scenarios
- Code examples

### Cryptography Documentation

Must cover:
- Supported cryptographic algorithms
- Key generation best practices
- Security considerations
- Algorithm selection guide

### Examples Documentation

Must include:
- Complete working examples
- Common use cases
- Integration patterns
- Error handling examples

## Technical Requirements

1. **Code Examples**
   - All examples must be compilable Java 17 code
   - No external dependencies
   - Follow Clean Code principles
   - Self-explanatory without comments

2. **Translation Quality**
   - Professional technical translation
   - Consistent terminology across languages
   - Culturally appropriate examples

3. **Documentation Style**
   - Clear, concise technical writing
   - Progressive complexity (simple to advanced)
   - Practical focus with real-world scenarios

## Implementation Notes

- Focus on the token generation and validation features
- Exclude authentication-related tests from documentation
- Emphasize the stateless nature of the library
- Highlight the zero-dependency approach
- Include security best practices for each feature

## Deliverables

1. Complete documentation in three languages (EN, ES, FR)
2. All code examples tested and working
3. Consistent structure across all language versions
4. Clear navigation between related topics
