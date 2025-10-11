# Bearer Authentication Tools

Une bibliothèque Java légère pour la génération et validation de jetons JWT avec des utilitaires cryptographiques supplémentaires. Cette bibliothèque fournit des fonctions d'aide sans état pour la gestion sécurisée des jetons sans dépendances externes.

## Fonctionnalités

- **Génération de Jetons JWT** : Crée des jetons JWT sécurisés avec des en-têtes et charges utiles personnalisés
- **Validation de Jetons JWT** : Valide les signatures de jetons et extrait les revendications
- **Support d'Algorithmes Multiples** : HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
- **Zéro Dépendances** : Implémentation Java pure sans dépendances de frameworks externes
- **Conception Sans État** : Toutes les fonctions sont sans état pour une flexibilité maximale
- **Utilitaires de Sécurité** : Outils supplémentaires pour le hachage de mots de passe, chiffrement et protection CSRF

## Démarrage Rapide

### Génération Basique de Jetons

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

String token = generator.generateJWT("votre-cle-secrete-32-caracteres-minimum", header, payload);
```

### Validation Basique de Jetons

```java
JWTTokenGenerator generator = new JWTTokenGenerator();

boolean estValide = generator.isValidSignature(token, "votre-cle-secrete-32-caracteres-minimum");

if (estValide) {
    JSONObject payload = generator.getJWTPayload(token);
    JSONObject header = generator.getJWTHeader(token);
}
```

## Installation

### Inclusion Manuelle du JAR

1. Construisez le projet en utilisant Gradle :
   ```bash
   ./gradlew build
   ```

2. Incluez le fichier JAR généré dans le classpath de votre projet :
   ```
   lib/build/libs/lib-1.4.3.jar
   ```

### Construire depuis le Code Source

1. Clonez le dépôt
2. Naviguez vers le répertoire du projet
3. Exécutez la commande de construction :
   ```bash
   ./gradlew build
   ```

## Composants Principaux

### JWTTokenGenerator

La classe principale pour les opérations de jetons JWT :
- `generateJWT(secretKey, header, payload)` : Crée un nouveau jeton JWT
- `isValidSignature(token, secretKey)` : Valide la signature du jeton
- `getJWTPayload(token)` : Extrait la charge utile du jeton
- `getJWTHeader(token)` : Extrait l'en-tête du jeton

### JWTTokenHandler

Gestion de jetons de haut niveau pour l'authentification basée sur les sessions :
- `createTokenForSession(session, secretKey)` : Crée des jetons avec une structure de session prédéfinie
- `isValidSignature(token, secretKey)` : Valide les jetons de session

### Algorithmes Supportés

- **HMAC-SHA256** : Algorithme par défaut pour la signature des jetons
- **HMAC-SHA384** : Option de sécurité améliorée
- **HMAC-SHA512** : Option de sécurité maximale

## Considérations de Sécurité

1. **Exigences de Clé Secrète** : Minimum 32 caractères pour la sécurité
2. **Expiration des Jetons** : Définissez toujours des délais d'expiration pour les jetons
3. **Validation de Signature** : Validez les signatures avant de faire confiance au contenu du jeton
4. **Stockage Sécurisé** : Stockez les clés secrètes de manière sécurisée et effectuez une rotation régulière

## Documentation Supplémentaire

- [Guide de Démarrage](demarrage-rapide.md)
- [Génération de Jetons](generation-jetons.md)
- [Validation de Jetons](validation-jetons.md)
- [Cryptographie](cryptographie.md)
- [Exemples](exemples.md)

## Licence

Ce projet fait partie de la suite MakechTec Bearer Authentication Tools.
