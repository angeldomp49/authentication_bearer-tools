# Guide de Génération de Jetons

Ce guide couvre la génération complète de jetons JWT en utilisant la bibliothèque Bearer Authentication Tools.

## Génération Basique de Jetons

### Utilisation de JWTTokenGenerator

La classe `JWTTokenGenerator` fournit les fonctionnalités principales pour créer des jetons JWT :

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
String token = generator.generateJWT(cleSecrete, header, payload);
```

### Configuration de l'En-tête

Les en-têtes JWT standard doivent inclure l'algorithme et le type de jeton :

```java
var header = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Structure de la Charge Utile

#### Revendications Standard

```java
var payload = ObjectLeafBuilder.builder()
    .put("iss", "votre-emetteur")                   // Émetteur
    .put("sub", "identifiant-utilisateur")          // Sujet
    .put("aud", "votre-audience")                   // Audience
    .put("exp", timestampExpiration)                // Expiration
    .put("nbf", timestampPasAvant)                  // Pas Avant
    .put("iat", timestampEmission)                  // Émis À
    .put("jti", UUID.randomUUID().toString())       // ID JWT
    .build();
```

#### Revendications Personnalisées

```java
var payload = ObjectLeafBuilder.builder()
    .put("idUtilisateur", "12345")
    .put("role", "administrateur")
    .put("permissions", tableauPermissions)
    .put("departement", "ingenierie")
    .put("niveau", 5)
    .build();
```

## Génération de Jetons Basée sur les Sessions

### Utilisation de JWTTokenHandler

Pour la gestion des sessions, utilisez `JWTTokenHandler` avec des structures de session prédéfinies :

```java
JWTTokenHandler handler = new JWTTokenHandler();

SessionInformation session = new SessionInformation(
    idUtilisateur,
    dateExpiration,
    false,  // estFermee
    Arrays.asList("lecture", "ecriture", "admin")
);

String token = handler.createTokenForSession(session, cleSecrete);
```

### Structure SessionInformation

```java
public record SessionInformation(
    long idUtilisateur,
    Calendar dateExpiration,
    boolean estFermee,
    List<String> permissions
) {}
```

## Sélection d'Algorithme

### Algorithmes HMAC

La bibliothèque utilise HMAC-SHA512 par défaut pour la signature :

```java
// Algorithme par défaut (HMAC-SHA512)
var header = ObjectLeafBuilder.builder()
    .put("alg", "SHA256")  // Référence interne
    .put("typ", "jwt")
    .build();
```

## Gestion des Clés

### Exigences de Clé Secrète

```java
// Minimum 32 caractères requis
String cleSecrete = "votre-cle-secrete-doit-avoir-32-caracteres-minimum";

// Exemple de génération de clé sécurisée
String cleSecurisee = genererCleSecurisee(32);
```

### Meilleures Pratiques de Sécurité des Clés

1. **Longueur** : Minimum 32 caractères
2. **Aléatoire** : Utiliser une génération cryptographiquement sécurisée et aléatoire
3. **Stockage** : Stocker les clés de manière sécurisée (variables d'environnement, coffres de clés)
4. **Rotation** : Implémenter une rotation régulière des clés

## Génération Avancée de Jetons

### Jetons avec Charges Utiles Complexes

```java
public String creerJetonComplexe(Utilisateur utilisateur, List<Role> roles) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var tableauRoles = ArrayStringLeafBuilder.builder();
    roles.stream()
        .map(Role::getNom)
        .forEach(tableauRoles::add);
    
    var tableauPermissions = ArrayStringLeafBuilder.builder();
    roles.stream()
        .flatMap(role -> role.getPermissions().stream())
        .distinct()
        .forEach(tableauPermissions::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", utilisateur.getId())
        .put("email", utilisateur.getEmail())
        .put("nom", utilisateur.getNomComplet())
        .put("roles", tableauRoles.build())
        .put("permissions", tableauPermissions.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + Duration.ofHours(1).toMillis())
        .put("jti", UUID.randomUUID().toString())
        .build();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
    
    return generator.generateJWT(cleSecrete, header, payload);
}
```

### Génération Conditionnelle de Jetons

```java
public String creerJetonConditionnel(Utilisateur utilisateur, boolean inclurePermissions) {
    var constructeurPayload = ObjectLeafBuilder.builder()
        .put("sub", utilisateur.getId())
        .put("nom", utilisateur.getNom())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000);
    
    if (inclurePermissions) {
        var permissions = ArrayStringLeafBuilder.builder();
        utilisateur.getPermissions().forEach(permissions::add);
        constructeurPayload.put("permissions", permissions.build());
    }
    
    return generator.generateJWT(cleSecrete, header, constructeurPayload.build());
}
```

## Gestion des Erreurs

### Erreurs de Validation

La bibliothèque valide les entrées et lève `IllegalArgumentException` pour des données invalides :

```java
try {
    String token = generator.generateJWT(cleSecrete, header, payload);
} catch (IllegalArgumentException e) {
    // Gérer les erreurs de validation
    System.err.println("Échec de génération de jeton : " + e.getMessage());
}
```

### Problèmes Courants de Validation

1. **Clé Secrète Trop Courte** : Doit avoir au moins 32 caractères
2. **Valeurs Nulles** : Les en-têtes et charges utiles ne peuvent pas être nuls
3. **JSON Vide** : Les en-têtes et charges utiles doivent contenir du JSON valide
4. **Session Invalide** : Échecs de validation de session

## Considérations de Performance

### Optimisation de Génération de Jetons

```java
// Réutiliser les instances du générateur
private static final JWTTokenGenerator GENERATEUR = new JWTTokenGenerator();

// Pré-construire les en-têtes communs
private static final ObjectLeaf HEADER_STANDARD = ObjectLeafBuilder.builder()
    .put("alg", "HS256")
    .put("typ", "JWT")
    .build();
```

### Génération de Jetons par Lots

```java
public List<String> genererJetonsPourUtilisateurs(List<Utilisateur> utilisateurs, String cleSecrete) {
    return utilisateurs.stream()
        .map(utilisateur -> creerJetonPourUtilisateur(utilisateur, cleSecrete))
        .collect(Collectors.toList());
}
```

## Exemples d'Intégration

### Intégration d'Application Web

```java
@Service
public class ServiceJeton {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String cleSecrete;
    
    public String authentifierUtilisateur(String nomUtilisateur, String motDePasse) {
        Utilisateur utilisateur = serviceUtilisateur.authentifier(nomUtilisateur, motDePasse);
        
        if (utilisateur != null) {
            return creerJetonPourUtilisateur(utilisateur);
        }
        
        throw new ExceptionAuthentification("Identifiants invalides");
    }
    
    private String creerJetonPourUtilisateur(Utilisateur utilisateur) {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", utilisateur.getId())
            .put("nomUtilisateur", utilisateur.getNomUtilisateur())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(cleSecrete, HEADER_STANDARD, payload);
    }
}
```
