# Démarrage Rapide avec Bearer Authentication Tools

Ce guide vous aidera à commencer avec la bibliothèque Bearer Authentication Tools pour la gestion des jetons JWT en Java.

## Prérequis

- Java 17 ou supérieur
- Compréhension de base des concepts JWT
- Familiarité avec les structures JSON

## Étapes d'Installation

### Étape 1 : Construire la Bibliothèque

Clonez ou téléchargez le projet et construisez-le :

```bash
cd bearer_authentication/tools
./gradlew build
```

### Étape 2 : Inclure dans Votre Projet

Ajoutez le JAR généré au classpath de votre projet :
```
lib/build/libs/lib-1.4.3.jar
```

### Étape 3 : Importer les Classes Requises

```java
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.json.JSONObject;
```

## Votre Premier Jeton JWT

### Créer un Jeton Simple

```java
public class ExempleJeton {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
            
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "utilisateur123")
            .put("nom", "Jean Dupont")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
            
        String cleSecrete = "ma-cle-super-secrete-32-caracteres";
        String token = generator.generateJWT(cleSecrete, header, payload);
        
        System.out.println("Jeton Généré : " + token);
    }
}
```

### Valider le Jeton

```java
public class ExempleValidation {
    
    public static void main(String[] args) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        String token = "votre.jeton.jwt";
        String cleSecrete = "ma-cle-super-secrete-32-caracteres";
        
        if (generator.isValidSignature(token, cleSecrete)) {
            JSONObject payload = generator.getJWTPayload(token);
            String sujet = payload.getString("sub");
            String nom = payload.getString("nom");
            long expiration = payload.getLong("exp");
            
            System.out.println("Jeton valide pour utilisateur : " + nom);
            System.out.println("Sujet : " + sujet);
            System.out.println("Expire à : " + new Date(expiration));
        } else {
            System.out.println("Signature de jeton invalide");
        }
    }
}
```

## Modèles Courants

### Jeton avec Vérification d'Expiration

```java
public boolean estJetonValideEtNonExpire(String token, String cleSecrete) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, cleSecrete)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    long expiration = payload.getLong("exp");
    
    return System.currentTimeMillis() < expiration;
}
```

### Gestion des Revendications Personnalisées

```java
public String creerJetonUtilisateur(String idUtilisateur, String role, List<String> permissions) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    var header = ObjectLeafBuilder.builder()
        .put("alg", "HS256")
        .put("typ", "JWT")
        .build();
        
    var tableauPermissions = ArrayStringLeafBuilder.builder();
    permissions.forEach(tableauPermissions::add);
    
    var payload = ObjectLeafBuilder.builder()
        .put("sub", idUtilisateur)
        .put("role", role)
        .put("permissions", tableauPermissions.build())
        .put("iat", System.currentTimeMillis())
        .put("exp", System.currentTimeMillis() + 3600000)
        .build();
        
    return generator.generateJWT("votre-cle-secrete", header, payload);
}
```

## Meilleures Pratiques

1. **Toujours Valider les Signatures** : Ne jamais faire confiance au contenu du jeton sans validation de signature
2. **Vérifier l'Expiration** : Toujours vérifier les dates d'expiration des jetons
3. **Clés Secrètes Sécurisées** : Utiliser des clés secrètes fortes, générées aléatoirement
4. **Gérer les Exceptions** : Envelopper les opérations de jetons dans une gestion appropriée des exceptions
5. **Journaliser les Événements de Sécurité** : Journaliser les validations échouées pour la surveillance de sécurité

## Prochaines Étapes

- Apprenez la [Génération de Jetons](generation-jetons.md) en détail
- Explorez les techniques de [Validation de Jetons](validation-jetons.md)
- Consultez les [Meilleures Pratiques de Sécurité](cryptographie.md)
- Voir plus d'[Exemples](exemples.md)
