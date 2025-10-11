# Guide de Validation de Jetons

Ce guide couvre la validation complète de jetons JWT en utilisant la bibliothèque Bearer Authentication Tools.

## Validation Basique de Jetons

### Vérification de Signature

La méthode principale de validation vérifie si la signature d'un jeton est valide :

```java
JWTTokenGenerator generator = new JWTTokenGenerator();
boolean estValide = generator.isValidSignature(token, cleSecrete);

if (estValide) {
    // La signature du jeton est valide - procéder à l'extraction des revendications
} else {
    // Signature invalide - rejeter le jeton
}
```

### Extraction des Revendications

Après la validation de signature, extraire les revendications du jeton :

```java
// Extraire les revendications de la charge utile
JSONObject payload = generator.getJWTPayload(token);
String sujet = payload.getString("sub");
long expiration = payload.getLong("exp");

// Extraire les informations de l'en-tête
JSONObject header = generator.getJWTHeader(token);
String algorithme = header.getString("alg");
String typeJeton = header.getString("typ");
```

## Validation Complète

### Processus Complet de Validation de Jeton

```java
public ResultatValidationJeton validerJeton(String token, String cleSecrete) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    try {
        // Étape 1 : Valider la signature
        if (!generator.isValidSignature(token, cleSecrete)) {
            return ResultatValidationJeton.invalide("Signature invalide");
        }
        
        // Étape 2 : Extraire et valider les revendications
        JSONObject payload = generator.getJWTPayload(token);
        
        // Étape 3 : Vérifier l'expiration
        if (payload.has("exp")) {
            long expiration = payload.getLong("exp");
            if (System.currentTimeMillis() > expiration) {
                return ResultatValidationJeton.invalide("Jeton expiré");
            }
        }
        
        // Étape 4 : Vérifier le temps pas-avant
        if (payload.has("nbf")) {
            long pasAvant = payload.getLong("nbf");
            if (System.currentTimeMillis() < pasAvant) {
                return ResultatValidationJeton.invalide("Jeton pas encore valide");
            }
        }
        
        // Étape 5 : Valider les revendications requises
        if (!payload.has("sub")) {
            return ResultatValidationJeton.invalide("Revendication de sujet manquante");
        }
        
        return ResultatValidationJeton.valide(payload);
        
    } catch (Exception e) {
        return ResultatValidationJeton.invalide("Erreur d'analyse de jeton : " + e.getMessage());
    }
}
```

### Validation de Jeton de Session

Pour les jetons basés sur les sessions créés avec `JWTTokenHandler` :

```java
JWTTokenHandler handler = new JWTTokenHandler();
boolean estSessionValide = handler.isValidSignature(token, cleSecrete);

if (estSessionValide) {
    JSONObject payload = new JWTTokenGenerator().getJWTPayload(token);
    
    long idUtilisateur = payload.getLong("uid");
    boolean estFermee = payload.getBoolean("isClosed");
    JSONArray permissions = payload.getJSONArray("permissions");
    
    if (estFermee) {
        // Session fermée - rejeter le jeton
        return false;
    }
}
```

## Validation des Revendications

### Validation des Revendications Standard

```java
public class ValidateurRevendications {
    
    public boolean validerRevendicationsStandard(JSONObject payload) {
        // Valider l'émetteur
        if (payload.has("iss")) {
            String emetteur = payload.getString("iss");
            if (!estEmetteurValide(emetteur)) {
                return false;
            }
        }
        
        // Valider l'audience
        if (payload.has("aud")) {
            String audience = payload.getString("aud");
            if (!estAudienceValide(audience)) {
                return false;
            }
        }
        
        // Valider le sujet
        if (payload.has("sub")) {
            String sujet = payload.getString("sub");
            if (sujet.isEmpty()) {
                return false;
            }
        }
        
        return true;
    }
    
    private boolean estEmetteurValide(String emetteur) {
        return "emetteur-de-votre-app".equals(emetteur);
    }
    
    private boolean estAudienceValide(String audience) {
        return "audience-de-votre-app".equals(audience);
    }
}
```

### Validation des Revendications Personnalisées

```java
public boolean validerRevendicationsPersonnalisees(JSONObject payload, Utilisateur utilisateurDemandeur) {
    // Valider que l'ID utilisateur correspond
    if (payload.has("idUtilisateur")) {
        String idUtilisateurJeton = payload.getString("idUtilisateur");
        if (!idUtilisateurJeton.equals(utilisateurDemandeur.getId())) {
            return false;
        }
    }
    
    // Valider les permissions de rôle
    if (payload.has("role")) {
        String role = payload.getString("role");
        if (!utilisateurDemandeur.aRole(role)) {
            return false;
        }
    }
    
    // Valider les permissions spécifiques
    if (payload.has("permissions")) {
        JSONArray permissions = payload.getJSONArray("permissions");
        for (int i = 0; i < permissions.length(); i++) {
            String permission = permissions.getString(i);
            if (!utilisateurDemandeur.aPermission(permission)) {
                return false;
            }
        }
    }
    
    return true;
}
```

## Vérification d'Expiration

### Validation Basée sur le Temps

```java
public class ValidateurExpiration {
    
    public ValidationTempsJeton validerTempsJeton(JSONObject payload) {
        long tempsActuel = System.currentTimeMillis();
        
        // Vérifier l'expiration
        if (payload.has("exp")) {
            long expiration = payload.getLong("exp");
            if (tempsActuel > expiration) {
                return ValidationTempsJeton.expire();
            }
        }
        
        // Vérifier pas-avant
        if (payload.has("nbf")) {
            long pasAvant = payload.getLong("nbf");
            if (tempsActuel < pasAvant) {
                return ValidationTempsJeton.pasEncoreValide();
            }
        }
        
        // Vérifier émis-à pour décalage d'horloge
        if (payload.has("iat")) {
            long emisA = payload.getLong("iat");
            long toleranceDecalage = 300000; // 5 minutes
            
            if (tempsActuel < (emisA - toleranceDecalage)) {
                return ValidationTempsJeton.decalageHorloge();
            }
        }
        
        return ValidationTempsJeton.valide();
    }
}
```

### Validation avec Période de Grâce

```java
public boolean estJetonValideAvecPeriodeGrace(String token, String cleSecrete, long periodeGraceMs) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, cleSecrete)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    if (payload.has("exp")) {
        long expiration = payload.getLong("exp");
        long tempsActuel = System.currentTimeMillis();
        
        // Permettre période de grâce après expiration
        return tempsActuel <= (expiration + periodeGraceMs);
    }
    
    return true;
}
```

## Gestion des Erreurs

### Gestion des Exceptions de Validation

```java
public class ValidateurJeton {
    
    public ResultatValidation validerJetonSecurise(String token, String cleSecrete) {
        try {
            JWTTokenGenerator generator = new JWTTokenGenerator();
            
            boolean estValide = generator.isValidSignature(token, cleSecrete);
            if (!estValide) {
                return ResultatValidation.echec("SIGNATURE_INVALIDE");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return ResultatValidation.succes(payload);
            
        } catch (IllegalArgumentException e) {
            return ResultatValidation.echec("FORMAT_JETON_INVALIDE");
        } catch (Exception e) {
            return ResultatValidation.echec("ERREUR_VALIDATION");
        }
    }
}
```

### Erreurs Courantes de Validation

```java
public enum ErreurValidation {
    SIGNATURE_INVALIDE("La signature du jeton est invalide"),
    JETON_EXPIRE("Le jeton a expiré"),
    JETON_PAS_ENCORE_VALIDE("Le jeton n'est pas encore valide"), 
    REVENDICATIONS_MANQUANTES("Les revendications requises sont manquantes"),
    FORMAT_INVALIDE("Le format du jeton est invalide"),
    ERREUR_ANALYSE("Erreur lors de l'analyse du jeton");
    
    private final String message;
    
    ErreurValidation(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
}
```

## Scénarios Avancés de Validation

### Validation Multi-Clés

```java
public boolean validerAvecMultiplesCles(String token, List<String> clesSecretes) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return clesSecretes.stream()
        .anyMatch(cle -> {
            try {
                return generator.isValidSignature(token, cle);
            } catch (Exception e) {
                return false;
            }
        });
}
```

### Validation Conditionnelle

```java
public boolean validerConditionnellement(String token, String cleSecrete, ContexteValidation contexte) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    if (!generator.isValidSignature(token, cleSecrete)) {
        return false;
    }
    
    JSONObject payload = generator.getJWTPayload(token);
    
    // Appliquer des validations spécifiques au contexte
    if (contexte.requireRoleAdmin()) {
        return payload.has("role") && "admin".equals(payload.getString("role"));
    }
    
    if (contexte.requirePermissionSpecifique()) {
        JSONArray permissions = payload.optJSONArray("permissions");
        return permissions != null && 
               contientPermission(permissions, contexte.getPermissionRequise());
    }
    
    return true;
}
```

## Optimisation des Performances

### Cache de Validation

```java
public class ValidateurJetonEnCache {
    
    private final Map<String, ResultatValidation> cacheValidation = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultatValidation validerAvecCache(String token, String cleSecrete) {
        String cleCache = genererCleCache(token, cleSecrete);
        
        return cacheValidation.computeIfAbsent(cleCache, cle -> {
            boolean estValide = generator.isValidSignature(token, cleSecrete);
            return estValide ? ResultatValidation.valide() : ResultatValidation.invalide();
        });
    }
    
    private String genererCleCache(String token, String cleSecrete) {
        return token.hashCode() + ":" + cleSecrete.hashCode();
    }
}
```

### Validation par Lots

```java
public List<ResultatValidation> validerJetons(List<String> jetons, String cleSecrete) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    return jetons.parallelStream()
        .map(jeton -> {
            try {
                boolean estValide = generator.isValidSignature(jeton, cleSecrete);
                return ResultatValidation.de(jeton, estValide);
            } catch (Exception e) {
                return ResultatValidation.erreur(jeton, e.getMessage());
            }
        })
        .collect(Collectors.toList());
}
```
