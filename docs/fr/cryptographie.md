# Guide de Cryptographie et Sécurité

Ce guide couvre les aspects cryptographiques et les considérations de sécurité de la bibliothèque Bearer Authentication Tools.

## Algorithmes Supportés

### Algorithmes HMAC

La bibliothèque utilise HMAC (Code d'Authentification de Message basé sur Hash) pour la signature des jetons :

#### HMAC-SHA512 (Par Défaut)
- **Implémentation Interne** : Utilise Hashing.hmacSha512() de Google Guava
- **Taille de Clé** : Minimum 32 caractères (256 bits recommandés)
- **Niveau de Sécurité** : Élevé
- **Performance** : Bonne

```java
// Algorithme par défaut utilisé par SignaturePrinter
SignaturePrinter signataire = new SignaturePrinter(cleSecrete);
String signature = signataire.sign(message);
```

#### Sélection d'Algorithme

La bibliothèque utilise en interne HMAC-SHA512 pour toutes les opérations de signature, fournissant une forte sécurité cryptographique :

```java
// Implémentation interne (de la classe SignaturePrinter)
public String sign(String message) {
    return Hashing.hmacSha512(cleSecrete.getBytes(StandardCharsets.UTF_8))
            .hashString(message, StandardCharsets.UTF_8)
            .toString();
}
```

## Gestion des Clés

### Exigences de Clé Secrète

#### Standards Minimaux de Sécurité
- **Longueur** : Minimum 32 caractères (256 bits recommandés)
- **Jeu de Caractères** : Utiliser l'ensemble complet de caractères ASCII pour une entropie maximale
- **Aléatoire** : Générer en utilisant des générateurs de nombres aléatoires cryptographiquement sécurisés

```java
// Exemple de génération de clé sécurisée
public String genererCleSecurisee(int longueur) {
    SecureRandom random = new SecureRandom();
    StringBuilder cle = new StringBuilder(longueur);
    String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    
    for (int i = 0; i < longueur; i++) {
        cle.append(charset.charAt(random.nextInt(charset.length())));
    }
    
    return cle.toString();
}
```

#### Meilleures Pratiques de Stockage de Clés

```java
// Stockage dans variable d'environnement
String cleSecrete = System.getenv("JWT_SECRET_KEY");

// Fichier de propriétés (chiffré)
Properties props = new Properties();
props.load(new FileInputStream("secure.properties"));
String cleSecrete = dechiffrer(props.getProperty("jwt.secret.encrypted"));

// Intégration avec service de gestion de clés
String cleSecrete = serviceGestionCles.getCle("jwt-signing-key");
```

### Rotation des Clés

Implémentez une rotation régulière des clés pour une sécurité renforcée :

```java
public class ServiceRotationCles {
    
    private final Map<String, String> clesActives = new ConcurrentHashMap<>();
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public String creerJetonAvecCleActuelle(ObjectLeaf header, ObjectLeaf payload) {
        String idCleActuelle = getIdCleActuelle();
        String cleSecrete = clesActives.get(idCleActuelle);
        
        // Ajouter ID de clé à l'en-tête
        var headerAvecIdCle = ObjectLeafBuilder.builder()
            .putAll(header.asMap())
            .put("kid", idCleActuelle)
            .build();
        
        return generator.generateJWT(cleSecrete, headerAvecIdCle, payload);
    }
    
    public boolean validerJetonAvecRotationCle(String token, String idCle) {
        String cleSecrete = clesActives.get(idCle);
        if (cleSecrete == null) {
            return false; // Clé non trouvée ou expirée
        }
        
        return generator.isValidSignature(token, cleSecrete);
    }
    
    public void effectuerRotationCle() {
        String nouvelIdCle = genererNouvelIdCle();
        String nouvelleCleSecrete = genererCleSecurisee(64);
        clesActives.put(nouvelIdCle, nouvelleCleSecrete);
        
        // Conserver les anciennes clés pour période de grâce
        programmerNettoyageCle(nouvelIdCle);
    }
}
```

## Considérations de Sécurité

### Sécurité des Jetons

#### Gestion d'Expiration
Définissez toujours des temps d'expiration appropriés :

```java
public long calculerTempsExpiration(TypeJeton typeJeton) {
    return switch (typeJeton) {
        case JETON_ACCES -> System.currentTimeMillis() + Duration.ofMinutes(15).toMillis();
        case JETON_RAFRAICHISSEMENT -> System.currentTimeMillis() + Duration.ofDays(30).toMillis();
        case JETON_SESSION -> System.currentTimeMillis() + Duration.ofHours(8).toMillis();
    };
}
```

#### Validation de Signature
Validez toujours les signatures avant de traiter le contenu du jeton :

```java
public ResultatTraitement traiterJeton(String token, String cleSecrete) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    
    // NE JAMAIS extraire la charge utile sans validation de signature
    if (!generator.isValidSignature(token, cleSecrete)) {
        throw new SecurityException("Signature de jeton invalide");
    }
    
    // Sûr de traiter la charge utile après validation
    JSONObject payload = generator.getJWTPayload(token);
    return traiterChargeUtileValidee(payload);
}
```

### Atténuation des Menaces

#### Attaques de Confusion d'Algorithme
Prévenir la substitution d'algorithme :

```java
public boolean validerAlgorithmeJeton(String token, String algorithmeAttendu) {
    JWTTokenGenerator generator = new JWTTokenGenerator();
    JSONObject header = generator.getJWTHeader(token);
    
    String algorithme = header.optString("alg", "");
    return algorithmeAttendu.equals(algorithme);
}
```

#### Attaques de Temporisation
Utiliser une comparaison à temps constant pour les opérations sensibles :

```java
public boolean egauxTempsConstant(String a, String b) {
    if (a.length() != b.length()) {
        return false;
    }
    
    int resultat = 0;
    for (int i = 0; i < a.length(); i++) {
        resultat |= a.charAt(i) ^ b.charAt(i);
    }
    
    return resultat == 0;
}
```

#### Attaques de Rejeu de Jeton
Implémenter des vérifications d'unicité de jeton :

```java
public class PreventionRejeuJeton {
    
    private final Set<String> jetonsUtilises = ConcurrentHashMap.newKeySet();
    
    public boolean estJetonUtilise(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (jti.isEmpty()) {
            return false; // Pas de revendication JTI
        }
        
        return !jetonsUtilises.add(jti); // Retourne true si déjà utilisé
    }
    
    public void marquerJetonCommeUtilise(String token) {
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        String jti = payload.optString("jti");
        if (!jti.isEmpty()) {
            jetonsUtilises.add(jti);
        }
    }
}
```

## Fonctionnalités Cryptographiques Avancées

### Utilitaires de Sécurité Supplémentaires

La bibliothèque inclut des utilitaires cryptographiques supplémentaires :

#### Hachage de Mots de Passe (Argon2)
```java
// Note : Disponible dans la bibliothèque mais focus sur la fonctionnalité JWT
PasswordHasher hasher = new PasswordHasherNative();
String motDePasseHache = hasher.hash("motDePasseUtilisateur", sel);
```

#### Chiffrement de Texte (AES)
```java
// Note : Disponible dans la bibliothèque mais focus sur la fonctionnalité JWT  
TextCipher cipher = new TextCipher();
String chiffre = cipher.encrypt("données sensibles", cle);
```

#### Génération de Jeton CSRF
```java
// Note : Disponible dans la bibliothèque mais focus sur la fonctionnalité JWT
CSRFTokenGenerator generateurCsrf = new CSRFTokenGenerator();
String jetonCsrf = generateurCsrf.generate();
```

### Gestion Sécurisée des Jetons

#### Gestion de la Mémoire
Effacer les données sensibles de la mémoire :

```java
public class GestionnaireJetonSecurise {
    
    public String traiterJetonSecurement(char[] charsJeton, char[] charsCleSecrete) {
        try {
            String token = new String(charsJeton);
            String cleSecrete = new String(charsCleSecrete);
            
            JWTTokenGenerator generator = new JWTTokenGenerator();
            boolean estValide = generator.isValidSignature(token, cleSecrete);
            
            return estValide ? "VALIDE" : "INVALIDE";
            
        } finally {
            // Effacer les données sensibles
            Arrays.fill(charsJeton, '\0');
            Arrays.fill(charsCleSecrete, '\0');
        }
    }
}
```

#### Transport Sécurisé
Assurer que les jetons sont transmis de manière sécurisée :

```java
public class TransportJetonSecurise {
    
    public void envoyerJetonSecurisee(String token, HttpServletResponse response) {
        // Utiliser des cookies sécurisés, HTTP uniquement
        Cookie cookieJeton = new Cookie("auth_token", token);
        cookieJeton.setHttpOnly(true);
        cookieJeton.setSecure(true);
        cookieJeton.setPath("/");
        cookieJeton.setMaxAge(3600);
        
        response.addCookie(cookieJeton);
    }
}
```

## Validation de Sécurité

### Validation d'Entrée
La bibliothèque fournit une validation complète des entrées :

```java
// Validation de clé secrète
SECRET_KEY_MIN_32_CHARS    // Assure la longueur minimale de clé
STRING_NOT_NULL           // Empêche les valeurs nulles
STRING_NOT_EMPTY          // Empêche les chaînes vides
JSON_NOT_EMPTY           // Valide le contenu JSON
```

### Validation Personnalisée
Implémenter des couches de validation supplémentaires :

```java
public class ValidateurJetonAmeliore {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultatValidation validerAmeliore(String token, String cleSecrete, ContexteSecurite contexte) {
        // Validation basique de signature
        if (!generator.isValidSignature(token, cleSecrete)) {
            return ResultatValidation.echec("SIGNATURE_INVALIDE");
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        
        // Vérifications de sécurité améliorées
        if (!validerAgeJeton(payload)) {
            return ResultatValidation.echec("JETON_TROP_ANCIEN");
        }
        
        if (!validerAdresseIP(payload, contexte.getIpClient())) {
            return ResultatValidation.echec("IP_NON_CORRESPONDANTE");
        }
        
        if (!validerUserAgent(payload, contexte.getUserAgent())) {
            return ResultatValidation.echec("USER_AGENT_NON_CORRESPONDANT");
        }
        
        return ResultatValidation.succes();
    }
}
```

## Équilibre Performance et Sécurité

### Opérations Sécurisées Optimisées
Équilibrer sécurité avec performance :

```java
public class ValidateurSecuriseOptimise {
    
    private final LoadingCache<String, Boolean> cacheSignature;
    
    public ValidateurSecuriseOptimise() {
        this.cacheSignature = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(Duration.ofMinutes(5))
            .build(this::validerSignatureSansCache);
    }
    
    private Boolean validerSignatureSansCache(String cleCachee) {
        String[] parties = cleCachee.split(":");
        String token = parties[0];
        String cleSecrete = parties[1];
        
        return new JWTTokenGenerator().isValidSignature(token, cleSecrete);
    }
}
```
