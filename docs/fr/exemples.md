# Exemples et Cas d'Usage

Ce guide fournit des exemples pratiques et des cas d'usage courants pour la bibliothèque Bearer Authentication Tools.

## Exemples Basiques

### Flux d'Authentification Simple

```java
public class ExempleAuthentificationSimple {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String cleSecrete = "ma-cle-super-secrete-32-caracteres";
    
    public String authentifierUtilisateur(String nomUtilisateur, String motDePasse) {
        Utilisateur utilisateur = validerIdentifiants(nomUtilisateur, motDePasse);
        
        if (utilisateur == null) {
            throw new ExceptionAuthentification("Identifiants invalides");
        }
        
        return creerJetonPourUtilisateur(utilisateur);
    }
    
    private String creerJetonPourUtilisateur(Utilisateur utilisateur) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", utilisateur.getId())
            .put("nomUtilisateur", utilisateur.getNomUtilisateur())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .put("iat", System.currentTimeMillis())
            .build();
        
        return generator.generateJWT(cleSecrete, header, payload);
    }
    
    public boolean validerJeton(String token) {
        return generator.isValidSignature(token, cleSecrete);
    }
}
```

### Exemple de Gestion de Sessions

```java
public class ExempleGestionSessions {
    
    private final JWTTokenHandler handler = new JWTTokenHandler();
    private final String cleSecrete = "cle-secrete-session-32-caracteres";
    
    public String creerSessionUtilisateur(Utilisateur utilisateur, List<String> permissions) {
        Calendar dateExpiration = Calendar.getInstance();
        dateExpiration.add(Calendar.HOUR, 12);
        
        SessionInformation session = new SessionInformation(
            utilisateur.getId(),
            dateExpiration,
            false,
            permissions
        );
        
        return handler.createTokenForSession(session, cleSecrete);
    }
    
    public InfoSession validerEtExtraireSession(String token) {
        if (!handler.isValidSignature(token, cleSecrete)) {
            throw new ExceptionJetonInvalide("Jeton de session invalide");
        }
        
        JWTTokenGenerator generator = new JWTTokenGenerator();
        JSONObject payload = generator.getJWTPayload(token);
        
        return new InfoSession(
            payload.getLong("uid"),
            payload.getBoolean("isClosed"),
            extrairePermissions(payload.getJSONArray("permissions")),
            payload.getLong("exp")
        );
    }
}
```

## Intégration d'Applications Web

### Intégration Spring Boot

```java
@RestController
@RequestMapping("/api/auth")
public class ControleurAuth {
    
    private final ServiceJeton serviceJeton;
    
    @Autowired
    public ControleurAuth(ServiceJeton serviceJeton) {
        this.serviceJeton = serviceJeton;
    }
    
    @PostMapping("/connexion")
    public ResponseEntity<ReponseConnexion> connexion(@RequestBody DemandeConnexion demande) {
        try {
            String token = serviceJeton.authentifierUtilisateur(
                demande.getNomUtilisateur(), 
                demande.getMotDePasse()
            );
            
            return ResponseEntity.ok(new ReponseConnexion(token, "succès"));
        } catch (ExceptionAuthentification e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ReponseConnexion(null, "Identifiants invalides"));
        }
    }
    
    @PostMapping("/valider")
    public ResponseEntity<ReponseValidation> validerJeton(@RequestHeader("Authorization") String headerAuth) {
        String token = extraireJetonDuHeader(headerAuth);
        
        if (serviceJeton.estJetonValide(token)) {
            InfoUtilisateur infoUtilisateur = serviceJeton.getInfoUtilisateurDuJeton(token);
            return ResponseEntity.ok(new ReponseValidation(true, infoUtilisateur));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ReponseValidation(false, null));
        }
    }
}

@Service
public class ServiceJeton {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String cleSecrete;
    
    public String authentifierUtilisateur(String nomUtilisateur, String motDePasse) {
        Utilisateur utilisateur = depotUtilisateur.findByNomUtilisateurAndMotDePasse(nomUtilisateur, hacherMotDePasse(motDePasse));
        
        if (utilisateur == null) {
            throw new ExceptionAuthentification("Identifiants invalides");
        }
        
        return creerJeton(utilisateur);
    }
    
    public boolean estJetonValide(String token) {
        try {
            return generator.isValidSignature(token, cleSecrete) && !estJetonExpire(token);
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean estJetonExpire(String token) {
        JSONObject payload = generator.getJWTPayload(token);
        long expiration = payload.getLong("exp");
        return System.currentTimeMillis() > expiration;
    }
}
```

### Intégration Filtre Servlet

```java
@WebFilter("/*")
public class FiltreAuthentificationJWT implements Filter {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private String cleSecrete;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        cleSecrete = filterConfig.getInitParameter("jwt.secret");
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String token = extraireJetonDeDemande(httpRequest);
        
        if (token != null && generator.isValidSignature(token, cleSecrete)) {
            JSONObject payload = generator.getJWTPayload(token);
            
            // Ajouter contexte utilisateur à la demande
            httpRequest.setAttribute("idUtilisateur", payload.getString("sub"));
            httpRequest.setAttribute("nomUtilisateur", payload.getString("nomUtilisateur"));
        }
        
        chain.doFilter(request, response);
    }
    
    private String extraireJetonDeDemande(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}
```

## Architecture Microservices

### Authentification Service-à-Service

```java
@Service
public class ServiceJetonMicroservice {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String cleSecreteService = "cle-secrete-service-a-service";
    
    public String creerJetonService(String idService, List<String> portees) {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var tableauPortees = ArrayStringLeafBuilder.builder();
        portees.forEach(tableauPortees::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", idService)
            .put("aud", "services-internes")
            .put("scopes", tableauPortees.build())
            .put("iat", System.currentTimeMillis())
            .put("exp", System.currentTimeMillis() + Duration.ofMinutes(10).toMillis())
            .build();
        
        return generator.generateJWT(cleSecreteService, header, payload);
    }
    
    public boolean validerJetonService(String token, String idServiceAttendu) {
        if (!generator.isValidSignature(token, cleSecreteService)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        String idService = payload.getString("sub");
        
        return idServiceAttendu.equals(idService);
    }
}
```

## Cas d'Usage Avancés

### Application Multi-Locataire

```java
@Service
public class ServiceJetonMultiLocataire {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final Map<String, String> secretsLocataire = new ConcurrentHashMap<>();
    
    public String creerJetonLocataire(String idLocataire, Utilisateur utilisateur, List<String> roles) {
        String secretLocataire = getSecretLocataire(idLocataire);
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .put("locataire", idLocataire)
            .build();
        
        var tableauRoles = ArrayStringLeafBuilder.builder();
        roles.forEach(tableauRoles::add);
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", utilisateur.getId())
            .put("locataire", idLocataire)
            .put("roles", tableauRoles.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(24).toMillis())
            .build();
        
        return generator.generateJWT(secretLocataire, header, payload);
    }
    
    public ResultatValidationLocataire validerJetonLocataire(String token, String idLocataireAttendu) {
        try {
            // Extraire locataire du header d'abord
            JSONObject header = generator.getJWTHeader(token);
            String idLocataireJeton = header.getString("locataire");
            
            if (!idLocataireAttendu.equals(idLocataireJeton)) {
                return ResultatValidationLocataire.echec("Locataire non correspondant");
            }
            
            String secretLocataire = getSecretLocataire(idLocataireJeton);
            if (!generator.isValidSignature(token, secretLocataire)) {
                return ResultatValidationLocataire.echec("Signature invalide");
            }
            
            JSONObject payload = generator.getJWTPayload(token);
            return ResultatValidationLocataire.succes(payload);
            
        } catch (Exception e) {
            return ResultatValidationLocataire.echec("Erreur de validation");
        }
    }
}
```

### Contrôle d'Accès Basé sur Permissions

```java
@Service
public class ServiceJetonBasePermissions {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    @Value("${jwt.secret}")
    private String cleSecrete;
    
    public String creerJetonPermission(Utilisateur utilisateur, Set<Permission> permissions) {
        var cartePermissions = ObjectLeafBuilder.builder();
        
        // Grouper permissions par ressource
        Map<String, List<String>> permissionsRessource = permissions.stream()
            .collect(Collectors.groupingBy(
                Permission::getRessource,
                Collectors.mapping(Permission::getAction, Collectors.toList())
            ));
        
        permissionsRessource.forEach((ressource, actions) -> {
            var tableauActions = ArrayStringLeafBuilder.builder();
            actions.forEach(tableauActions::add);
            cartePermissions.put(ressource, tableauActions.build());
        });
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", utilisateur.getId())
            .put("permissions", cartePermissions.build())
            .put("exp", System.currentTimeMillis() + Duration.ofHours(8).toMillis())
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        return generator.generateJWT(cleSecrete, header, payload);
    }
    
    public boolean aPermission(String token, String ressource, String action) {
        if (!generator.isValidSignature(token, cleSecrete)) {
            return false;
        }
        
        JSONObject payload = generator.getJWTPayload(token);
        JSONObject permissions = payload.optJSONObject("permissions");
        
        if (permissions == null || !permissions.has(ressource)) {
            return false;
        }
        
        JSONArray actions = permissions.getJSONArray(ressource);
        for (int i = 0; i < actions.length(); i++) {
            if (action.equals(actions.getString(i))) {
                return true;
            }
        }
        
        return false;
    }
}
```

## Exemples de Gestion d'Erreurs

### Gestion Complète d'Erreurs

```java
@Service
public class ServiceJetonRobuste {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    
    public ResultatTraitementJeton traiterJeton(String token, String cleSecrete) {
        try {
            // Étape 1 : Validation basique
            if (token == null || token.trim().isEmpty()) {
                return ResultatTraitementJeton.erreur(CodeErreur.JETON_MANQUANT);
            }
            
            // Étape 2 : Validation de format
            if (!estFormatJWTValide(token)) {
                return ResultatTraitementJeton.erreur(CodeErreur.FORMAT_INVALIDE);
            }
            
            // Étape 3 : Validation de signature
            if (!generator.isValidSignature(token, cleSecrete)) {
                return ResultatTraitementJeton.erreur(CodeErreur.SIGNATURE_INVALIDE);
            }
            
            // Étape 4 : Extraction et validation des revendications
            JSONObject payload = generator.getJWTPayload(token);
            
            if (!payload.has("exp")) {
                return ResultatTraitementJeton.erreur(CodeErreur.EXPIRATION_MANQUANTE);
            }
            
            long expiration = payload.getLong("exp");
            if (System.currentTimeMillis() > expiration) {
                return ResultatTraitementJeton.erreur(CodeErreur.JETON_EXPIRE);
            }
            
            return ResultatTraitementJeton.succes(payload);
            
        } catch (IllegalArgumentException e) {
            return ResultatTraitementJeton.erreur(CodeErreur.ENTREE_INVALIDE, e.getMessage());
        } catch (JSONException e) {
            return ResultatTraitementJeton.erreur(CodeErreur.ERREUR_ANALYSE_JSON, e.getMessage());
        } catch (Exception e) {
            return ResultatTraitementJeton.erreur(CodeErreur.ERREUR_INATTENDUE, e.getMessage());
        }
    }
    
    private boolean estFormatJWTValide(String token) {
        String[] parties = token.split("\\.");
        return parties.length == 3;
    }
}

public enum CodeErreur {
    JETON_MANQUANT("Le jeton est manquant"),
    FORMAT_INVALIDE("Format JWT invalide"),
    SIGNATURE_INVALIDE("Signature de jeton invalide"),
    EXPIRATION_MANQUANTE("Jeton sans expiration"),
    JETON_EXPIRE("Le jeton a expiré"),
    ENTREE_INVALIDE("Paramètres d'entrée invalides"),
    ERREUR_ANALYSE_JSON("Erreur d'analyse JSON"),
    ERREUR_INATTENDUE("Erreur inattendue survenue");
    
    private final String message;
    
    CodeErreur(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
}
```

## Exemples de Tests

### Tests Unitaires d'Opérations de Jetons

```java
@ExtendWith(MockitoExtension.class)
class TestServiceJeton {
    
    private final JWTTokenGenerator generator = new JWTTokenGenerator();
    private final String cleSecreteTest = "cle-secrete-test-32-caracteres-long";
    
    @Test
    void devraitCreerJetonValide() {
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .put("typ", "JWT")
            .build();
        
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "utilisateur-test")
            .put("exp", System.currentTimeMillis() + 3600000)
            .build();
        
        String token = generator.generateJWT(cleSecreteTest, header, payload);
        
        assertThat(token).isNotNull();
        assertThat(generator.isValidSignature(token, cleSecreteTest)).isTrue();
    }
    
    @Test
    void devraitRejeterSignatureInvalide() {
        String jetonInvalide = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalide.signature";
        
        assertThat(generator.isValidSignature(jetonInvalide, cleSecreteTest)).isFalse();
    }
    
    @Test
    void devraitExtraireChargeUtileCorrectement() {
        var payload = ObjectLeafBuilder.builder()
            .put("sub", "utilisateur-test")
            .put("role", "admin")
            .build();
        
        var header = ObjectLeafBuilder.builder()
            .put("alg", "HS256")
            .build();
        
        String token = generator.generateJWT(cleSecreteTest, header, payload);
        JSONObject chargeUtileExtraite = generator.getJWTPayload(token);
        
        assertThat(chargeUtileExtraite.getString("sub")).isEqualTo("utilisateur-test");
        assertThat(chargeUtileExtraite.getString("role")).isEqualTo("admin");
    }
}
```
