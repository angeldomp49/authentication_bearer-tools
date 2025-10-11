package org.makechtec.bearer_authentication.tools.concordion.token;

import org.concordion.api.ConcordionResources;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenHandler;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.json.JSONObject;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;

@RunWith(ConcordionRunner.class)
@ConcordionResources("css/concordion-custom.css")
public class BearerTokenFixture {

    private final JWTTokenHandler tokenHandler = new JWTTokenHandler();
    
    public String createToken(String userId, String secretKey, long expirationMinutes) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, (int) expirationMinutes);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ", "WRITE"),
                new JSONObject()
            );
            
            return tokenHandler.createTokenForSession(session, secretKey);
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String validateToken(String token, String secretKey) {
        try {
            boolean isValid = tokenHandler.isValidSignature(token, secretKey);
            return isValid ? "VALID" : "INVALID";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testRoundTripToken(String userId, String secretKey) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            SessionInformation originalSession = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                new JSONObject()
            );
            
            String token = tokenHandler.createTokenForSession(originalSession, secretKey);
            boolean isValid = tokenHandler.isValidSignature(token, secretKey);
            
            return isValid ? "SUCCESS" : "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String validateTokenStructure(String token) {
        if (token == null || token.startsWith("ERROR:")) {
            return "INVALID_STRUCTURE";
        }
        
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return "INVALID_STRUCTURE";
        }
        
        try {
            Base64.getUrlDecoder().decode(parts[0]);
            Base64.getUrlDecoder().decode(parts[1]);
            Base64.getUrlDecoder().decode(parts[2]);
            return "VALID_STRUCTURE";
        } catch (Exception e) {
            return "INVALID_STRUCTURE";
        }
    }
    
    public String testExpiredToken(String userId, String secretKey) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, -1);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                new JSONObject()
            );
            
            String token = tokenHandler.createTokenForSession(session, secretKey);
            return "TOKEN_CREATED_FOR_EXPIRED_SESSION";
        } catch (Exception e) {
            if (e.getMessage().contains("expiration") || e.getMessage().contains("future")) {
                return "CORRECTLY_EXPIRED";
            }
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testTamperedToken(String userId, String secretKey) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                new JSONObject()
            );
            
            String token = tokenHandler.createTokenForSession(session, secretKey);
            
            String[] parts = token.split("\\.");
            char[] payloadChars = parts[1].toCharArray();
            payloadChars[0] = payloadChars[0] == 'A' ? 'B' : 'A';
            parts[1] = new String(payloadChars);
            String tamperedToken = String.join(".", parts);
            
            boolean isValid = tokenHandler.isValidSignature(tamperedToken, secretKey);
            return isValid ? "INCORRECTLY_ACCEPTED" : "CORRECTLY_REJECTED";
        } catch (Exception e) {
            return "CORRECTLY_REJECTED";
        }
    }
    
    public String testWrongSecretKey(String userId, String correctKey, String wrongKey) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                new JSONObject()
            );
            
            String token = tokenHandler.createTokenForSession(session, correctKey);
            boolean isValid = tokenHandler.isValidSignature(token, wrongKey);
            
            return isValid ? "INCORRECTLY_ACCEPTED" : "CORRECTLY_REJECTED";
        } catch (Exception e) {
            return "CORRECTLY_REJECTED";
        }
    }
    
    public String validateNullInputs(String inputType) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                123L,
                List.of("READ"),
                new JSONObject()
            );
            String validKey = "thisIsASecretKeyThatIsSufficientlyLong";
            
            if ("session".equals(inputType)) {
                tokenHandler.createTokenForSession(null, validKey);
            } else if ("secretKey".equals(inputType)) {
                tokenHandler.createTokenForSession(session, null);
            } else if ("token".equals(inputType)) {
                tokenHandler.isValidSignature(null, validKey);
            }
            return "NO_EXCEPTION";
        } catch (IllegalArgumentException e) {
            return "EXPECTED_EXCEPTION: " + e.getMessage();
        } catch (Exception e) {
            return "UNEXPECTED_EXCEPTION: " + e.getMessage();
        }
    }
    
    public String validateShortSecretKey(String shortKey) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                123L,
                List.of("READ"),
                new JSONObject()
            );
            
            tokenHandler.createTokenForSession(session, shortKey);
            return "NO_EXCEPTION";
        } catch (IllegalArgumentException e) {
            return "EXPECTED_EXCEPTION: " + e.getMessage();
        } catch (Exception e) {
            return "UNEXPECTED_EXCEPTION: " + e.getMessage();
        }
    }
    
    public String testCustomClaims(String userId, String secretKey, String customClaim, String customValue) {
        try {
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            JSONObject claims = new JSONObject();
            claims.put(customClaim, customValue);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                claims
            );
            
            String token = tokenHandler.createTokenForSession(session, secretKey);
            boolean isValid = tokenHandler.isValidSignature(token, secretKey);
            
            return isValid ? "SUCCESS" : "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String generateSecretKey() {
        return "thisIsASecretKeyThatIsSufficientlyLongForJWTSigning";
    }
    
    public String generateShortKey() {
        return "shortKey";
    }
}
