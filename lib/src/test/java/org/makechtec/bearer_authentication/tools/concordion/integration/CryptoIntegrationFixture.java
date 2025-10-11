package org.makechtec.bearer_authentication.tools.concordion.integration;

import org.concordion.api.ConcordionResources;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.bearer.stateless.aes.TextCipher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenHandler;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.json.JSONObject;

import java.util.Base64;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.List;

@RunWith(ConcordionRunner.class)
@ConcordionResources("css/concordion-custom.css")
public class CryptoIntegrationFixture {

    private final TextCipher textCipher = new TextCipher();
    private final ArgonSettings argonSettings = new ArgonSettings(65536, 3);
    private final PasswordHasherNative passwordHasher = new PasswordHasherNative(argonSettings);
    private final JWTTokenHandler tokenHandler = new JWTTokenHandler();
    private final SecureRandom secureRandom = new SecureRandom();
    
    public String testSecureCredentialStorage(String password) {
        try {
            String hashedPassword = passwordHasher.hash(password);
            
            byte[] encryptionKey = new byte[32];
            secureRandom.nextBytes(encryptionKey);
            
            byte[] encryptedHash = textCipher.encrypt(hashedPassword.getBytes(), encryptionKey);
            
            byte[] decryptedHashBytes = textCipher.decrypt(encryptedHash, encryptionKey);
            String decryptedHash = new String(decryptedHashBytes);
            
            boolean isValidPassword = passwordHasher.matches(password, decryptedHash);
            
            return isValidPassword ? "SUCCESS" : "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testTokenPayloadEncryption(String userId, String sensitiveData, String jwtSecret) {
        try {
            byte[] encryptionKey = new byte[32];
            secureRandom.nextBytes(encryptionKey);
            
            byte[] encryptedSensitiveData = textCipher.encrypt(sensitiveData.getBytes(), encryptionKey);
            
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 60);
            
            JSONObject claims = new JSONObject();
            claims.put("encryptedData", Base64.getEncoder().encodeToString(encryptedSensitiveData));
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(userId.replaceAll("\\D", "1")),
                List.of("READ"),
                claims
            );
            
            String token = tokenHandler.createTokenForSession(session, jwtSecret);
            boolean isValidToken = tokenHandler.isValidSignature(token, jwtSecret);
            
            if (isValidToken) {
                byte[] decryptedData = textCipher.decrypt(encryptedSensitiveData, encryptionKey);
                String decryptedSensitiveData = new String(decryptedData);
                
                return sensitiveData.equals(decryptedSensitiveData) ? "SUCCESS" : "FAILED";
            }
            
            return "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testPasswordBasedEncryption(String password, String plaintext) {
        try {
            byte[] key = deriveKeyFromPassword(password);
            
            byte[] encrypted = textCipher.encrypt(plaintext.getBytes(), key);
            byte[] decrypted = textCipher.decrypt(encrypted, key);
            
            String decryptedText = new String(decrypted);
            return plaintext.equals(decryptedText) ? "SUCCESS" : "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testMultiLayerSecurity(String password, String userData, String jwtSecret) {
        try {
            String hashedPassword = passwordHasher.hash(password);
            
            byte[] userEncryptionKey = deriveKeyFromPassword(password);
            byte[] encryptedUserData = textCipher.encrypt(userData.getBytes(), userEncryptionKey);
            
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 30);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                123L,
                List.of("READ"),
                new JSONObject()
            );
            
            String token = tokenHandler.createTokenForSession(session, jwtSecret);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, jwtSecret);
            boolean passwordValid = passwordHasher.matches(password, hashedPassword);
            
            if (tokenValid && passwordValid) {
                byte[] decryptedUserData = textCipher.decrypt(encryptedUserData, userEncryptionKey);
                String decryptedData = new String(decryptedUserData);
                
                return userData.equals(decryptedData) ? "SUCCESS" : "FAILED";
            }
            
            return "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testCrossComponentValidation(String input) {
        try {
            if (input == null || input.trim().isEmpty()) {
                return "INVALID_INPUT";
            }
            
            String hashedInput = passwordHasher.hash(input);
            
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);
            byte[] encryptedHash = textCipher.encrypt(hashedInput.getBytes(), key);
            
            Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.MINUTE, 15);
            
            SessionInformation session = new SessionInformation(
                expirationDate,
                false,
                Long.parseLong(input.replaceAll("\\D", "1")),
                List.of("READ"),
                new JSONObject()
            );
            
            String jwtSecret = "crossComponentValidationSecretKey";
            String token = tokenHandler.createTokenForSession(session, jwtSecret);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, jwtSecret);
            byte[] decryptedHashBytes = textCipher.decrypt(encryptedHash, key);
            String decryptedHash = new String(decryptedHashBytes);
            boolean passwordValid = passwordHasher.matches(input, decryptedHash);
            
            if (tokenValid && passwordValid) {
                return "ALL_COMPONENTS_VALID";
            }
            
            return "COMPONENT_VALIDATION_FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testKeyRotationScenario(String userId, String oldSecret, String newSecret) {
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
            
            String oldToken = tokenHandler.createTokenForSession(session, oldSecret);
            
            boolean validWithOldKey = tokenHandler.isValidSignature(oldToken, oldSecret);
            
            if (!validWithOldKey) {
                return "OLD_KEY_VALIDATION_FAILED";
            }
            
            try {
                boolean validWithNewKey = tokenHandler.isValidSignature(oldToken, newSecret);
                if (validWithNewKey) {
                    return "NEW_KEY_INCORRECTLY_ACCEPTED_OLD_TOKEN";
                }
            } catch (Exception e) {
                // Expected - new key should not validate old token
            }
            
            String newToken = tokenHandler.createTokenForSession(session, newSecret);
            boolean validNewToken = tokenHandler.isValidSignature(newToken, newSecret);
            
            if (validNewToken) {
                return "KEY_ROTATION_SUCCESS";
            }
            
            return "KEY_ROTATION_FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    private byte[] deriveKeyFromPassword(String password) {
        try {
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            return sha256.digest(password.getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }
    
    public String generateJWTSecret() {
        return "integrationTestSecretKeyForJWTSigning";
    }
    
    public String generateSensitiveData() {
        return "This is highly sensitive user data that needs encryption";
    }
}
