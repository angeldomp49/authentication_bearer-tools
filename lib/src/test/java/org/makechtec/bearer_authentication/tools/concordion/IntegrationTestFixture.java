package org.makechtec.bearer_authentication.tools.concordion;

import org.concordion.api.FullOGNL;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.support.CryptoTestHelper;
import org.makechtec.bearer_authentication.tools.support.PasswordTestHelper;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenHandler;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;

import java.util.Calendar;
import java.util.List;
import java.util.Objects;

@FullOGNL
@RunWith(ConcordionRunner.class)
public class IntegrationTestFixture {
    
    private final CryptoTestHelper cryptoHelper;
    private final PasswordTestHelper passwordHelper;
    private final JWTTokenHandler tokenHandler;
    
    public IntegrationTestFixture() {
        this.cryptoHelper = new CryptoTestHelper();
        this.passwordHelper = new PasswordTestHelper();
        this.tokenHandler = new JWTTokenHandler();
    }
    
    public String testCompleteLoginFlow(String username, String password, String secretKey) {
        if (Objects.isNull(username) || Objects.isNull(password) || Objects.isNull(secretKey)) {
            return "NULL_INPUT";
        }
        
        try {
            String hashedPassword = passwordHelper.hashPassword(password);
            
            boolean passwordVerified = passwordHelper.verifyPassword(password, hashedPassword);
            if (!passwordVerified) {
                return "PASSWORD_VERIFICATION_FAILED";
            }
            
            Calendar expiration = Calendar.getInstance();
            expiration.add(Calendar.HOUR, 1);
            
            long userIdLong;
            try {
                userIdLong = Long.parseLong(username);
            } catch (NumberFormatException e) {
                userIdLong = username.hashCode();
            }
            
            SessionInformation session = new SessionInformation(
                expiration,
                false,
                userIdLong,
                List.of("READ", "WRITE")
            );
            
            String token = tokenHandler.createTokenForSession(session, secretKey);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, secretKey);
            if (!tokenValid) {
                return "TOKEN_VALIDATION_FAILED";
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String testEncryptedTokenPayload(String userId, String sensitiveData, String tokenSecret, String encryptionKey) {
        if (Objects.isNull(userId) || Objects.isNull(sensitiveData) || Objects.isNull(tokenSecret) || Objects.isNull(encryptionKey)) {
            return "NULL_INPUT";
        }
        
        try {
            String encryptedData = cryptoHelper.encryptText(sensitiveData, encryptionKey);
            
            Calendar expiration = Calendar.getInstance();
            expiration.add(Calendar.HOUR, 1);
            
            long userIdLong;
            try {
                userIdLong = Long.parseLong(userId);
            } catch (NumberFormatException e) {
                userIdLong = userId.hashCode();
            }
            
            SessionInformation session = new SessionInformation(
                expiration,
                false,
                userIdLong,
                List.of("ENCRYPTED_DATA:" + encryptedData)
            );
            
            String token = tokenHandler.createTokenForSession(session, tokenSecret);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, tokenSecret);
            if (!tokenValid) {
                return "TOKEN_INVALID";
            }
            
            String decryptedData = cryptoHelper.decryptText(encryptedData, encryptionKey);
            if (!sensitiveData.equals(decryptedData)) {
                return "DECRYPTION_FAILED";
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String testPasswordEncryptionBeforeHashing(String password, String encryptionKey) {
        if (Objects.isNull(password) || Objects.isNull(encryptionKey)) {
            return "NULL_INPUT";
        }
        
        try {
            String encryptedPassword = cryptoHelper.encryptText(password, encryptionKey);
            
            String hashedEncryptedPassword = passwordHelper.hashPassword(encryptedPassword);
            
            String decryptedPassword = cryptoHelper.decryptText(encryptedPassword, encryptionKey);
            
            boolean verification = passwordHelper.verifyPassword(encryptedPassword, hashedEncryptedPassword);
            
            if (!password.equals(decryptedPassword)) {
                return "DECRYPTION_FAILED";
            }
            
            if (!verification) {
                return "HASH_VERIFICATION_FAILED";
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String testSecurityLayersIntegration(String username, String password, String sensitiveData, String tokenSecret, String encryptionKey) {
        try {
            String encryptedSensitiveData = cryptoHelper.encryptText(sensitiveData, encryptionKey);
            
            String hashedPassword = passwordHelper.hashPassword(password);
            
            boolean passwordValid = passwordHelper.verifyPassword(password, hashedPassword);
            if (!passwordValid) {
                return "PASSWORD_AUTH_FAILED";
            }
            
            Calendar expiration = Calendar.getInstance();
            expiration.add(Calendar.HOUR, 1);
            
            long userIdLong;
            try {
                userIdLong = Long.parseLong(username);
            } catch (NumberFormatException e) {
                userIdLong = username.hashCode();
            }
            
            SessionInformation session = new SessionInformation(
                expiration,
                false,
                userIdLong,
                List.of("ENCRYPTED:" + encryptedSensitiveData)
            );
            
            String token = tokenHandler.createTokenForSession(session, tokenSecret);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, tokenSecret);
            if (!tokenValid) {
                return "TOKEN_AUTH_FAILED";
            }
            
            String decryptedData = cryptoHelper.decryptText(encryptedSensitiveData, encryptionKey);
            if (!sensitiveData.equals(decryptedData)) {
                return "DATA_DECRYPTION_FAILED";
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String testPerformanceIntegration(String username, String password, String tokenSecret, int iterations) {
        try {
            long startTime = System.currentTimeMillis();
            
            for (int i = 0; i < iterations; i++) {
                String hashedPassword = passwordHelper.hashPassword(password + i);
                
                Calendar expiration = Calendar.getInstance();
                expiration.add(Calendar.HOUR, 1);
                
                long userIdLong;
                try {
                    userIdLong = Long.parseLong(username + i);
                } catch (NumberFormatException e) {
                    userIdLong = (username + i).hashCode();
                }
                
                SessionInformation session = new SessionInformation(
                    expiration,
                    false,
                    userIdLong,
                    List.of("READ")
                );
                
                String token = tokenHandler.createTokenForSession(session, tokenSecret);
                tokenHandler.isValidSignature(token, tokenSecret);
            }
            
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            long maxAllowedTime = iterations * 2000; // 2 seconds per iteration max
            
            return totalTime <= maxAllowedTime ? "WITHIN_LIMIT" : "EXCEEDED_LIMIT";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    // Método que falla intencionalmente para demostrar reportes
    public String testIntegrationWithFailure(String testType) {
        switch (testType) {
            case "EXPECTED_SUCCESS":
                return "FAILURE"; // Falla intencionalmente
            case "EXPECTED_FAILURE":
                return "SUCCESS"; // No falla cuando debería
            case "FORCE_ERROR":
                throw new RuntimeException("Intentional integration failure");
            default:
                return "UNKNOWN_TEST";
        }
    }
    
    public String testCompleteLoginFlowWithFailures(String username, String password, String secretKey, String scenario) {
        if (Objects.isNull(username) || Objects.isNull(password) || Objects.isNull(secretKey)) {
            return "NULL_INPUT";
        }
        
        // Agregar escenarios que fallen intencionalmente
        if ("FORCE_HASH_FAILURE".equals(scenario)) {
            return "HASH_FAILED";
        }
        
        if ("FORCE_TOKEN_FAILURE".equals(scenario)) {
            return "TOKEN_FAILED";
        }
        
        try {
            String hashedPassword = passwordHelper.hashPassword(password);
            
            boolean passwordVerified = passwordHelper.verifyPassword(password, hashedPassword);
            if (!passwordVerified) {
                return "PASSWORD_VERIFICATION_FAILED";
            }
            
            Calendar expiration = Calendar.getInstance();
            expiration.add(Calendar.HOUR, 1);
            
            long userIdLong;
            try {
                userIdLong = Long.parseLong(username);
            } catch (NumberFormatException e) {
                userIdLong = username.hashCode();
            }
            
            SessionInformation session = new SessionInformation(
                expiration,
                false,
                userIdLong,
                List.of("READ", "WRITE")
            );
            
            String token = tokenHandler.createTokenForSession(session, secretKey);
            
            boolean tokenValid = tokenHandler.isValidSignature(token, secretKey);
            if (!tokenValid) {
                return "TOKEN_VALIDATION_FAILED";
            }
            
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
}
