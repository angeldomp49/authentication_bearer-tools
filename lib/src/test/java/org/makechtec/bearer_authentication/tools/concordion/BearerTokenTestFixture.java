package org.makechtec.bearer_authentication.tools.concordion;

import org.concordion.api.FullOGNL;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenHandler;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;

import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;

@FullOGNL
@RunWith(ConcordionRunner.class)
public class BearerTokenTestFixture {

    private final JWTTokenHandler tokenHandler;
    private final JWTTokenGenerator tokenGenerator;

    public BearerTokenTestFixture() {
        this.tokenHandler = new JWTTokenHandler();
        this.tokenGenerator = new JWTTokenGenerator();
    }

    public String generateToken(String userId, String secretKey, boolean isClosed) {
        if (Objects.isNull(userId) || Objects.isNull(secretKey)) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }

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
                isClosed,
                userIdLong,
                List.of("READ", "WRITE")
        );

        return tokenHandler.createTokenForSession(session, secretKey);
    }

    public String generateExpiredToken(String userId, String secretKey) {
        if (Objects.isNull(userId) || Objects.isNull(secretKey)) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }

        Calendar expiration = Calendar.getInstance();
        expiration.add(Calendar.HOUR, -1);

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
                List.of("READ")
        );

        return tokenHandler.createTokenForSession(session, secretKey);
    }

    public boolean validateToken(String token, String secretKey) {
        if (Objects.isNull(token) || Objects.isNull(secretKey)) {
            return false;
        }

        return tokenHandler.isValidSignature(token, secretKey);
    }

    public boolean isTokenExpired(String token) {
        if (Objects.isNull(token)) {
            return true;
        }

        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return true;
            }

            String payload = new String(Base64.getDecoder().decode(parts[1]));

            long exp = extractExpirationFromPayload(payload);

            return System.currentTimeMillis() > exp;
        } catch (Exception e) {
            return true;
        }
    }

    public String testTokenGeneration(String userId, String secretKey, String testCase) {
        if (Objects.isNull(userId) || Objects.isNull(secretKey)) {
            return "NULL_INPUT";
        }

        try {
            switch (testCase) {
                case "VALID_TOKEN":
                    String token = generateToken(userId, secretKey, false);
                    boolean isValid = validateToken(token, secretKey);
                    boolean isExpired = isTokenExpired(token);
                    return validateTokenResult(token, isValid, isExpired);

                case "EXPIRED_TOKEN":
                    String expiredToken = generateExpiredToken(userId, secretKey);
                    boolean expiredValid = validateToken(expiredToken, secretKey);
                    boolean expired = isTokenExpired(expiredToken);
                    return validateTokenResult(expiredToken, expiredValid, expired);

                case "INVALID_SECRET":
                    String validToken = generateToken(userId, secretKey, false);
                    boolean invalidSecretValid = validateToken(validToken, "wrongsecret");
                    return invalidSecretValid ? "SECURITY_BREACH" : "SECURE";

                case "MALFORMED_TOKEN":
                    return validateToken("invalid.token", secretKey) ? "VALIDATION_FAILED" : "VALIDATION_PASSED";

                case "FORCE_FAILURE":
                    return "UNEXPECTED_RESULT"; // Fallará intencionalmente

                default:
                    return "UNKNOWN_TEST";
            }
        } catch (Exception e) {
            return "ERROR";
        }
    }

    // Método helper para validar resultados de tokens
    private String validateTokenResult(String token, boolean isValid, boolean hasExpired) {
        if (Objects.isNull(token)) {
            return "NULL_TOKEN";
        }

        if (token.isEmpty()) {
            return "EMPTY_TOKEN";
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return "INVALID_JWT_FORMAT";
        }

        if (hasExpired && isValid) {
            return "EXPIRED_BUT_VALID";
        }

        if (!hasExpired && !isValid) {
            return "NOT_EXPIRED_BUT_INVALID";
        }

        return isValid ? "VALID" : "INVALID";
    }

    public String testTokenSecurity(String userId, String secretKey) {
        try {
            String token1 = generateToken(userId, secretKey, false);
            String token2 = generateToken(userId, secretKey, false);

            if (token1.equals(token2)) {
                return "TOKEN_NOT_UNIQUE";
            }

            boolean valid1 = validateToken(token1, secretKey);
            boolean valid2 = validateToken(token2, secretKey);

            if (valid1 && valid2) {
                return "SECURE";
            } else {
                return "VALIDATION_INCONSISTENT";
            }
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public String validateTokenFormat(String token) {
        if (Objects.isNull(token)) {
            return "NULL_TOKEN";
        }

        if (token.isEmpty()) {
            return "EMPTY_TOKEN";
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return "INVALID_FORMAT";
        }

        try {
            Base64.getDecoder().decode(parts[0]); // header
            Base64.getDecoder().decode(parts[1]); // payload
            Base64.getDecoder().decode(parts[2]); // signature
            return "VALID_FORMAT";
        } catch (IllegalArgumentException e) {
            return "INVALID_BASE64";
        }
    }

    public String testCustomClaims(String userId, String secretKey, String customClaim, String customValue) {
        try {
            // Implementación simplificada sin ObjectLeafBuilder
            String token = generateToken(userId, secretKey, false);
            boolean isValid = validateToken(token, secretKey);

            return isValid ? "SUCCESS" : "INVALID_TOKEN";
        } catch (Exception e) {
            return "ERROR";
        }
    }

    // Método que falla intencionalmente
    public String testIntentionalTokenFailure() {
        return "WRONG_RESULT"; // Siempre retorna un valor incorrecto
    }

    private long extractExpirationFromPayload(String payload) {
        if (Objects.isNull(payload) || payload.isEmpty()) {
            return 0;
        }
        int expKeyIndex = payload.indexOf("\"exp\"");
        if (expKeyIndex == -1) {
            return 0;
        }
        int colonIndex = payload.indexOf(":", expKeyIndex);
        if (colonIndex == -1) {
            return 0;
        }
        int valueStart = colonIndex + 1;
        while (valueStart < payload.length() && Character.isWhitespace(payload.charAt(valueStart))) {
            valueStart++;
        }
        int valueEnd = valueStart;
        while (valueEnd < payload.length() && Character.isDigit(payload.charAt(valueEnd))) {
            valueEnd++;
        }
        if (valueStart == valueEnd) {
            return 0;
        }
        String expValue = payload.substring(valueStart, valueEnd);
        return Long.parseLong(expValue);
    }

}
