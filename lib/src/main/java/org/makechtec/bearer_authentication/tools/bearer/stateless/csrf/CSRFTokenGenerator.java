package org.makechtec.bearer_authentication.tools.bearer.stateless.csrf;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class CSRFTokenGenerator {

    private static final int SALT_LENGTH_BYTES = 16;

    private final String secretKey;

    public CSRFTokenGenerator(String secretKey) {
        this.secretKey = secretKey;
    }

    public String generateCSRFToken() {

        var randomGenerator = new SecureRandom();
        var salt = new byte[SALT_LENGTH_BYTES];
        randomGenerator.nextBytes(salt);
        var formattedSalt = this.formatSaltToString(salt);

        var hashedValue = hash(formattedSalt);

        return "${salt}.${hashedValue}"
                .replace("${salt}", formatSaltToString(salt))
                .replace("${hashedValue}", hashedValue.toString());
    }

    public boolean isValidCSRFToken(String token) {
        var tokenComponents = token.split("\\.");
        var hashedValue = hash(tokenComponents[0]);
        return hashedValue.equals(HashCode.fromString(tokenComponents[1]));
    }

    private String formatSaltToString(byte[] salt) {
        var hexString = new StringBuilder();
        for (byte b : salt) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    private HashCode hash(String formattedSalt) {
        return Hashing.hmacSha512(secretKey.getBytes(StandardCharsets.UTF_8))
                .hashString(formattedSalt, StandardCharsets.UTF_8);
    }

}
