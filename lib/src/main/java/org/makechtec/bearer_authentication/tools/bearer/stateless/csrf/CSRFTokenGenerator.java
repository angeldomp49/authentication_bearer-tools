package org.makechtec.bearer_authentication.tools.bearer.stateless.csrf;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidationApplier;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.*;

public class CSRFTokenGenerator {

    private static final int SALT_LENGTH_BYTES = 16;

    private final GenericValidationApplier<String> stringGenericValidationApplier;

    public CSRFTokenGenerator() {
        this.stringGenericValidationApplier = new GenericValidationApplier<>();
    }

    public CSRFTokenGenerator(GenericValidationApplier<String> stringGenericValidationApplier) {
        this.stringGenericValidationApplier = stringGenericValidationApplier;
    }

    public String generateCSRFToken(String secretKey) {
        
        if(!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, STRING_MIN_32_CHARS)) {
            throw new IllegalArgumentException("Invalid secret key: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }
        
        var randomGenerator = new SecureRandom();
        var salt = new byte[SALT_LENGTH_BYTES];
        randomGenerator.nextBytes(salt);
        var formattedSalt = this.formatSaltToString(salt);

        var hashedValue = hash(formattedSalt, secretKey);

        return "${salt}.${hashedValue}"
                .replace("${salt}", formatSaltToString(salt))
                .replace("${hashedValue}", hashedValue.toString());
    }

    public boolean isValidCSRFToken(String token, String secretKey) {

        if(!stringGenericValidationApplier.applyAllValidations(token, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid token: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        if(!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, STRING_MIN_32_CHARS)) {
            throw new IllegalArgumentException("Invalid secret key: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }
        
        var tokenComponents = token.split("\\.");
        var hashedValue = hash(tokenComponents[0], secretKey);
        return hashedValue.equals(HashCode.fromString(tokenComponents[1]));
    }

    private String formatSaltToString(byte[] salt) {
        var hexString = new StringBuilder();
        for (byte b : salt) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    private HashCode hash(String formattedSalt, String secretKey) {
        return Hashing.hmacSha512(secretKey.getBytes(StandardCharsets.UTF_8))
                .hashString(formattedSalt, StandardCharsets.UTF_8);
    }

}
