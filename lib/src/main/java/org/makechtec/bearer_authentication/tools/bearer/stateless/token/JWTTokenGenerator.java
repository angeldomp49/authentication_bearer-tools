package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.json.JSONObject;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidationApplier;
import org.makechtec.software.json_tree.ObjectLeaf;

import java.util.Base64;

import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultJSONValidators.JSON_NOT_EMPTY;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultSecretKeyValidators.SECRET_KEY_MIN_32_CHARS;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_EMPTY;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_NULL;

public class JWTTokenGenerator {

    private final GenericValidationApplier<String> stringGenericValidationApplier;

    public JWTTokenGenerator() {
        this.stringGenericValidationApplier = new GenericValidationApplier<>();
    }

    public JWTTokenGenerator(GenericValidationApplier<String> stringGenericValidationApplier) {
        this.stringGenericValidationApplier = stringGenericValidationApplier;
    }

    public String generateJWT(String secretKey, ObjectLeaf jsonHeader, ObjectLeaf jsonPayload) {

        if (!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, SECRET_KEY_MIN_32_CHARS)) {
            throw new IllegalArgumentException("Invalid secret key: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringGenericValidationApplier.applyAllValidations(jsonHeader.getLeafValue(), STRING_NOT_NULL, STRING_NOT_EMPTY, JSON_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid JSON header: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringGenericValidationApplier.applyAllValidations(jsonPayload.getLeafValue(), STRING_NOT_NULL, STRING_NOT_EMPTY, JSON_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid JSON payload: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        var signaturePrinter = new SignaturePrinter(secretKey);

        return TokenBuilder.builder(signaturePrinter)
                .header(jsonHeader)
                .payload(jsonPayload)
                .sign()
                .build();
    }

    public boolean isValidSignature(String token, String secretKey) {

        if (!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, SECRET_KEY_MIN_32_CHARS)) {
            throw new IllegalArgumentException("Invalid secret key: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringGenericValidationApplier.applyAllValidations(token, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid token: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        var signaturePrinter = new SignaturePrinter(secretKey);
        var components = token.split("\\.");

        var message = components[0] + '.' + components[1];

        var reformedSignature = signaturePrinter.sign(message);
        var reformedToken = components[0] + '.' + components[1] + '.' + reformedSignature;

        return reformedToken.equals(token);
    }

    public JSONObject getJWTPayload(String token) {

        if (!stringGenericValidationApplier.applyAllValidations(token, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid token: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        var components = token.split("\\.");
        var decoded = Base64.getDecoder().decode(components[1]);
        return new JSONObject(new String(decoded));
    }

    public JSONObject getJWTHeader(String token) {

        if (!stringGenericValidationApplier.applyAllValidations(token, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid token: " + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        var components = token.split("\\.");
        var decoded = Base64.getDecoder().decode(components[0]);
        return new JSONObject(new String(decoded));
    }

}
