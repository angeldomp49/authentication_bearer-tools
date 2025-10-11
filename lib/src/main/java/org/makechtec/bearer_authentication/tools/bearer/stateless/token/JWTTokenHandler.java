package org.makechtec.bearer_authentication.tools.bearer.stateless.token;

import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidationApplier;
import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;

import java.util.UUID;

import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultSecretKeyValidators.SECRET_KEY_MIN_32_CHARS;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultSessionValidators.*;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_EMPTY;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_NULL;


public class JWTTokenHandler {

    private final GenericValidationApplier<SessionInformation> sessionValidator;
    private final GenericValidationApplier<String> stringGenericValidationApplier;

    public JWTTokenHandler(GenericValidationApplier<SessionInformation> sessionValidator, GenericValidationApplier<String> stringGenericValidationApplier) {
        this.sessionValidator = sessionValidator;
        this.stringGenericValidationApplier = stringGenericValidationApplier;
    }

    public JWTTokenHandler() {
        this.sessionValidator = new GenericValidationApplier<>();
        this.stringGenericValidationApplier = new GenericValidationApplier<>();
    }

    public String createTokenForSession(SessionInformation session, String secretKey) {

        if (!sessionValidator.applyAllValidations(session, SESSION_NOT_NULL, SESSION_IS_NOT_CLOSED, SESSION_POSITIVE_USER_ID, SESSION_EXPIRATION_DATE_IN_FUTURE, SESSION_AT_LEAST_ONE_PERMISSION)) {
            throw new IllegalArgumentException("The session is not valid" + sessionValidator.getInvalidator().getErrorMessage());
        }

        if (!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, SECRET_KEY_MIN_32_CHARS)) {
            throw new IllegalArgumentException("The secret key is not valid" + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }


        var signaturePrinter = new SignaturePrinter(secretKey);
        var permissionsSet = ArrayStringLeafBuilder.builder();

        session.permissions().forEach(permissionsSet::add);

        return TokenBuilder.builder(signaturePrinter)
                .header(
                        ObjectLeafBuilder.builder()
                                .put("alg", "SHA256")
                                .put("typ", "jwt")
                                .build()
                )
                .payload(
                        ObjectLeafBuilder.builder()
                                .put("exp", session.expirationDate().getTimeInMillis())
                                .put("uid", session.userId())
                                .put("isClosed", session.isClosed())
                                .put("permissions", permissionsSet.build())
                                .put("jti", UUID.randomUUID().toString())
                                .build()
                )
                .sign()
                .build();
    }

    public boolean isValidSignature(String token, String secretKey) {

        if (!stringGenericValidationApplier.applyAllValidations(token, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("The token is not valid" + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }
        if (!stringGenericValidationApplier.applyAllValidations(secretKey, STRING_NOT_NULL, STRING_NOT_EMPTY, SECRET_KEY_MIN_32_CHARS)) {
            throw new IllegalArgumentException("The secret key is not valid" + stringGenericValidationApplier.getInvalidator().getErrorMessage());
        }

        var signaturePrinter = new SignaturePrinter(secretKey);
        var components = token.split("\\.");

        var message = components[0] + '.' + components[1];

        var reformedSignature = signaturePrinter.sign(message);
        var reformedToken = components[0] + '.' + components[1] + '.' + reformedSignature;

        return reformedToken.equals(token);
    }

}
