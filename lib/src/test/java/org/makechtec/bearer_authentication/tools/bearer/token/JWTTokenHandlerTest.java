package org.makechtec.bearer_authentication.tools.bearer.token;

import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenHandler;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SignaturePrinter;

import java.security.SecureRandom;
import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTTokenHandlerTest {

    @Test
    void createTokenForSession() {


        var secretKey = "secretKey";
        var signaturePrinter = new SignaturePrinter(secretKey);
        var tokenHandler = new JWTTokenHandler();
        var secureRandom = new SecureRandom();
        var expirationTime = Calendar.getInstance();
        expirationTime.add(Calendar.DAY_OF_MONTH, 1);
        var session = new SessionInformation(
                expirationTime,
                false,
                secureRandom.nextInt(),
                List.of("read", "write")
        );

        var token = tokenHandler.createTokenForSession(session, secretKey);

        assertNotNull(token);
        assertTrue(tokenHandler.isValidSignature(token, secretKey));

    }
}