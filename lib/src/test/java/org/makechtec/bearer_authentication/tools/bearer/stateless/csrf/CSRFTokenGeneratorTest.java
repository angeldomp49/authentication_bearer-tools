package org.makechtec.bearer_authentication.tools.bearer.stateless.csrf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CSRFTokenGeneratorTest {

    @Test
    void isValidCSRFToken() {
        var secureRandom = new SecureRandom();

        var key = new byte[16];

        secureRandom.nextBytes(key);

        var secretKey = new String(Hex.encode(key));
        var generator = new CSRFTokenGenerator();

        var csrfToken = generator.generateCSRFToken(secretKey);

        assertTrue(generator.isValidCSRFToken(csrfToken, secretKey));
    }


    @Test
    void isValidCSRFToken_invalidCSRFToken() {
        var secureRandom = new SecureRandom();

        var key = new byte[16];

        secureRandom.nextBytes(key);

        var secretKey = new String(Hex.encode(key));
        var generator = new CSRFTokenGenerator();


        var key2 = new byte[16];

        secureRandom.nextBytes(key2);

        var secretKey2 = new String(Hex.encode(key2));
        var generator2 = new CSRFTokenGenerator();

        var csrfToken2 = generator2.generateCSRFToken(secretKey2);


        assertFalse(generator.isValidCSRFToken(csrfToken2, secretKey));
    }

}