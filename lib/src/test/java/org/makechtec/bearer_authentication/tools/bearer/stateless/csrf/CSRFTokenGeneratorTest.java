package org.makechtec.bearer_authentication.tools.bearer.stateless.csrf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class CSRFTokenGeneratorTest {

    @Test
    void isValidCSRFToken() {
        var secureRandom = new SecureRandom();

        var key = new byte[16];

        secureRandom.nextBytes(key);

        var secretKey = new String(Hex.encode(key));
        var generator = new CSRFTokenGenerator(secretKey);
        
        var csrfToken = generator.generateCSRFToken();
        
        assertTrue(generator.isValidCSRFToken(csrfToken));
    }


    @Test
    void isValidCSRFToken_invalidCSRFToken() {
        var secureRandom = new SecureRandom();

        var key = new byte[16];

        secureRandom.nextBytes(key);

        var secretKey = new String(Hex.encode(key));
        var generator = new CSRFTokenGenerator(secretKey);

        
        var key2 = new byte[16];

        secureRandom.nextBytes(key2);

        var secretKey2 = new String(Hex.encode(key2));
        var generator2 = new CSRFTokenGenerator(secretKey2);

        var csrfToken2 = generator2.generateCSRFToken();

        
        assertFalse(generator.isValidCSRFToken(csrfToken2));
    }
    
}