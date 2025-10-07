package org.makechtec.bearer_authentication.tools.bearer.argon;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherNativeTest {

    private static final String ENTERED_TEXT = """
            Hello World!
            """;
    
    private static final SaltGenerator SALT_GENERATOR = new SaltGenerator();
    private PasswordHasherNative hasher;

    @BeforeEach
    void setUp() {
        hasher = new PasswordHasherNative(new ArgonSettings(128, 10));
    }

    @Test
    void rawHash() {

        var encrypted = hasher.hash(ENTERED_TEXT);
        
        System.out.println(encrypted.getBytes(StandardCharsets.UTF_8));
        
        

        assertTrue(hasher.matches(ENTERED_TEXT, encrypted));

    }
    
    @Test
    void rawHashSalt() {
    
        var salt = SALT_GENERATOR.generate();
        var encrypted = hasher.rawHash(ENTERED_TEXT, salt);
        
        var encryptedString = new String(Hex.encode(encrypted));
        
        System.out.println(encryptedString);
        

        assertTrue(hasher.matches(ENTERED_TEXT, encryptedString));

    }
    
    @Test
    void rawHashNotIncludedSalt(){
        var salt = SALT_GENERATOR.generate();
        
        System.out.printf("Salt = %s%n", SALT_GENERATOR.formatSaltToString(salt));
        
        var encrypted = hasher.rawHashNotIncludingSalt(ENTERED_TEXT, salt);
        
        System.out.printf("Encrypted password = %s%n", SALT_GENERATOR.formatSaltToString(encrypted));
    }
}