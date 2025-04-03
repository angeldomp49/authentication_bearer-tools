package org.makechtec.bearer_authentication.tools.bearer.argon;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherNativeTest {

    @Test
    void rawHash() {
        
        var enteredText = """
                Hello World!
                """;
        var hasher = new PasswordHasherNative(new ArgonSettings(128, 10));
        var encrypted = hasher.hash(enteredText);
        
        assertTrue(hasher.matches(enteredText, encrypted));
        
    }
}