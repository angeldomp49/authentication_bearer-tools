package org.makechtec.bearer_authentication.tools.bearer.aes;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.aes.TextCipher;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TextCipherTest {

    @Test
    void encrypt() throws InvalidCipherTextException {
        var cipher = new TextCipher();
        var secureRandom = new SecureRandom();

        var key = new byte[16];

        secureRandom.nextBytes(key);
        var enteredText = "Hello World!".getBytes(StandardCharsets.UTF_8);

        System.out.println("Entered text: " + new String(enteredText, StandardCharsets.UTF_8));
        System.out.println("key: " + new String(Hex.encode(key)));

        var encrypted = cipher.encrypt(enteredText, key);
        var decrypted = cipher.decrypt(encrypted, key);

        assertEquals(Hex.toHexString(enteredText), Hex.toHexString(decrypted));

    }

}