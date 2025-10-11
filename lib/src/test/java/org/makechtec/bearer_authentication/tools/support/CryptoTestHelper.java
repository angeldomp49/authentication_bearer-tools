package org.makechtec.bearer_authentication.tools.support;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.makechtec.bearer_authentication.tools.bearer.stateless.aes.TextCipher;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

public class CryptoTestHelper {

    private final TextCipher textCipher;

    public CryptoTestHelper() {
        this.textCipher = new TextCipher();
    }

    public String encryptText(String plainText, String keyString) {
        if (Objects.isNull(plainText) || Objects.isNull(keyString)) {
            throw new IllegalArgumentException("Input parameters cannot be null");
        }

        try {
            byte[] key = generateKeyFromString(keyString);
            byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = textCipher.encrypt(plainBytes, key);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decryptText(String encryptedText, String keyString) {
        if (Objects.isNull(encryptedText) || Objects.isNull(keyString)) {
            throw new IllegalArgumentException("Input parameters cannot be null");
        }

        try {
            byte[] key = generateKeyFromString(keyString);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decrypted = textCipher.decrypt(encryptedBytes, key);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public String testEncryptionRoundTrip(String plainText, String keyString) {
        try {
            String encrypted = encryptText(plainText, keyString);
            String decrypted = decryptText(encrypted, keyString);

            if (plainText.equals(decrypted)) {
                return "SUCCESS";
            } else {
                return "ROUND_TRIP_FAILED";
            }
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public String validateKeyFormat(String keyString) {
        if (Objects.isNull(keyString)) {
            return "NULL_KEY";
        }

        if (keyString.isEmpty()) {
            return "EMPTY_KEY";
        }

        if (keyString.length() < 16) {
            return "KEY_TOO_SHORT";
        }

        return "VALID_KEY";
    }

    public long measureEncryptionTime(String plainText, String keyString, int iterations) {
        long startTime = System.nanoTime();

        for (int i = 0; i < iterations; i++) {
            encryptText(plainText, keyString);
        }

        long endTime = System.nanoTime();
        return (endTime - startTime) / 1_000_000;
    }

    public boolean isEncryptedDifferent(String plainText, String encrypted) {
        if (Objects.isNull(plainText) || Objects.isNull(encrypted)) {
            return false;
        }

        try {
            String plainTextBase64 = Base64.getEncoder().encodeToString(
                    plainText.getBytes(StandardCharsets.UTF_8)
            );
            return !plainTextBase64.equals(encrypted);
        } catch (Exception e) {
            return true;
        }
    }

    private byte[] generateKeyFromString(String keyString) {
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];

        System.arraycopy(keyBytes, 0, key, 0, Math.min(keyBytes.length, key.length));

        if (keyBytes.length < key.length) {
            for (int i = keyBytes.length; i < key.length; i++) {
                key[i] = (byte) (i % 256);
            }
        }

        return key;
    }
}
