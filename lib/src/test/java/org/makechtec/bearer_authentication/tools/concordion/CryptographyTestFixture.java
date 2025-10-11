package org.makechtec.bearer_authentication.tools.concordion;

import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.support.CryptoTestHelper;
import org.makechtec.bearer_authentication.tools.support.TestDataGenerator;

import java.util.Objects;

@RunWith(ConcordionRunner.class)
public class CryptographyTestFixture {

    private final CryptoTestHelper cryptoHelper;

    public CryptographyTestFixture() {
        this.cryptoHelper = new CryptoTestHelper();
    }

    public String encrypt(String plainText, String secretKey) {
        if (Objects.isNull(plainText) || Objects.isNull(secretKey)) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }
        return cryptoHelper.encryptText(plainText, secretKey);
    }

    public String decrypt(String encryptedText, String secretKey) {
        if (Objects.isNull(encryptedText) || Objects.isNull(secretKey)) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }
        return cryptoHelper.decryptText(encryptedText, secretKey);
    }

    public String testEncryption(String input, String key) {
        if (Objects.isNull(input) || Objects.isNull(key)) {
            return "NULL_INPUT";
        }

        String keyValidation = cryptoHelper.validateKeyFormat(key);
        if (!"VALID_KEY".equals(keyValidation)) {
            return keyValidation;
        }

        return cryptoHelper.testEncryptionRoundTrip(input, key);
    }

    public String testLargeText(String sizeType, String key) {
        try {
            int sizeInKb = switch (sizeType) {
                case "SMALL" -> 1;
                case "MEDIUM" -> 100;
                case "LARGE" -> 1024;
                case "EXTRA_LARGE" -> 10240;
                default -> throw new IllegalArgumentException("Unknown size type: " + sizeType);
            };

            String largeText = TestDataGenerator.generateLargeText(sizeInKb);
            return cryptoHelper.testEncryptionRoundTrip(largeText, key);
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public String testSpecialCharacters(String testType, String key) {
        try {
            String testText = switch (testType) {
                case "UTF8" -> TestDataGenerator.getUtf8TestString();
                case "SPECIAL_CHARS" -> TestDataGenerator.getSpecialCharsString();
                case "EMPTY" -> "";
                case "NULL" -> null;
                default -> throw new IllegalArgumentException("Unknown test type: " + testType);
            };

            if (Objects.isNull(testText)) {
                return "NULL_INPUT";
            }

            return cryptoHelper.testEncryptionRoundTrip(testText, key);
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public String testPerformance(String text, String key, int iterations) {
        try {
            long executionTime = cryptoHelper.measureEncryptionTime(text, key, iterations);
            long maxAllowedTime = iterations * 100;

            return executionTime <= maxAllowedTime ? "WITHIN_LIMIT" : "EXCEEDED_LIMIT";
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public boolean isDifferentFromPlaintext(String plaintext, String encrypted) {
        if (Objects.isNull(plaintext) || Objects.isNull(encrypted)) {
            return false;
        }
        return cryptoHelper.isEncryptedDifferent(plaintext, encrypted);
    }

    public String validateEncryptionSecurity(String plaintext, String key) {
        try {
            String encrypted1 = cryptoHelper.encryptText(plaintext, key);
            String encrypted2 = cryptoHelper.encryptText(plaintext, key);

            if (encrypted1.equals(encrypted2)) {
                return "IV_NOT_RANDOM";
            }

            String decrypted1 = cryptoHelper.decryptText(encrypted1, key);
            String decrypted2 = cryptoHelper.decryptText(encrypted2, key);

            if (plaintext.equals(decrypted1) && plaintext.equals(decrypted2)) {
                return "SECURE";
            } else {
                return "DECRYPTION_INCONSISTENT";
            }
        } catch (Exception e) {
            return "ERROR";
        }
    }

    // Método que falla intencionalmente para demostrar reportes de Concordion
    public String testIntentionalFailure(String input) {
        return "FAILURE"; // Siempre retorna FAILURE para generar fallos en reportes
    }
}
