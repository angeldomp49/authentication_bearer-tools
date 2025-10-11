package org.makechtec.bearer_authentication.tools.concordion.support;

import java.util.Base64;

public class TestVectors {
    
    public static class AESTestVectors {
        public static final String NIST_KEY_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        public static final String NIST_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";
        public static final String NIST_IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        
        public static byte[] getNistKey256Bytes() {
            return hexStringToByteArray(NIST_KEY_256);
        }
        
        public static byte[] getNistPlaintextBytes() {
            return hexStringToByteArray(NIST_PLAINTEXT);
        }
        
        public static byte[] getNistIVBytes() {
            return hexStringToByteArray(NIST_IV);
        }
    }
    
    public static class Argon2TestVectors {
        public static final String RFC_PASSWORD = "password";
        public static final String RFC_SALT = "somesalt";
        public static final int RFC_ITERATIONS = 2;
        public static final int RFC_MEMORY = 65536;
        public static final int RFC_PARALLELISM = 1;
        public static final int RFC_HASH_LENGTH = 32;
        
        public static final String EXPECTED_HASH_PREFIX = "$argon2id$v=19$";
    }
    
    public static class HMACTestVectors {
        public static final String RFC_KEY = "key";
        public static final String RFC_MESSAGE = "The quick brown fox jumps over the lazy dog";
        public static final String RFC_EXPECTED_HMAC_SHA256 = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    }
    
    public static class JWTTestVectors {
        public static final String SAMPLE_SECRET = "your-256-bit-secret";
        public static final String SAMPLE_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        public static final String SAMPLE_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        
        public static String getValidJWTStructure() {
            return SAMPLE_HEADER + "." + SAMPLE_PAYLOAD + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        }
    }
    
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    public static String byteArrayToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    public static String generateBase64Key(int bytes) {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] key = new byte[bytes];
        random.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
    
    public static boolean isValidBase64(String input) {
        try {
            Base64.getDecoder().decode(input);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
