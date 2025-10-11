package org.makechtec.bearer_authentication.tools.concordion.support;

import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

public class CryptoAssertions {
    
    public static boolean isValidArgon2Hash(String hash) {
        if (hash == null || hash.isEmpty()) {
            return false;
        }
        
        Pattern argon2Pattern = Pattern.compile(
            "^\\$argon2id\\$v=19\\$m=\\d+,t=\\d+,p=\\d+\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+$"
        );
        return argon2Pattern.matcher(hash).matches();
    }
    
    public static boolean isValidJWTStructure(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        
        try {
            Base64.getUrlDecoder().decode(parts[0]);
            Base64.getUrlDecoder().decode(parts[1]);
            Base64.getUrlDecoder().decode(parts[2]);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    
    public static boolean areByteArraysEqual(byte[] array1, byte[] array2) {
        return Arrays.equals(array1, array2);
    }
    
    public static boolean isValidEncryptionLength(byte[] encrypted, byte[] original, int ivLength) {
        if (encrypted == null || original == null) {
            return false;
        }
        return encrypted.length >= (original.length + ivLength + 16);
    }
    
    public static boolean hasUniqueIV(byte[] encrypted1, byte[] encrypted2, int ivLength) {
        if (encrypted1 == null || encrypted2 == null) {
            return false;
        }
        
        if (encrypted1.length < ivLength || encrypted2.length < ivLength) {
            return false;
        }
        
        byte[] iv1 = Arrays.copyOfRange(encrypted1, 0, ivLength);
        byte[] iv2 = Arrays.copyOfRange(encrypted2, 0, ivLength);
        
        return !Arrays.equals(iv1, iv2);
    }
    
    public static boolean isWithinTimeRange(long duration1, long duration2, double maxRatio) {
        if (duration1 <= 0 || duration2 <= 0) {
            return false;
        }
        
        double ratio = (double) Math.max(duration1, duration2) / Math.min(duration1, duration2);
        return ratio <= maxRatio;
    }
    
    public static boolean isValidSaltLength(byte[] salt, int expectedLength) {
        return salt != null && salt.length == expectedLength;
    }
    
    public static boolean isValidKeyLength(byte[] key, int expectedLength) {
        return key != null && key.length == expectedLength;
    }
    
    public static boolean containsExpectedErrorMessage(String actualMessage, String expectedPart) {
        if (actualMessage == null || expectedPart == null) {
            return false;
        }
        return actualMessage.toLowerCase().contains(expectedPart.toLowerCase());
    }
    
    public static boolean isSecureRandomDistribution(byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        
        double expectedFreq = (double) data.length / 256;
        double tolerance = expectedFreq * 0.5;
        
        for (int freq : frequency) {
            if (Math.abs(freq - expectedFreq) > tolerance) {
                return false;
            }
        }
        
        return true;
    }
    
    public static boolean isValidBase64Encoding(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        
        try {
            Base64.getDecoder().decode(input);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
