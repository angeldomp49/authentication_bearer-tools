package org.makechtec.bearer_authentication.tools.support;

import java.util.Arrays;
import java.util.Objects;

public class TestDataGenerator {

    public static String generateLongPassword(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive");
        }
        
        StringBuilder password = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(i % chars.length()));
        }
        
        return password.toString();
    }

    public static String generateLargeText(int sizeInKb) {
        if (sizeInKb <= 0) {
            throw new IllegalArgumentException("Size must be positive");
        }
        
        StringBuilder text = new StringBuilder();
        String pattern = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
        int targetLength = sizeInKb * 1024;
        
        while (text.length() < targetLength) {
            text.append(pattern);
        }
        
        return text.substring(0, targetLength);
    }

    public static byte[] generateKey(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Key length must be positive");
        }
        
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = (byte) ((i % 256) - 128);
        }
        return key;
    }

    public static String getUtf8TestString() {
        return "Hello 世界 🌍 Привет мир パスワード";
    }

    public static String getSpecialCharsString() {
        return "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
    }

    public static boolean areArraysEqual(byte[] array1, byte[] array2) {
        return Arrays.equals(array1, array2);
    }

    public static boolean isValidBase64(String str) {
        if (Objects.isNull(str) || str.isEmpty()) {
            return false;
        }
        
        try {
            java.util.Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
