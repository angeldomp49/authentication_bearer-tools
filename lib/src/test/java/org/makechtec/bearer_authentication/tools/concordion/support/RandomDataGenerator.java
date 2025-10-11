package org.makechtec.bearer_authentication.tools.concordion.support;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class RandomDataGenerator {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    private static final String UNICODE_CHARS = "áéíóúñüÁÉÍÓÚÑÜ测试тест";
    
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
    
    public static String generateRandomBase64Key(int keyLength) {
        byte[] key = generateRandomBytes(keyLength);
        return Base64.getEncoder().encodeToString(key);
    }
    
    public static String generateRandomPassword(int length) {
        StringBuilder password = new StringBuilder();
        String allChars = ALPHANUMERIC + SPECIAL_CHARS;
        
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(allChars.length());
            password.append(allChars.charAt(randomIndex));
        }
        
        return password.toString();
    }
    
    public static String generateRandomText(int length) {
        StringBuilder text = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(ALPHANUMERIC.length());
            text.append(ALPHANUMERIC.charAt(randomIndex));
        }
        
        return text.toString();
    }
    
    public static String generateRandomUnicodeText(int length) {
        StringBuilder text = new StringBuilder();
        String allChars = ALPHANUMERIC + UNICODE_CHARS;
        
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(allChars.length());
            text.append(allChars.charAt(randomIndex));
        }
        
        return text.toString();
    }
    
    public static String generateRandomUserId() {
        return "user_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }
    
    public static String generateRandomEmail() {
        String username = generateRandomText(8);
        String domain = generateRandomText(6);
        return username.toLowerCase() + "@" + domain.toLowerCase() + ".com";
    }
    
    public static String generateWeakPassword() {
        return "123456";
    }
    
    public static String generateStrongPassword() {
        StringBuilder password = new StringBuilder();
        
        password.append(ALPHANUMERIC.charAt(secureRandom.nextInt(26)));
        password.append(ALPHANUMERIC.charAt(26 + secureRandom.nextInt(26)));
        password.append("0123456789".charAt(secureRandom.nextInt(10)));
        password.append(SPECIAL_CHARS.charAt(secureRandom.nextInt(SPECIAL_CHARS.length())));
        
        for (int i = 4; i < 12; i++) {
            String allChars = ALPHANUMERIC + "0123456789" + SPECIAL_CHARS;
            password.append(allChars.charAt(secureRandom.nextInt(allChars.length())));
        }
        
        return shuffleString(password.toString());
    }
    
    private static String shuffleString(String input) {
        char[] chars = input.toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }
        return new String(chars);
    }
    
    public static String generateJWTSecret() {
        return generateRandomBase64Key(32);
    }
    
    public static String generateLargeText(int kilobytes) {
        int totalChars = kilobytes * 1024;
        StringBuilder text = new StringBuilder(totalChars);
        
        while (text.length() < totalChars) {
            text.append(generateRandomText(Math.min(1000, totalChars - text.length())));
        }
        
        return text.toString();
    }
    
    public static byte[] generateSalt() {
        return generateRandomBytes(16);
    }
    
    public static byte[] generateAESKey() {
        return generateRandomBytes(32);
    }
}
