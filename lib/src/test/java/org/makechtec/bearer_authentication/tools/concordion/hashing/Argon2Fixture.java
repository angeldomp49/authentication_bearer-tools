package org.makechtec.bearer_authentication.tools.concordion.hashing;

import org.concordion.api.ConcordionResources;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;

import java.util.regex.Pattern;

@RunWith(ConcordionRunner.class)
@ConcordionResources("css/concordion-custom.css")
public class Argon2Fixture {

    private final ArgonSettings defaultSettings = new ArgonSettings(65536, 3);
    private final PasswordHasherNative passwordHasher = new PasswordHasherNative(defaultSettings);
    private final SaltGenerator saltGenerator = new SaltGenerator();
    
    public String hashPassword(String password) {
        try {
            return passwordHasher.hash(password);
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String verifyPassword(String password, String hash) {
        try {
            boolean isValid = passwordHasher.matches(password, hash);
            return isValid ? "VALID" : "INVALID";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String validateHashFormat(String hash) {
        if (hash == null || hash.startsWith("ERROR:")) {
            return "INVALID_FORMAT";
        }
        
        // Check if it's a hex-encoded hash (current implementation)
        Pattern hexPattern = Pattern.compile("^[a-fA-F0-9]+$");
        return hexPattern.matcher(hash).matches() && hash.length() >= 128 ? "VALID_FORMAT" : "INVALID_FORMAT";
    }
    
    public String testRoundTripHashing(String password) {
        try {
            String hash = passwordHasher.hash(password);
            boolean isValid = passwordHasher.matches(password, hash);
            return isValid ? "SUCCESS" : "FAILED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String testWrongPassword(String correctPassword, String wrongPassword) {
        try {
            String hash = passwordHasher.hash(correctPassword);
            boolean isValid = passwordHasher.matches(wrongPassword, hash);
            return isValid ? "UNEXPECTED_VALID" : "CORRECTLY_REJECTED";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public boolean verifyHashUniqueness(String password, int iterations) {
        try {
            for (int i = 0; i < iterations - 1; i++) {
                String hash1 = passwordHasher.hash(password);
                String hash2 = passwordHasher.hash(password);
                
                if (hash1.equals(hash2)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    public String validateNullPassword() {
        try {
            passwordHasher.hash(null);
            return "NO_EXCEPTION";
        } catch (IllegalArgumentException e) {
            return "EXPECTED_EXCEPTION: " + e.getMessage();
        } catch (Exception e) {
            return "UNEXPECTED_EXCEPTION: " + e.getMessage();
        }
    }
    
    public String validateEmptyPassword() {
        try {
            String result = passwordHasher.hash("");
            return validateHashFormat(result).equals("VALID_FORMAT") ? "VALID_HASH" : "INVALID_HASH";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public String generateSalt() {
        try {
            byte[] salt = saltGenerator.generate();
            return salt.length == 16 ? "CORRECT_LENGTH" : "INCORRECT_LENGTH";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    public boolean verifySaltUniqueness(int iterations) {
        try {
            for (int i = 0; i < iterations - 1; i++) {
                byte[] salt1 = saltGenerator.generate();
                byte[] salt2 = saltGenerator.generate();
                
                if (java.util.Arrays.equals(salt1, salt2)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    public String testTimingAttackResistance(String password, String wrongPassword) {
        try {
            String hash = passwordHasher.hash(password);
            
            long startTime1 = System.nanoTime();
            passwordHasher.matches(password, hash);
            long duration1 = System.nanoTime() - startTime1;
            
            long startTime2 = System.nanoTime();
            passwordHasher.matches(wrongPassword, hash);
            long duration2 = System.nanoTime() - startTime2;
            
            double ratio = (double) Math.max(duration1, duration2) / Math.min(duration1, duration2);
            return ratio < 2.0 ? "TIMING_SAFE" : "TIMING_VULNERABLE";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}
