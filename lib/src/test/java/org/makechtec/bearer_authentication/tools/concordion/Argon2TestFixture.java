package org.makechtec.bearer_authentication.tools.concordion;

import org.concordion.api.FullOGNL;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import org.makechtec.bearer_authentication.tools.support.PasswordTestHelper;
import org.makechtec.bearer_authentication.tools.support.TestDataGenerator;

import java.util.Objects;

@FullOGNL
@RunWith(ConcordionRunner.class)
public class Argon2TestFixture {
    
    private final PasswordTestHelper passwordHelper;
    
    public Argon2TestFixture() {
        this.passwordHelper = new PasswordTestHelper();
    }
    
    public String hashPassword(String password) {
        if (Objects.isNull(password)) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        return passwordHelper.hashPassword(password);
    }
    
    public boolean verifyPassword(String password, String hash) {
        if (Objects.isNull(password) || Objects.isNull(hash)) {
            return false;
        }
        return passwordHelper.verifyPassword(password, hash);
    }
    
    // Método que falla intencionalmente para demostrar reportes
    public String testPasswordHashingWithFailure(String password, String testCase) {
        if ("FORCE_FAILURE".equals(testCase)) {
            return "FAIL"; // Falla intencionalmente
        }
        return passwordHelper.testPasswordHashing(password, testCase);
    }
    
    public String testIntentionalHashFailure() {
        return "EXPECTED_PASS"; // Siempre retorna un valor que no coincidirá con "FAIL" esperado
    }
    
    public String testLongPassword(int length) {
        try {
            String longPassword = TestDataGenerator.generateLongPassword(length);
            return passwordHelper.testPasswordHashing(longPassword, "LONG_PASSWORD");
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String validateHashFormat(String hash) {
        return passwordHelper.validateHashFormat(hash);
    }
    
    public String testSaltRandomness(String password, int iterations) {
        try {
            String[] hashes = new String[iterations];
            for (int i = 0; i < iterations; i++) {
                hashes[i] = passwordHelper.hashPassword(password);
            }
            
            for (int i = 0; i < iterations; i++) {
                for (int j = i + 1; j < iterations; j++) {
                    if (hashes[i].equals(hashes[j])) {
                        return "COLLISION_DETECTED";
                    }
                }
            }
            
            return "RANDOM";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public String testMemoryHardness(String password) {
        return passwordHelper.testPasswordHashing(password, "MEMORY_HARD");
    }
    
    public String testPasswordPerformance(String password, int iterations) {
        try {
            long executionTime = passwordHelper.measureHashingTime(password, iterations);
            long maxAllowedTime = iterations * 1000; // 1 second per iteration max
            
            return executionTime <= maxAllowedTime ? "WITHIN_LIMIT" : "EXCEEDED_LIMIT";
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    public boolean isDifferentFromPassword(String password, String hash) {
        if (Objects.isNull(password) || Objects.isNull(hash)) {
            return false;
        }
        return !password.equals(hash);
    }
}
