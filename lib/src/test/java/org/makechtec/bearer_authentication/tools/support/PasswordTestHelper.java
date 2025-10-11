package org.makechtec.bearer_authentication.tools.support;

import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class PasswordTestHelper {

    private final PasswordHasher passwordHasher;

    public PasswordTestHelper() {
        ArgonSettings settings = new ArgonSettings(65536, 3);
        this.passwordHasher = new PasswordHasherNative(settings);
    }

    public String hashPassword(String password) {
        if (Objects.isNull(password)) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        return passwordHasher.hash(password);
    }

    public boolean verifyPassword(String password, String hash) {
        if (Objects.isNull(password) || Objects.isNull(hash)) {
            return false;
        }
        return passwordHasher.matches(password, hash);
    }

    public String testPasswordHashing(String password, String testCase) {
        if (Objects.isNull(password)) {
            return "NULL_PASSWORD";
        }

        try {
            switch (testCase) {
                case "UNIQUE_SALT":
                    return testUniqueSalt(password);
                case "UTF8_SUPPORT":
                case "SPECIAL_CHARS":
                case "LONG_PASSWORD":
                    return testBasicHashing(password);
                case "TIMING_RESISTANCE":
                    return testTimingAttackResistance(password);
                case "MEMORY_HARD":
                    return testMemoryHardness(password);
                default:
                    return "UNKNOWN_TEST";
            }
        } catch (Exception e) {
            return "ERROR";
        }
    }

    public long measureHashingTime(String password, int iterations) {
        long startTime = System.nanoTime();

        for (int i = 0; i < iterations; i++) {
            passwordHasher.hash(password);
        }

        long endTime = System.nanoTime();
        return (endTime - startTime) / 1_000_000;
    }

    public String validateHashFormat(String hash) {
        if (Objects.isNull(hash)) {
            return "NULL_HASH";
        }

        if (hash.isEmpty()) {
            return "EMPTY_HASH";
        }

        if (!hash.startsWith("$argon2")) {
            return "INVALID_FORMAT";
        }

        if (hash.length() < 96) {
            return "INCOMPLETE_HASH";
        }

        return "VALID_HASH";
    }

    private String testUniqueSalt(String password) {
        String hash1 = passwordHasher.hash(password);
        String hash2 = passwordHasher.hash(password);

        if (hash1.equals(hash2)) {
            return "SALT_NOT_UNIQUE";
        }

        boolean verify1 = passwordHasher.matches(password, hash1);
        boolean verify2 = passwordHasher.matches(password, hash2);

        if (verify1 && verify2) {
            return "PASS";
        } else {
            return "VERIFICATION_FAILED";
        }
    }

    private String testBasicHashing(String password) {
        String hash = passwordHasher.hash(password);
        boolean verification = passwordHasher.matches(password, hash);
        boolean wrongVerification = passwordHasher.matches("wrongpassword", hash);

        if (verification && !wrongVerification) {
            return "PASS";
        } else {
            return "FAIL";
        }
    }

    private String testTimingAttackResistance(String password) {
        String correctHash = passwordHasher.hash(password);
        List<Long> correctTimes = new ArrayList<>();
        List<Long> incorrectTimes = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            long start = System.nanoTime();
            passwordHasher.matches(password, correctHash);
            long end = System.nanoTime();
            correctTimes.add(end - start);

            start = System.nanoTime();
            passwordHasher.matches("wrongpassword", correctHash);
            end = System.nanoTime();
            incorrectTimes.add(end - start);
        }

        double correctAvg = correctTimes.stream().mapToLong(Long::longValue).average().orElse(0);
        double incorrectAvg = incorrectTimes.stream().mapToLong(Long::longValue).average().orElse(0);

        double timeDiff = Math.abs(correctAvg - incorrectAvg) / Math.max(correctAvg, incorrectAvg);

        return timeDiff < 0.1 ? "PASS" : "TIMING_LEAK_DETECTED";
    }

    private String testMemoryHardness(String password) {
        try {
            String hash = passwordHasher.hash(password);
            return passwordHasher.matches(password, hash) ? "PASS" : "FAIL";
        } catch (OutOfMemoryError e) {
            return "MEMORY_EXHAUSTED";
        }
    }
}
