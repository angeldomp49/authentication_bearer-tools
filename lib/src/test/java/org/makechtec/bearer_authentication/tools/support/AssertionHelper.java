package org.makechtec.bearer_authentication.tools.support;

import java.util.Objects;

public class AssertionHelper {

    public static String validateEncryptionResult(String original, String encrypted, String decrypted) {
        if (Objects.isNull(original) || Objects.isNull(encrypted) || Objects.isNull(decrypted)) {
            return "NULL_INPUT";
        }

        if (original.equals(encrypted)) {
            return "NOT_ENCRYPTED";
        }

        if (!original.equals(decrypted)) {
            return "DECRYPTION_FAILED";
        }

        return "SUCCESS";
    }

    public static String validateHashResult(String password, String hash1, String hash2, boolean verification) {
        if (Objects.isNull(password) || Objects.isNull(hash1) || Objects.isNull(hash2)) {
            return "NULL_INPUT";
        }

        if (hash1.equals(hash2)) {
            return "SALT_NOT_UNIQUE";
        }

        if (!verification) {
            return "VERIFICATION_FAILED";
        }

        return "SUCCESS";
    }

    public static String validateTokenResult(String token, boolean isValid, boolean hasExpired) {
        if (Objects.isNull(token)) {
            return "NULL_TOKEN";
        }

        if (token.isEmpty()) {
            return "EMPTY_TOKEN";
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return "INVALID_JWT_FORMAT";
        }

        if (hasExpired && isValid) {
            return "EXPIRED_BUT_VALID";
        }

        if (!hasExpired && !isValid) {
            return "NOT_EXPIRED_BUT_INVALID";
        }

        return isValid ? "VALID" : "INVALID";
    }

    public static String validatePerformance(long executionTime, long maxAllowedTime) {
        if (executionTime < 0) {
            return "INVALID_TIME";
        }

        return executionTime <= maxAllowedTime ? "WITHIN_LIMIT" : "EXCEEDED_LIMIT";
    }

    public static String validateSecurityProperty(String propertyName, Object value) {
        switch (propertyName) {
            case "TIMING_CONSISTENT":
                return validateTimingConsistency((Long[]) value);
            case "RANDOM_DISTRIBUTION":
                return validateRandomness((byte[]) value);
            case "NO_INFORMATION_LEAK":
                return validateNoInformationLeak((String) value);
            default:
                return "UNKNOWN_PROPERTY";
        }
    }

    private static String validateTimingConsistency(Long[] timings) {
        if (Objects.isNull(timings) || timings.length < 2) {
            return "INSUFFICIENT_DATA";
        }

        double mean = calculateMean(timings);
        double variance = calculateVariance(timings, mean);
        double coefficient = Math.sqrt(variance) / mean;

        return coefficient < 0.1 ? "CONSISTENT" : "INCONSISTENT";
    }

    private static String validateRandomness(byte[] data) {
        if (Objects.isNull(data) || data.length < 16) {
            return "INSUFFICIENT_DATA";
        }

        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }

        double expectedFreq = (double) data.length / 256;
        double chiSquare = 0;

        for (int freq : frequency) {
            double diff = freq - expectedFreq;
            chiSquare += (diff * diff) / expectedFreq;
        }

        return chiSquare < 293.25 ? "RANDOM" : "NOT_RANDOM";
    }

    private static String validateNoInformationLeak(String value) {
        if (Objects.isNull(value)) {
            return "NO_LEAK";
        }

        String lowerValue = value.toLowerCase();
        String[] sensitivePatterns = {"password", "secret", "key", "token", "hash"};

        for (String pattern : sensitivePatterns) {
            if (lowerValue.contains(pattern)) {
                return "INFORMATION_LEAK";
            }
        }

        return "NO_LEAK";
    }

    private static double calculateMean(Long[] values) {
        double sum = 0;
        for (Long value : values) {
            sum += value;
        }
        return sum / values.length;
    }

    private static double calculateVariance(Long[] values, double mean) {
        double sum = 0;
        for (Long value : values) {
            double diff = value - mean;
            sum += diff * diff;
        }
        return sum / values.length;
    }
}
