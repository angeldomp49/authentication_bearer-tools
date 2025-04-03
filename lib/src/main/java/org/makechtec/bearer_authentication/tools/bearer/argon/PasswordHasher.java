package org.makechtec.bearer_authentication.tools.bearer.argon;

public interface PasswordHasher {
    byte[] rawHash(String password);

    byte[] rawHashNotIncludingSalt(String password, byte[] salt);

    byte[] rawHash(String password, byte[] salt);

    String hash(String password);

    boolean matches(String originalUnhashed, String hashedToCompare);
}
