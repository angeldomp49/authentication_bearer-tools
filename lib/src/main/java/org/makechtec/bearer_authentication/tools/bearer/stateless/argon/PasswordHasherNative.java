package org.makechtec.bearer_authentication.tools.bearer.stateless.argon;

import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

public class PasswordHasherNative implements PasswordHasher {

    private final ArgonSettings crypographyInformation;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private static final int HASH_LENGTH_BYTES = 64;
    private static final int SALT_LENGTH_BYTES = 16;

    public PasswordHasherNative(ArgonSettings crypographyInformation) {
        this.crypographyInformation = crypographyInformation;
    }

    private static byte[] mergeArrays(byte[] array1, byte[] array2) {
        ByteBuffer buffer = ByteBuffer.allocate(array1.length + array2.length);
        buffer.put(array1);
        buffer.put(array2);
        return buffer.array();
    }

    @Override
    public byte[] rawHash(String password) {
        var salt = saltGenerator.generate();
        return rawHash(password, salt);
    }

    public byte[] rawHashNotIncludingSalt(String password, byte[] salt) {
        var argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id, SALT_LENGTH_BYTES, HASH_LENGTH_BYTES);

        return argon2.rawHash(
                crypographyInformation.iterations(),
                crypographyInformation.memoryInKb(),
                Runtime.getRuntime().availableProcessors(),
                password.toCharArray(),
                salt
        );
    }

    public byte[] rawHash(String password, byte[] salt) {

        var hash = rawHashNotIncludingSalt(password, salt);

        return mergeArrays(hash, salt);
    }

    @Override
    public String hash(String password) {
        return new String(Hex.encode(rawHash(password)));
    }

    public boolean matches(String originalUnhashed, String hashedToCompare) {
        var storedHash = Hex.decode(hashedToCompare);
        byte[] salt = Arrays.copyOfRange(storedHash, 64, storedHash.length);

        return MessageDigest.isEqual(rawHash(originalUnhashed, salt), storedHash);
    }

}
