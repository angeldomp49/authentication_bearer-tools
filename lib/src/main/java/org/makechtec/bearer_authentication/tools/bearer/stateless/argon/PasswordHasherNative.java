package org.makechtec.bearer_authentication.tools.bearer.stateless.argon;

import de.mkammerer.argon2.Argon2Factory;
import org.bouncycastle.util.encoders.Hex;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidationApplier;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultBytesValidators.BYTES_NOT_EMPTY;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultBytesValidators.BYTES_NOT_NULL;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_EMPTY;
import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultStringValidators.STRING_NOT_NULL;

public class PasswordHasherNative implements PasswordHasher {

    private static final int HASH_LENGTH_BYTES = 64;
    private static final int SALT_LENGTH_BYTES = 16;
    private final ArgonSettings cryptographyInformation;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final GenericValidationApplier<byte[]> bytesValidationApplier;
    private final GenericValidationApplier<String> stringValidationApplier;

    public PasswordHasherNative(ArgonSettings cryptographyInformation) {
        this.cryptographyInformation = cryptographyInformation;
        this.bytesValidationApplier = new GenericValidationApplier<>();
        this.stringValidationApplier = new GenericValidationApplier<>();
    }

    public PasswordHasherNative(ArgonSettings cryptographyInformation, GenericValidationApplier<byte[]> bytesValidationApplier, GenericValidationApplier<String> stringValidationApplier) {
        this.cryptographyInformation = cryptographyInformation;
        this.bytesValidationApplier = bytesValidationApplier;
        this.stringValidationApplier = stringValidationApplier;
    }

    private static byte[] mergeArrays(byte[] array1, byte[] array2) {

        var bytesValidationApplier = new GenericValidationApplier<byte[]>();

        if (!bytesValidationApplier.applyAllValidations(array1, BYTES_NOT_NULL, BYTES_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid first array:" + bytesValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!bytesValidationApplier.applyAllValidations(array2, BYTES_NOT_NULL, BYTES_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid second array:" + bytesValidationApplier.getInvalidator().getErrorMessage());
        }


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

        if (!bytesValidationApplier.applyAllValidations(salt, BYTES_NOT_NULL, BYTES_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid salt:" + bytesValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringValidationApplier.applyAllValidations(password, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        var argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id, SALT_LENGTH_BYTES, HASH_LENGTH_BYTES);

        return argon2.rawHash(
                cryptographyInformation.iterations(),
                cryptographyInformation.memoryInKb(),
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

        if (!stringValidationApplier.applyAllValidations(originalUnhashed, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid original unhashed password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringValidationApplier.applyAllValidations(hashedToCompare, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid hashed to compare password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        var storedHash = Hex.decode(hashedToCompare);
        byte[] salt = Arrays.copyOfRange(storedHash, 64, storedHash.length);

        return MessageDigest.isEqual(rawHash(originalUnhashed, salt), storedHash);
    }

    public String hashWithInformation(String password) {

        if (!stringValidationApplier.applyAllValidations(password, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        var salt = saltGenerator.generate();

        var cleanHash = rawHashNotIncludingSalt(password, salt);

        var algorithm = "argon2id";
        var version = "v=13";
        var memory = "m=" + cryptographyInformation.memoryInKb();
        var iterations = "t=" + cryptographyInformation.iterations();
        var parallelism = "p=" + Runtime.getRuntime().availableProcessors();

        return "$" + String.join(
                "$",
                algorithm,
                version,
                memory,
                iterations,
                parallelism,
                new String(Hex.encode(salt)),
                new String(Hex.encode(cleanHash))
        );
    }

    public boolean matchesWithInformation(String originalUnhashed, String hashedToCompare) {

        if (!stringValidationApplier.applyAllValidations(originalUnhashed, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid original unhashed password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        if (!stringValidationApplier.applyAllValidations(hashedToCompare, STRING_NOT_NULL, STRING_NOT_EMPTY)) {
            throw new IllegalArgumentException("Invalid hashed to compare password:" + stringValidationApplier.getInvalidator().getErrorMessage());
        }

        var hashedToBeingDecoded = hashedToCompare.split("\\$");
        var hashedDecoded = Hex.decode(hashedToBeingDecoded[6]);
        var salt = Hex.decode(hashedToBeingDecoded[5]);

        return MessageDigest.isEqual(rawHashNotIncludingSalt(originalUnhashed, salt), hashedDecoded);
    }

}
