package org.makechtec.bearer_authentication.tools.bearer.stateless.aes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidationApplier;

import java.security.SecureRandom;

import static org.makechtec.bearer_authentication.tools.bearer.stateless.validators.DefaultBytesValidators.*;

public class TextCipher {
    
    private final GenericValidationApplier<byte[]> validationApplier;
    
    public TextCipher(){
        this.validationApplier = new GenericValidationApplier<>();
    }

    public TextCipher(GenericValidationApplier<byte[]> validationApplier) {
        this.validationApplier = validationApplier;
    }

    public byte[] encrypt(byte[] plaintext, byte[] key) throws InvalidCipherTextException {
        
        if(!validationApplier.applyAllValidations(plaintext, BYTES_NOT_NULL, BYTES_NOT_EMPTY)){
            
            var message = "Invalid plain text:" + validationApplier.getInvalidator().getErrorMessage();
            
            throw new IllegalArgumentException(message);
        }

        if(!validationApplier.applyAllValidations(key, BYTES_NOT_NULL, BYTES_NOT_EMPTY, BYTES_MIN_32)){

            var message = "Invalid key text:" + validationApplier.getInvalidator().getErrorMessage();

            throw new IllegalArgumentException(message);
        }

        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        KeyParameter keyParameter = new KeyParameter(key);
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        CipherParameters params = new AEADParameters(keyParameter, 128, iv, null);
        cipher.init(true, params);


        byte[] cipherText = new byte[cipher.getOutputSize(plaintext.length)];
        int len = cipher.processBytes(plaintext, 0, plaintext.length, cipherText, 0);
        cipher.doFinal(cipherText, len);

        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return combined;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key) throws InvalidCipherTextException {

        if(!validationApplier.applyAllValidations(ciphertext, BYTES_NOT_NULL, BYTES_NOT_EMPTY)){

            var message = "Invalid plain text:" + validationApplier.getInvalidator().getErrorMessage();

            throw new IllegalArgumentException(message);
        }

        if(!validationApplier.applyAllValidations(key, BYTES_NOT_NULL, BYTES_NOT_EMPTY, BYTES_MIN_32)){

            var message = "Invalid key text:" + validationApplier.getInvalidator().getErrorMessage();

            throw new IllegalArgumentException(message);
        }

        byte[] iv = Arrays.copyOfRange(ciphertext, 0, 12);
        byte[] cipherTextData = Arrays.copyOfRange(ciphertext, 12, ciphertext.length);

        KeyParameter keyParameter = new KeyParameter(key);
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        CipherParameters params = new AEADParameters(keyParameter, 128, iv, null);
        cipher.init(false, params);

        byte[] plaintext = new byte[cipher.getOutputSize(cipherTextData.length)];
        int len = cipher.processBytes(cipherTextData, 0, cipherTextData.length, plaintext, 0);
        cipher.doFinal(plaintext, len);

        return plaintext;
    }

}


