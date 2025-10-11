package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

public enum DefaultBytesValidators implements GenericValidator<byte[]> {
    
    BYTES_NOT_EMPTY {
        @Override
        public boolean validate(byte[] input) {
            return input.length > 0;
        }

        @Override
        public String getErrorMessage() {
            return "The byte array is empty";
        }
    },
    BYTES_MIN_32 {
        @Override
        public boolean validate(byte[] input) {
            return input.length >= 32;
        }

        @Override
        public String getErrorMessage() {
            return "The byte array is less than 32 bytes";
        }
    },
    BYTES_NOT_NULL {
        @Override
        public boolean validate(byte[] input) {
            return input != null;
        }

        @Override
        public String getErrorMessage() {
            return "The byte array is null";
        }
    };
    
}
