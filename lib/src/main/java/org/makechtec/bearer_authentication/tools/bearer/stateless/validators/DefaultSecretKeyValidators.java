package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

public enum DefaultSecretKeyValidators implements GenericValidator<String> {
    
    SECRET_KEY_MIN_32_CHARS {
        @Override
        public boolean validate(String input) {
            return input.length() >= 32;
        }

        @Override
        public String getErrorMessage() {
            return "The string is less than 32 characters";
        }
    };
    
}
