package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

public enum DefaultStringValidators implements GenericValidator<String> {

    STRING_NOT_EMPTY {
        @Override
        public boolean validate(String input) {
            return !input.isEmpty();
        }

        @Override
        public String getErrorMessage() {
            return "The string is empty";
        }
    },
    STRING_NOT_NULL {
        @Override
        public boolean validate(String input) {
            return input != null;
        }

        @Override
        public String getErrorMessage() {
            return "The string is null";
        }
    };

}
