package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

import java.util.Base64;

public enum DefaultJWTTokenValidators implements GenericValidator<String> {

    TOKEN_WELL_FORMED {
        @Override
        public boolean validate(String input) {
            var parts = input.split("\\.");
            
            
            try{
                Base64.getDecoder().decode(parts[0]);
                Base64.getDecoder().decode(parts[1]);
            } catch (IllegalArgumentException e){
                return false;
            }
            
            return parts.length == 3;
        }

        @Override
        public String getErrorMessage() {
            return "The token is not well formed. It must have three parts separated by dots and the first two parts must be valid Base64 strings.";
        }
    };

}
