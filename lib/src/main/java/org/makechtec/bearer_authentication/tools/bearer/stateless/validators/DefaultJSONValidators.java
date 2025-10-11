package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.json.JSONObject;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

public enum DefaultJSONValidators implements GenericValidator<String> {

    JSON_NOT_EMPTY {
        @Override
        public boolean validate(String input) {

            var jsonInput = new JSONObject(input);

            return jsonInput.isEmpty();
        }

        @Override
        public String getErrorMessage() {
            return "The JSON is empty";
        }
    };

}
