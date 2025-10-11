package org.makechtec.bearer_authentication.tools.bearer.stateless.validators;

import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.makechtec.bearer_authentication.tools.bearer.stateless.validation.GenericValidator;

public enum DefaultSessionValidators implements GenericValidator<SessionInformation> {

    SESSION_EXPIRATION_DATE_IN_FUTURE {
        @Override
        public boolean validate(SessionInformation input) {
            var currentTime = System.currentTimeMillis();
            return input.expirationDate().getTimeInMillis() > currentTime;
        }

        @Override
        public String getErrorMessage() {
            return "The string is empty";
        }
    },
    SESSION_NOT_NULL {
        @Override
        public boolean validate(SessionInformation input) {
            return input != null;
        }

        @Override
        public String getErrorMessage() {
            return "The string is null";
        }
    },
    SESSION_IS_NOT_CLOSED {
        @Override
        public boolean validate(SessionInformation input) {
            return !input.isClosed();
        }

        @Override
        public String getErrorMessage() {
            return "The session is closed";
        }
    },
    SESSION_AT_LEAST_ONE_PERMISSION {
        @Override
        public boolean validate(SessionInformation input) {
            return input.permissions() != null && !input.permissions().isEmpty();
        }

        @Override
        public String getErrorMessage() {
            return "The session has no permissions";
        }
    },
    SESSION_POSITIVE_USER_ID {
        @Override
        public boolean validate(SessionInformation input) {
            return input.userId() >= 0;
        }

        @Override
        public String getErrorMessage() {
            return "The user id is negative";
        }
    },
    SESSION_NOT_EMPTY_CLAIMS {
        @Override
        public boolean validate(SessionInformation input) {
            return input.claims() != null && !input.claims().isEmpty();
        }

        @Override
        public String getErrorMessage() {
            return "The session has no claims";
        }
    };


}
