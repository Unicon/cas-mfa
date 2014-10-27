package com.toopher.integrations.cas.authentication.handler;

import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * @author Misagh Moayyed
 */
public class ToopherAuthenticationException extends AuthenticationException {
    private static final long serialVersionUID = 355117992040392653L;

    public ToopherAuthenticationException(final String code, final String message, final String type) {
        super(code, message, type);
    }

    public static ToopherAuthenticationException getInstance() {
        return new ToopherAuthenticationException("toopher.authentication.error.unknown",
                "Unknown error returned by Toopher API", "toopherUnknownError");

    }


    public static class InvalidSignatureToopherException extends ToopherAuthenticationException {
        private static final long serialVersionUID = -1736771884688799597L;

        public InvalidSignatureToopherException(final String code, final String message, final String type) {
            super(code, message, type);
        }

        public static final InvalidSignatureToopherException getInstance() {
            return new InvalidSignatureToopherException("toopher.authentication.error.invalid_signature",
                    "Invalid signature returned by Toopher API", "toopherInvalidSignature");

        }
    }

    public static class PairingDeactivatedToopherException extends ToopherAuthenticationException {
        private static final long serialVersionUID = -1736771884688799597L;

        public PairingDeactivatedToopherException(final String code, final String message, final String type) {
            super(code, message, type);
        }

        public static final PairingDeactivatedToopherException getInstance() {
            return new PairingDeactivatedToopherException("toopher.authentication.error.pairing_deactivated",
                    "Pairing has been deactivated", "toopherPairingDeactivated");

        }
    }

    public static class UserOptOutToopherException extends ToopherAuthenticationException {
        private static final long serialVersionUID = -1736771884688799597L;

        public UserOptOutToopherException(final String code, final String message, final String type) {
            super(code, message, type);
        }

        public static final UserOptOutToopherException getInstance() {
            return new UserOptOutToopherException("toopher.authentication.error.user_opt_out",
                    "User has opted-out of Toopher Authentication", "toopherUserOptOut");

        }
    }

    public static class UnknownUserToopherException extends ToopherAuthenticationException {
        private static final long serialVersionUID = -1736771884688799597L;

        public UnknownUserToopherException(final String code, final String message, final String type) {
            super(code, message, type);
        }

        public static final UnknownUserToopherException getInstance() {
            return new UnknownUserToopherException("toopher.authentication.error.user_unknown",
                    "No matching user found in Toopher API", "toopherUserUnknown");

        }
    }

    public static class PairingNotAuthorizedToopherException extends ToopherAuthenticationException {
        private static final long serialVersionUID = -1736771884688799597L;

        public PairingNotAuthorizedToopherException(final String code, final String message, final String type) {
            super(code, message, type);
        }

        public static final PairingNotAuthorizedToopherException getInstance() {
            return new PairingNotAuthorizedToopherException("toopher.authentication.error.pairing_not_authorized",
                    "Pairing has not been authorized on the mobile device", "toopherPairingNotAuthorized");

        }
    }
}
