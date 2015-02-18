package com.duosecurity;

/**
 * Duo security integration code copied from: https://github.com/duosecurity/duo_java .
 * @author Duo Security
 */
public class DuoWebException extends Exception {

    private static final long serialVersionUID = 451949380095167112L;

    /**
     * Instantiates a new Duo web exception.
     *
     * @param message the message
     */
    public DuoWebException(final String message) {
        super(message);
    }
}
