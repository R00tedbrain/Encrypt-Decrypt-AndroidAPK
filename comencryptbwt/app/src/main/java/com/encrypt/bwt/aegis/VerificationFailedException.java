//VerificationFailedException

package com.encrypt.bwt.aegis;

/**
 * This exception is thrown when the verification of a ciphertext tag fails.
 */
public class VerificationFailedException extends Exception {
    /**
     * Constructs a new VerificationFailedException with the specified detail
     * message.
     *
     * @param message the detail message
     */
    public VerificationFailedException(String message) {
        super(message);
    }

    @Override
    public String toString() {
        return "VerificationFailedException []";
    }
}