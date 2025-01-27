//authenticatedCipherText

package com.encrypt.bwt.aegis;

import java.util.Arrays;

/**
 * Represents an authenticated ciphertext, which consists of a ciphertext and a
 * tag.
 */
public class AuthenticatedCiphertext {
    public byte ct[];
    public byte tag[];

    /**
     * Constructs a new AuthenticatedCiphertext object with the given ciphertext and
     * tag.
     *
     * @param ct  the ciphertext
     * @param tag the tag
     */
    public AuthenticatedCiphertext(final byte ct[], final byte tag[]) {
        this.ct = ct;
        this.tag = tag;
    }

    @Override
    public String toString() {
        return "AuthenticatedCiphertext [ct=" + Arrays.toString(ct) + ", tag=" + Arrays.toString(tag) + "]";
    }
}