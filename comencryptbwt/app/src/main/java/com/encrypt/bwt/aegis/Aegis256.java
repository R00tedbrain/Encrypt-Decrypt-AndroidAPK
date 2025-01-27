//Aegis256.java
package com.encrypt.bwt.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Aegis256 is a class that implements the AEGIS-256 authenticated encryption
 * algorithm.
 */
public class Aegis256 {
    /**
     * Generates a random 256-bit key using a secure random number generator.
     *
     * @return the generated key as a byte array
     */
    public static byte[] keygen() {
        var key = new byte[32];
        var rng = new SecureRandom();
        rng.nextBytes(key);
        return key;
    }

    /**
     * Generates a random 256-bit nonce using a secure random number generator.
     *
     * @return the generated nonce as a byte array
     */
    public static byte[] noncegen() {
        var nonce = new byte[32];
        var rng = new SecureRandom();
        rng.nextBytes(nonce);
        return nonce;
    }

    AesBlock[] state = new AesBlock[6];

    int tag_length;

    public Aegis256(final byte[] key, final byte[] nonce, final int tag_length) throws InvalidParameterException {
        if (tag_length != 16 && tag_length != 32) {
            throw new InvalidParameterException("invalid tag length");
        }
        if (key.length != 32) {
            throw new InvalidParameterException("invalid key length");
        }
        if (nonce.length != 32) {
            throw new InvalidParameterException("invalid nonce length");
        }
        this.tag_length = tag_length;

        final byte[] c0_bytes = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90 - 256,
                0xe9 - 256, 0x79, 0x62 };
        final byte[] c1_bytes = { 0xdb - 256, 0x3d, 0x18, 0x55, 0x6d, 0xc2 - 256, 0x2f, 0xf1 - 256, 0x20, 0x11, 0x31,
                0x42, 0x73, 0xb5 - 256, 0x28, 0xdd - 256 };
        final AesBlock c0 = new AesBlock(c0_bytes);
        final AesBlock c1 = new AesBlock(c1_bytes);

        final AesBlock k0 = new AesBlock(Arrays.copyOfRange(key, 0, 16));
        final AesBlock k1 = new AesBlock(Arrays.copyOfRange(key, 16, 32));
        final AesBlock n0 = new AesBlock(Arrays.copyOfRange(nonce, 0, 16));
        final AesBlock n1 = new AesBlock(Arrays.copyOfRange(nonce, 16, 32));
        final AesBlock k0n0 = k0.xor(n0);
        final AesBlock k1n1 = k1.xor(n1);
        var s = this.state;
        s[0] = k0n0;
        s[1] = k1n1;
        s[2] = new AesBlock(c1);
        s[3] = new AesBlock(c0);
        s[4] = k0.xor(c0);
        s[5] = k1.xor(c1);
        for (int i = 0; i < 4; i++) {
            this.update(k0);
            this.update(k1);
            this.update(k0n0);
            this.update(k1n1);
        }
    }

    public AuthenticatedCiphertext encryptDetached(final byte[] msg, final byte[] ad) {
        var ciphertext = new byte[msg.length];
        var i = 0;
        if (ad != null) {
            for (; i + 16 <= ad.length; i += 16) {
                this.absorb(Arrays.copyOfRange(ad, i, i + 16));
            }
            if (ad.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < ad.length % 16; j++) {
                    pad[j] = ad[i + j];
                }
                this.absorb(pad);
            }
        }
        if (msg != null) {
            i = 0;
            for (; i + 16 <= msg.length; i += 16) {
                var ci = this.enc(Arrays.copyOfRange(msg, i, i + 16));
                for (var j = 0; j < 16; j++) {
                    ciphertext[i + j] = ci[j];
                }
            }
            if (msg.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < msg.length % 16; j++) {
                    pad[j] = msg[i + j];
                }
                var ci = this.enc(pad);
                for (var j = 0; j < msg.length % 16; j++) {
                    ciphertext[i + j] = ci[j];
                }
            }
        }
        final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

        return new AuthenticatedCiphertext(ciphertext, tag);
    }

    public byte[] encrypt(final byte[] msg, final byte[] ad) {
        var res = this.encryptDetached(msg, ad);
        var ciphertext = new byte[res.ct.length + res.tag.length];
        for (var i = 0; i < res.ct.length; i++) {
            ciphertext[i] = res.ct[i];
        }
        for (var i = 0; i < res.tag.length; i++) {
            ciphertext[res.ct.length + i] = res.tag[i];
        }
        return ciphertext;
    }

    public byte[] decryptDetached(final AuthenticatedCiphertext ac, final byte[] ad)
            throws VerificationFailedException {
        var i = 0;
        if (ad != null) {
            for (; i + 16 <= ad.length; i += 16) {
                this.absorb(Arrays.copyOfRange(ad, i, i + 16));
            }
            if (ad.length % 16 != 0) {
                var pad = new byte[16];
                Arrays.fill(pad, (byte) 0);
                for (var j = 0; j < ad.length % 16; j++) {
                    pad[j] = ad[i + j];
                }
                this.absorb(pad);
            }
        }
        var msg = new byte[ac.ct.length];
        i = 0;
        for (; i + 16 <= ac.ct.length; i += 16) {
            var xi = this.dec(Arrays.copyOfRange(ac.ct, i, i + 16));
            for (var j = 0; j < 16; j++) {
                msg[i + j] = xi[j];
            }
        }
        if (ac.ct.length % 16 != 0) {
            var xi = this.decLast(Arrays.copyOfRange(ac.ct, i, ac.ct.length));
            for (var j = 0; j < ac.ct.length % 16; j++) {
                msg[i + j] = xi[j];
            }
        }
        final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);
        var dt = (byte) 0;
        for (var j = 0; j < tag.length; j++) {
            dt |= tag[j] ^ ac.tag[j];
        }
        if (dt != 0) {
            throw new VerificationFailedException("verification failed");
        }
        return msg;
    }

    public byte[] decrypt(final byte[] ciphertext, final byte[] ad) throws VerificationFailedException {
        if (ciphertext.length < this.tag_length) {
            throw new VerificationFailedException("truncated ciphertext");
        }
        var ct = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - this.tag_length);
        var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - this.tag_length, ciphertext.length);
        return this.decryptDetached(new AuthenticatedCiphertext(ct, tag), ad);
    }

    @Override
    public String toString() {
        return "Aegis256 [state=" + Arrays.toString(state) + ", tag_length=" + tag_length + "]";
    }

    protected void update(final AesBlock m) {
        var s = this.state;
        final var tmp = new AesBlock(s[5]);
        s[5] = s[4].encrypt(s[5]);
        s[4] = s[3].encrypt(s[4]);
        s[3] = s[2].encrypt(s[3]);
        s[2] = s[1].encrypt(s[2]);
        s[1] = s[0].encrypt(s[1]);
        s[0] = tmp.encrypt(s[0]);

        s[0] = s[0].xor(m);
    }

    protected void absorb(byte[] ai) {
        assert ai.length == 16;
        final var t = new AesBlock(ai);
        this.update(t);
    }

    protected byte[] enc(byte[] xi) {
        assert xi.length == 16;
        var s = this.state;
        final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
        final var t = new AesBlock(xi);
        final var ci = t.xor(z).toBytes();
        this.update(t);
        return ci;
    }

    protected byte[] dec(byte[] ci) {
        assert ci.length == 16;
        var s = this.state;
        final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
        final var t = new AesBlock(ci);
        final var out = t.xor(z);
        this.update(out);
        return out.toBytes();
    }

    protected byte[] decLast(byte cn[]) {
        assert cn.length <= 16;
        var s = this.state;
        final var z = s[1].xor(s[4]).xor(s[5]).xor(s[2].and(s[3]));
        var pad = new byte[16];
        Arrays.fill(pad, (byte) 0);
        for (var i = 0; i < cn.length; i++) {
            pad[i] = cn[i];
        }
        final var t = new AesBlock(pad);
        final var out_bytes = t.xor(z).toBytes();
        for (var i = 0; i < 16; i++) {
            pad[i] = out_bytes[i];
        }
        var xn = new byte[cn.length];
        for (var i = 0; i < cn.length; i++) {
            xn[i] = pad[i];
        }
        for (var i = cn.length; i < 16; i++) {
            pad[i] = 0;
        }
        final var v = new AesBlock(pad);
        this.update(v);

        return xn;
    }

    protected byte[] mac(final int ad_len_bytes, final int msg_len_bytes) {
        var s = this.state;
        var bytes = new byte[16];

        final long ad_len = (long) ad_len_bytes * 8;
        final long msg_len = (long) msg_len_bytes * 8;

        bytes[0 * 8 + 0] = (byte) (ad_len >> 0);
        bytes[0 * 8 + 1] = (byte) (ad_len >> 8);
        bytes[0 * 8 + 2] = (byte) (ad_len >> 16);
        bytes[0 * 8 + 3] = (byte) (ad_len >> 24);
        bytes[0 * 8 + 4] = (byte) (ad_len >> 32);
        bytes[0 * 8 + 5] = (byte) (ad_len >> 40);
        bytes[0 * 8 + 6] = (byte) (ad_len >> 48);
        bytes[0 * 8 + 7] = (byte) (ad_len >> 56);

        bytes[1 * 8 + 0] = (byte) (msg_len >> 0);
        bytes[1 * 8 + 1] = (byte) (msg_len >> 8);
        bytes[1 * 8 + 2] = (byte) (msg_len >> 16);
        bytes[1 * 8 + 3] = (byte) (msg_len >> 24);
        bytes[1 * 8 + 4] = (byte) (msg_len >> 32);
        bytes[1 * 8 + 5] = (byte) (msg_len >> 40);
        bytes[1 * 8 + 6] = (byte) (msg_len >> 48);
        bytes[1 * 8 + 7] = (byte) (msg_len >> 56);

        final var t = s[3].xor(new AesBlock(bytes));
        for (var i = 0; i < 7; i++) {
            this.update(t);
        }

        if (this.tag_length == 16) {
            return s[0].xor(s[1]).xor(s[2]).xor(s[3]).xor(s[4]).xor(s[5]).toBytes();
        }
        assert this.tag_length == 32;
        var tag = new byte[32];
        final var t0 = s[0].xor(s[1]).xor(s[2]).toBytes();
        final var t1 = s[3].xor(s[4]).xor(s[5]).toBytes();
        for (var i = 0; i < 16; i++) {
            tag[i] = t0[i];
        }
        for (var i = 0; i < 16; i++) {
            tag[16 + i] = t1[i];
        }

        this.state = null;

        return tag;
    }
}