//Aegis128L.java

package com.encrypt.bwt.aegis;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Aegis128L implements the AEGIS-128L authenticated encryption algorithm.
 */
public class Aegis128L {
    // Genera clave de 128 bits aleatoria
    public static byte[] keygen() {
        var key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    // Genera nonce de 128 bits aleatorio
    public static byte[] noncegen() {
        var nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    AesBlock[] state = new AesBlock[8];
    int tag_length;

    public Aegis128L(final byte[] key, final byte[] nonce, final int tag_length) throws InvalidParameterException {
        if (tag_length != 16 && tag_length != 32) {
            throw new InvalidParameterException("invalid tag length (must be 16 or 32 bytes)");
        }
        if (key.length != 16) {
            throw new InvalidParameterException("invalid key length (must be 16 bytes)");
        }
        if (nonce.length != 16) {
            throw new InvalidParameterException("invalid nonce length (must be 16 bytes)");
        }
        this.tag_length = tag_length;

        // c0 y c1 son constantes en AEGIS
        final byte[] c0_bytes = {
                0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                0x15, 0x22, 0x37, 0x59, (byte)0x90, (byte)0xe9, 0x79, 0x62
        };
        final byte[] c1_bytes = {
                (byte)0xdb, 0x3d, 0x18, 0x55, 0x6d, (byte)0xc2, 0x2f, (byte)0xf1,
                0x20, 0x11, 0x31, 0x42, 0x73, (byte)0xb5, 0x28, (byte)0xdd
        };

        final AesBlock c0 = new AesBlock(c0_bytes);
        final AesBlock c1 = new AesBlock(c1_bytes);

        final AesBlock key_block = new AesBlock(key);
        final AesBlock nonce_block = new AesBlock(nonce);

        var s = this.state;
        s[0] = key_block.xor(nonce_block);
        s[1] = new AesBlock(c1);
        s[2] = new AesBlock(c0);
        s[3] = new AesBlock(c1);
        s[4] = key_block.xor(nonce_block);
        s[5] = key_block.xor(c0);
        s[6] = key_block.xor(c1);
        s[7] = key_block.xor(c0);

        // 10 rondas
        for (int i = 0; i < 10; i++) {
            this.update(nonce_block, key_block);
        }
    }

    public AuthenticatedCiphertext encryptDetached(final byte[] msg, final byte[] ad) {
        var ciphertext = new byte[msg.length];

        // Absorber AD
        int i = 0;
        if (ad != null) {
            for (; i + 32 <= ad.length; i += 32) {
                absorb(Arrays.copyOfRange(ad, i, i + 32));
            }
            if (ad.length % 32 != 0) {
                var pad = new byte[32];
                Arrays.fill(pad, (byte)0);
                for (int j = 0; j < ad.length % 32; j++) {
                    pad[j] = ad[i + j];
                }
                absorb(pad);
            }
        }

        // Encriptar msg
        i = 0;
        if (msg != null) {
            for (; i + 32 <= msg.length; i += 32) {
                var block = Arrays.copyOfRange(msg, i, i + 32);
                var ci = this.enc(block);
                System.arraycopy(ci, 0, ciphertext, i, 32);
            }
            int leftover = msg.length % 32;
            if (leftover != 0) {
                var pad = new byte[32];
                Arrays.fill(pad, (byte)0);
                System.arraycopy(msg, i, pad, 0, leftover);
                var ci = this.enc(pad);
                // copio solo leftover bytes
                System.arraycopy(ci, 0, ciphertext, i, leftover);
            }
        }

        // Calcular tag
        final var tag = this.mac(ad == null ? 0 : ad.length, msg == null ? 0 : msg.length);

        return new AuthenticatedCiphertext(ciphertext, tag);
    }

    public byte[] encrypt(final byte[] msg, final byte[] ad) {
        var ac = encryptDetached(msg, ad);
        var out = new byte[ac.ct.length + ac.tag.length];
        System.arraycopy(ac.ct, 0, out, 0, ac.ct.length);
        System.arraycopy(ac.tag, 0, out, ac.ct.length, ac.tag.length);
        return out;
    }

    public byte[] decryptDetached(final AuthenticatedCiphertext ac, final byte[] ad)
            throws VerificationFailedException
    {
        // Absorber AD
        int i = 0;
        if (ad != null) {
            for (; i + 32 <= ad.length; i += 32) {
                absorb(Arrays.copyOfRange(ad, i, i + 32));
            }
            if (ad.length % 32 != 0) {
                var pad = new byte[32];
                Arrays.fill(pad, (byte)0);
                for (int j = 0; j < ad.length % 32; j++) {
                    pad[j] = ad[i + j];
                }
                absorb(pad);
            }
        }

        var msg = new byte[ac.ct.length];
        i = 0;
        for (; i + 32 <= ac.ct.length; i += 32) {
            var block = Arrays.copyOfRange(ac.ct, i, i + 32);
            var decblock = this.dec(block);
            System.arraycopy(decblock, 0, msg, i, 32);
        }
        int leftover = ac.ct.length % 32;
        if (leftover != 0) {
            var partial = Arrays.copyOfRange(ac.ct, i, ac.ct.length);
            var decPart = this.decLast(partial);
            System.arraycopy(decPart, 0, msg, i, leftover);
        }

        // Verificar tag
        var calcTag = this.mac(ad == null ? 0 : ad.length, msg.length);
        if (calcTag.length != ac.tag.length) {
            throw new VerificationFailedException("tag length mismatch");
        }
        byte diff = 0;
        for (int j = 0; j < calcTag.length; j++) {
            diff |= (byte)(calcTag[j] ^ ac.tag[j]);
        }
        if (diff != 0) {
            throw new VerificationFailedException("verification failed");
        }
        return msg;
    }

    public byte[] decrypt(final byte[] ciphertext, final byte[] ad)
            throws VerificationFailedException
    {
        if (ciphertext.length < this.tag_length) {
            throw new VerificationFailedException("truncated ciphertext");
        }
        var ct = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - this.tag_length);
        var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - this.tag_length, ciphertext.length);
        var ac = new AuthenticatedCiphertext(ct, tag);
        return decryptDetached(ac, ad);
    }

    @Override
    public String toString() {
        return "Aegis128L [tag_length=" + tag_length + "]";
    }

    // -------------------- Internos --------------------

    protected void update(final AesBlock m0, final AesBlock m1) {
        var s = this.state;
        final AesBlock tmp = new AesBlock(s[7]);
        s[7] = s[6].encrypt(s[7]);
        s[6] = s[5].encrypt(s[6]);
        s[5] = s[4].encrypt(s[5]);
        s[4] = s[3].encrypt(s[4]);
        s[3] = s[2].encrypt(s[3]);
        s[2] = s[1].encrypt(s[2]);
        s[1] = s[0].encrypt(s[1]);
        s[0] = tmp.encrypt(s[0]);

        s[4] = s[4].xor(m1);
        s[0] = s[0].xor(m0);
    }

    protected void absorb(byte[] ai) {
        // ai de 32 bytes
        final AesBlock t0 = new AesBlock(Arrays.copyOfRange(ai, 0, 16));
        final AesBlock t1 = new AesBlock(Arrays.copyOfRange(ai, 16, 32));
        this.update(t0, t1);
    }

    protected byte[] enc(byte[] block32) {
        var s = this.state;
        final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
        final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));

        final AesBlock t0 = new AesBlock(Arrays.copyOfRange(block32, 0, 16));
        final AesBlock t1 = new AesBlock(Arrays.copyOfRange(block32, 16, 32));

        var out0 = t0.xor(z0).toBytes();
        var out1 = t1.xor(z1).toBytes();

        this.update(t0, t1);
        var combined = new byte[32];
        System.arraycopy(out0, 0, combined, 0, 16);
        System.arraycopy(out1, 0, combined, 16, 16);
        return combined;
    }

    protected byte[] dec(byte[] block32) {
        var s = this.state;
        final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
        final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));

        final AesBlock c0 = new AesBlock(Arrays.copyOfRange(block32, 0, 16));
        final AesBlock c1 = new AesBlock(Arrays.copyOfRange(block32, 16, 32));

        var out0 = c0.xor(z0);
        var out1 = c1.xor(z1);

        this.update(out0, out1);

        var combined = new byte[32];
        System.arraycopy(out0.toBytes(), 0, combined, 0, 16);
        System.arraycopy(out1.toBytes(), 0, combined, 16, 16);
        return combined;
    }

    protected byte[] decLast(byte[] partial) {
        // partial < 32
        var s = this.state;
        final var z0 = s[6].xor(s[1]).xor(s[2].and(s[3]));
        final var z1 = s[2].xor(s[5]).xor(s[6].and(s[7]));

        var pad = new byte[32];
        Arrays.fill(pad, (byte)0);
        System.arraycopy(partial, 0, pad, 0, partial.length);

        final AesBlock c0 = new AesBlock(Arrays.copyOfRange(pad, 0, 16));
        final AesBlock c1 = new AesBlock(Arrays.copyOfRange(pad, 16, 32));

        var out0 = c0.xor(z0).toBytes();
        var out1 = c1.xor(z1).toBytes();

        // Reconstruct leftover
        var leftover = new byte[partial.length];
        System.arraycopy(out0, 0, leftover, 0, Math.min(16, partial.length));
        if (partial.length > 16) {
            int secondPart = partial.length - 16;
            System.arraycopy(out1, 0, leftover, 16, secondPart);
        }

        // Actualizar estado con el block completado
        for (int i = partial.length; i < 32; i++) {
            pad[i] = 0;
        }
        var v0 = new AesBlock(Arrays.copyOfRange(pad, 0, 16));
        var v1 = new AesBlock(Arrays.copyOfRange(pad, 16, 32));
        this.update(v0, v1);

        return leftover;
    }

    protected byte[] mac(final int ad_len_bytes, final int msg_len_bytes) {
        var s = this.state;
        var bytes = new byte[16];

        long adLenBits = ((long)ad_len_bytes) * 8;
        long msgLenBits = ((long)msg_len_bytes) * 8;

        // meter adLenBits en bytes[0..7], msgLenBits en bytes[8..15]
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte)(adLenBits >>> (8*i));
            bytes[8 + i] = (byte)(msgLenBits >>> (8*i));
        }

        final var t = s[2].xor(new AesBlock(bytes));
        // 7 updates
        for (int i = 0; i < 7; i++) {
            this.update(t, t);
        }

        if (this.tag_length == 16) {
            return s[0].xor(s[1]).xor(s[2]).xor(s[3])
                    .xor(s[4]).xor(s[5]).xor(s[6])
                    .toBytes();
        }
        // else => 32
        var tag = new byte[32];
        var t0 = s[0].xor(s[1]).xor(s[2]).xor(s[3]).toBytes();
        var t1 = s[4].xor(s[5]).xor(s[6]).xor(s[7]).toBytes();
        System.arraycopy(t0, 0, tag, 0, 16);
        System.arraycopy(t1, 0, tag, 16, 16);

        // Limpio state
        this.state = null;

        return tag;
    }
}
