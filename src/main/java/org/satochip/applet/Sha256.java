/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2026 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin  
 *               
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   
 */    

package org.satochip.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * SHA-256 with two interchangeable backends, selected once at install:
 * <ul>
 * <li>BACKEND_PLATFORM: the card's MessageDigest.ALG_SHA_256;</li>
 * <li>BACKEND_BYTECODE: the implementation below, in JavaCard bytecode.</li>
 * </ul>
 * It is used for the hashes that process the ECDSA private key and the nonce (the HMAC-SHA256 of
 * RFC 6979, see HmacSha256): with the bytecode backend these values never enter a platform
 * primitive. Callers do not know which backend is active.
 * <p>
 * The bytecode implementation follows FIPS 180-4 directly (it is not derived from another
 * code base). JavaCard has no 32-bit integers, so a 32-bit word is a pair of shorts (high half,
 * low half); the carry of a 16-bit addition is computed with bitwise operations only. There is no
 * branch and no table index that depends on the hashed data: the running time only depends on
 * the length of the input. Its speed on a card has to be measured.
 * <p>
 * Limits of the bytecode backend: a message is at most 8191 bytes (the length is kept in a
 * short); state lives in two transient arrays, about 170 bytes of RAM, allocated only
 * when this backend is selected.
 */
public class Sha256 {

    public static final byte BACKEND_PLATFORM = (byte) 0;
    public static final byte BACKEND_BYTECODE = (byte) 1;
    public static final short HASHSIZE = (short) 32;
    public static final short BLOCKSIZE = (short) 64;

    private static byte backend = BACKEND_PLATFORM;
    private static MessageDigest platform;

    // bytecode backend
    private static final short ST_H = (short) 0;      // 8 words: chaining value
    private static final short ST_W = (short) 16;     // 16 words: rolling message schedule
    private static final short ST_FILL = (short) 48;  // number of bytes waiting in block[]
    private static final short ST_TOTAL = (short) 49; // number of bytes hashed so far
    private static final short ST_SIZE = (short) 50;
    private static final short MAX_MESSAGE = (short) 8191;
    private static short[] st;
    private static byte[] block;

    private static final short[] H0 = {
        (short)0x6A09, (short)0xE667, (short)0xBB67, (short)0xAE85, (short)0x3C6E, (short)0xF372, (short)0xA54F, (short)0xF53A,
        (short)0x510E, (short)0x527F, (short)0x9B05, (short)0x688C, (short)0x1F83, (short)0xD9AB, (short)0x5BE0, (short)0xCD19
    };
    private static final short[] K = {
        (short)0x428A, (short)0x2F98, (short)0x7137, (short)0x4491, (short)0xB5C0, (short)0xFBCF, (short)0xE9B5, (short)0xDBA5,
        (short)0x3956, (short)0xC25B, (short)0x59F1, (short)0x11F1, (short)0x923F, (short)0x82A4, (short)0xAB1C, (short)0x5ED5,
        (short)0xD807, (short)0xAA98, (short)0x1283, (short)0x5B01, (short)0x2431, (short)0x85BE, (short)0x550C, (short)0x7DC3,
        (short)0x72BE, (short)0x5D74, (short)0x80DE, (short)0xB1FE, (short)0x9BDC, (short)0x06A7, (short)0xC19B, (short)0xF174,
        (short)0xE49B, (short)0x69C1, (short)0xEFBE, (short)0x4786, (short)0x0FC1, (short)0x9DC6, (short)0x240C, (short)0xA1CC,
        (short)0x2DE9, (short)0x2C6F, (short)0x4A74, (short)0x84AA, (short)0x5CB0, (short)0xA9DC, (short)0x76F9, (short)0x88DA,
        (short)0x983E, (short)0x5152, (short)0xA831, (short)0xC66D, (short)0xB003, (short)0x27C8, (short)0xBF59, (short)0x7FC7,
        (short)0xC6E0, (short)0x0BF3, (short)0xD5A7, (short)0x9147, (short)0x06CA, (short)0x6351, (short)0x1429, (short)0x2967,
        (short)0x27B7, (short)0x0A85, (short)0x2E1B, (short)0x2138, (short)0x4D2C, (short)0x6DFC, (short)0x5338, (short)0x0D13,
        (short)0x650A, (short)0x7354, (short)0x766A, (short)0x0ABB, (short)0x81C2, (short)0xC92E, (short)0x9272, (short)0x2C85,
        (short)0xA2BF, (short)0xE8A1, (short)0xA81A, (short)0x664B, (short)0xC24B, (short)0x8B70, (short)0xC76C, (short)0x51A3,
        (short)0xD192, (short)0xE819, (short)0xD699, (short)0x0624, (short)0xF40E, (short)0x3585, (short)0x106A, (short)0xA070,
        (short)0x19A4, (short)0xC116, (short)0x1E37, (short)0x6C08, (short)0x2748, (short)0x774C, (short)0x34B0, (short)0xBCB5,
        (short)0x391C, (short)0x0CB3, (short)0x4ED8, (short)0xAA4A, (short)0x5B9C, (short)0xCA4F, (short)0x682E, (short)0x6FF3,
        (short)0x748F, (short)0x82EE, (short)0x78A5, (short)0x636F, (short)0x84C8, (short)0x7814, (short)0x8CC7, (short)0x0208,
        (short)0x90BE, (short)0xFFFA, (short)0xA450, (short)0x6CEB, (short)0xBEF9, (short)0xA3F7, (short)0xC671, (short)0x78F2
    };

    /**
     * @param platformDigest a MessageDigest.ALG_SHA_256 instance, shared with the caller (the
     *        platform backend only uses it between reset() and doFinal())
     * @param selectedBackend BACKEND_PLATFORM or BACKEND_BYTECODE
     */
    public static void init(MessageDigest platformDigest, byte selectedBackend) {
        platform = platformDigest;
        backend = (selectedBackend == BACKEND_BYTECODE) ? BACKEND_BYTECODE : BACKEND_PLATFORM;
        if (backend == BACKEND_BYTECODE) {
            // RAM only: the state holds parts of secret messages. No persistent fallback.
            try {
                st = JCSystem.makeTransientShortArray(ST_SIZE, JCSystem.CLEAR_ON_DESELECT);
                block = JCSystem.makeTransientByteArray(BLOCKSIZE, JCSystem.CLEAR_ON_DESELECT);
            } catch (SystemException e) {
                st = JCSystem.makeTransientShortArray(ST_SIZE, JCSystem.CLEAR_ON_RESET);
                block = JCSystem.makeTransientByteArray(BLOCKSIZE, JCSystem.CLEAR_ON_RESET);
            }
        }
    }

    public static byte getBackend() {
        return backend;
    }

    public static void reset() {
        if (backend == BACKEND_PLATFORM) {
            platform.reset();
            return;
        }
        for (short i = (short) 0; i < (short) 16; i++) {
            st[(short) (ST_H + i)] = H0[i];
        }
        st[ST_FILL] = (short) 0;
        st[ST_TOTAL] = (short) 0;
    }

    public static void update(byte[] in, short off, short len) {
        if (backend == BACKEND_PLATFORM) {
            platform.update(in, off, len);
            return;
        }
        short fill = st[ST_FILL];
        short total = (short) (st[ST_TOTAL] + len);
        if (len < (short) 0 || total < (short) 0 || total > MAX_MESSAGE) {
            ISOException.throwIt(Satochip.SW_HMAC_UNSUPPORTED_MSGSIZE);
        }
        st[ST_TOTAL] = total;
        while (len > (short) 0) {
            short n = (short) (BLOCKSIZE - fill);
            if (n > len) {
                n = len;
            }
            Util.arrayCopyNonAtomic(in, off, block, fill, n);
            fill += n;
            off += n;
            len -= n;
            if (fill == BLOCKSIZE) {
                compress();
                fill = (short) 0;
            }
        }
        st[ST_FILL] = fill;
    }

    /**
     * Hashes the last part of the message and writes the 32-byte digest at out[outOff].
     * The engine is reset afterwards. in and out may overlap.
     * @return HASHSIZE
     */
    public static short doFinal(byte[] in, short off, short len, byte[] out, short outOff) {
        if (backend == BACKEND_PLATFORM) {
            return platform.doFinal(in, off, len, out, outOff);
        }
        update(in, off, len);
        short fill = st[ST_FILL];
        short total = st[ST_TOTAL];
        // padding: 0x80, zeros, then the message length in bits on 8 bytes
        block[fill] = (byte) 0x80;
        fill++;
        if (fill > (short) 56) {
            // fill can be 64 here: a zero-length fill at offset 64 is an error on some cards
            if (fill < BLOCKSIZE)
                Util.arrayFillNonAtomic(block, fill, (short) (BLOCKSIZE - fill), (byte) 0);
            compress();
            fill = (short) 0;
        }
        Util.arrayFillNonAtomic(block, fill, (short) (BLOCKSIZE - fill), (byte) 0);
        block[(short) 61] = (byte) ((total >> 13) & 0x07);
        block[(short) 62] = (byte) (total >> 5);
        block[(short) 63] = (byte) (total << 3);
        compress();
        for (short i = (short) 0; i < (short) 16; i++) {
            Util.setShort(out, (short) (outOff + (short) (i << 1)), st[(short) (ST_H + i)]);
        }
        clear();
        return HASHSIZE;
    }

    /** Erases the state of the bytecode backend (it may hold part of a secret message). */
    public static void clear() {
        if (backend == BACKEND_PLATFORM) {
            platform.reset();
            return;
        }
        for (short i = (short) 0; i < ST_SIZE; i++) {
            st[i] = (short) 0;
        }
        Util.arrayFillNonAtomic(block, (short) 0, BLOCKSIZE, (byte) 0);
    }

    /** The SHA-256 compression function, on block[0..64). */
    private static void compress() {
        short ah = st[(short) 0], al = st[(short) 1], bh = st[(short) 2], bl = st[(short) 3];
        short ch = st[(short) 4], cl = st[(short) 5], dh = st[(short) 6], dl = st[(short) 7];
        short eh = st[(short) 8], el = st[(short) 9], fh = st[(short) 10], fl = st[(short) 11];
        short gh = st[(short) 12], gl = st[(short) 13], hh = st[(short) 14], hl = st[(short) 15];
        short wh, wl, xh, xl, th, tl, uh, ul, s, c, j;

        for (short t = (short) 0; t < (short) 64; t++) {
            j = (short) (ST_W + (short) ((short) (t & 0x0F) << 1));
            if (t < (short) 16) {
                // the branch depends on the round number only
                wh = Util.getShort(block, (short) (t << 2));
                wl = Util.getShort(block, (short) ((short) (t << 2) + (short) 2));
            } else {
                // w[t] = s1(w[t-2]) + w[t-7] + s0(w[t-15]) + w[t-16]; w[t-16] is the slot being replaced
                wh = st[j];
                wl = st[(short) (j + (short) 1)];
                xh = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 14) & 0x0F) << 1))];
                xl = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 14) & 0x0F) << 1) + (short) 1)];
                th = (short)((short)((short)((xl >> 1) & 0x7FFF) | (short)(xh << 15)) ^ (short)((short)((xl >> 3) & 0x1FFF) | (short)(xh << 13)) ^ (short)((xh >> 10) & 0x003F));
                tl = (short)((short)((short)((xh >> 1) & 0x7FFF) | (short)(xl << 15)) ^ (short)((short)((xh >> 3) & 0x1FFF) | (short)(xl << 13)) ^ (short)((short)((xl >> 10) & 0x003F) | (short)(xh << 6)));
                s = (short)(wl + tl);
                c = (short)(((((wl & tl) | ((wl | tl) & ~s))) >> 15) & 1);
                wl = s;
                wh = (short)(wh + th + c);
                th = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 9) & 0x0F) << 1))];
                tl = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 9) & 0x0F) << 1) + (short) 1)];
                s = (short)(wl + tl);
                c = (short)(((((wl & tl) | ((wl | tl) & ~s))) >> 15) & 1);
                wl = s;
                wh = (short)(wh + th + c);
                xh = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 1) & 0x0F) << 1))];
                xl = st[(short) (ST_W + (short) ((short) ((short) (t + (short) 1) & 0x0F) << 1) + (short) 1)];
                th = (short)((short)((short)((xh >> 7) & 0x01FF) | (short)(xl << 9)) ^ (short)((short)((xl >> 2) & 0x3FFF) | (short)(xh << 14)) ^ (short)((xh >> 3) & 0x1FFF));
                tl = (short)((short)((short)((xl >> 7) & 0x01FF) | (short)(xh << 9)) ^ (short)((short)((xh >> 2) & 0x3FFF) | (short)(xl << 14)) ^ (short)((short)((xl >> 3) & 0x1FFF) | (short)(xh << 13)));
                s = (short)(wl + tl);
                c = (short)(((((wl & tl) | ((wl | tl) & ~s))) >> 15) & 1);
                wl = s;
                wh = (short)(wh + th + c);
            }
            st[j] = wh;
            st[(short) (j + (short) 1)] = wl;

            // T1 = h + S1(e) + Ch(e,f,g) + K[t] + w[t]
            th = hh;
            tl = hl;
            xh = (short)((short)((short)((eh >> 6) & 0x03FF) | (short)(el << 10)) ^ (short)((short)((eh >> 11) & 0x001F) | (short)(el << 5)) ^ (short)((short)((el >> 9) & 0x007F) | (short)(eh << 7)));
            xl = (short)((short)((short)((el >> 6) & 0x03FF) | (short)(eh << 10)) ^ (short)((short)((el >> 11) & 0x001F) | (short)(eh << 5)) ^ (short)((short)((eh >> 9) & 0x007F) | (short)(el << 7)));
            s = (short)(tl + xl);
            c = (short)(((((tl & xl) | ((tl | xl) & ~s))) >> 15) & 1);
            tl = s;
            th = (short)(th + xh + c);
            xh = (short) ((eh & fh) ^ (~eh & gh));
            xl = (short) ((el & fl) ^ (~el & gl));
            s = (short)(tl + xl);
            c = (short)(((((tl & xl) | ((tl | xl) & ~s))) >> 15) & 1);
            tl = s;
            th = (short)(th + xh + c);
            xh = K[(short) (t << 1)];
            xl = K[(short) ((short) (t << 1) + (short) 1)];
            s = (short)(tl + xl);
            c = (short)(((((tl & xl) | ((tl | xl) & ~s))) >> 15) & 1);
            tl = s;
            th = (short)(th + xh + c);
            s = (short)(tl + wl);
            c = (short)(((((tl & wl) | ((tl | wl) & ~s))) >> 15) & 1);
            tl = s;
            th = (short)(th + wh + c);

            // T2 = S0(a) + Maj(a,b,c)
            uh = (short)((short)((short)((ah >> 2) & 0x3FFF) | (short)(al << 14)) ^ (short)((short)((ah >> 13) & 0x0007) | (short)(al << 3)) ^ (short)((short)((al >> 6) & 0x03FF) | (short)(ah << 10)));
            ul = (short)((short)((short)((al >> 2) & 0x3FFF) | (short)(ah << 14)) ^ (short)((short)((al >> 13) & 0x0007) | (short)(ah << 3)) ^ (short)((short)((ah >> 6) & 0x03FF) | (short)(al << 10)));
            xh = (short) ((ah & bh) ^ (ah & ch) ^ (bh & ch));
            xl = (short) ((al & bl) ^ (al & cl) ^ (bl & cl));
            s = (short)(ul + xl);
            c = (short)(((((ul & xl) | ((ul | xl) & ~s))) >> 15) & 1);
            ul = s;
            uh = (short)(uh + xh + c);

            hh = gh; hl = gl;
            gh = fh; gl = fl;
            fh = eh; fl = el;
            // e = d + T1
            eh = dh; el = dl;
            s = (short)(el + tl);
            c = (short)(((((el & tl) | ((el | tl) & ~s))) >> 15) & 1);
            el = s;
            eh = (short)(eh + th + c);
            dh = ch; dl = cl;
            ch = bh; cl = bl;
            bh = ah; bl = al;
            // a = T1 + T2
            ah = th; al = tl;
            s = (short)(al + ul);
            c = (short)(((((al & ul) | ((al | ul) & ~s))) >> 15) & 1);
            al = s;
            ah = (short)(ah + uh + c);
        }

        // add the working variables to the chaining value
        xh = st[(short) 0]; xl = st[(short) 1];
        s = (short)(al + xl);
        c = (short)(((((al & xl) | ((al | xl) & ~s))) >> 15) & 1);
        al = s;
        ah = (short)(ah + xh + c);
        st[(short) 0] = ah; st[(short) 1] = al;
        xh = st[(short) 2]; xl = st[(short) 3];
        s = (short)(bl + xl);
        c = (short)(((((bl & xl) | ((bl | xl) & ~s))) >> 15) & 1);
        bl = s;
        bh = (short)(bh + xh + c);
        st[(short) 2] = bh; st[(short) 3] = bl;
        xh = st[(short) 4]; xl = st[(short) 5];
        s = (short)(cl + xl);
        c = (short)(((((cl & xl) | ((cl | xl) & ~s))) >> 15) & 1);
        cl = s;
        ch = (short)(ch + xh + c);
        st[(short) 4] = ch; st[(short) 5] = cl;
        xh = st[(short) 6]; xl = st[(short) 7];
        s = (short)(dl + xl);
        c = (short)(((((dl & xl) | ((dl | xl) & ~s))) >> 15) & 1);
        dl = s;
        dh = (short)(dh + xh + c);
        st[(short) 6] = dh; st[(short) 7] = dl;
        xh = st[(short) 8]; xl = st[(short) 9];
        s = (short)(el + xl);
        c = (short)(((((el & xl) | ((el | xl) & ~s))) >> 15) & 1);
        el = s;
        eh = (short)(eh + xh + c);
        st[(short) 8] = eh; st[(short) 9] = el;
        xh = st[(short) 10]; xl = st[(short) 11];
        s = (short)(fl + xl);
        c = (short)(((((fl & xl) | ((fl | xl) & ~s))) >> 15) & 1);
        fl = s;
        fh = (short)(fh + xh + c);
        st[(short) 10] = fh; st[(short) 11] = fl;
        xh = st[(short) 12]; xl = st[(short) 13];
        s = (short)(gl + xl);
        c = (short)(((((gl & xl) | ((gl | xl) & ~s))) >> 15) & 1);
        gl = s;
        gh = (short)(gh + xh + c);
        st[(short) 12] = gh; st[(short) 13] = gl;
        xh = st[(short) 14]; xl = st[(short) 15];
        s = (short)(hl + xl);
        c = (short)(((((hl & xl) | ((hl | xl) & ~s))) >> 15) & 1);
        hl = s;
        hh = (short)(hh + xh + c);
        st[(short) 14] = hh; st[(short) 15] = hl;
    }
}
