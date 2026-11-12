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

import javacard.framework.Util;

/**
 * HMAC-SHA256 (RFC 2104) assembled in software on top of Sha256, for 32-byte keys: the only use
 * is the RFC 6979 nonce derivation of the self-built ECDSA, where key and messages are secret.
 * Same construction as HmacSha160/HmacSha512, but the message is streamed (begin / update /
 * finish) instead of being copied to the scratch buffer, so its length is not bounded by it.
 * <p>
 * Because the hash is Sha256, the HMAC runs on whichever SHA-256 backend was selected at
 * install: with the bytecode backend, neither the key nor the message enters a platform
 * primitive.
 * <p>
 * Scratch: data[0..96), shared with the other HMAC helpers and with the blinded arithmetic of
 * Satochip (tmpBuffer). An HMAC computation must therefore not be interleaved with those.
 */
public class HmacSha256 {

    public static final short BLOCKSIZE = (short) 64;
    public static final short HASHSIZE = (short) 32;
    public static final short KEYSIZE = (short) 32;
    private static final short SCRATCH_SIZE = (short) (BLOCKSIZE + HASHSIZE);
    private static byte[] data;

    public static void init(byte[] tmp) {
        data = tmp;
    }

    /** Starts HMAC(key, ...) with the 32-byte key at key[keyOff]. */
    public static void begin(byte[] key, short keyOff) {
        padKey(key, keyOff, (byte) 0x36);
        Sha256.reset();
        Sha256.update(data, (short) 0, BLOCKSIZE);
    }

    /** Appends message bytes. */
    public static void update(byte[] msg, short msgOff, short msgLen) {
        Sha256.update(msg, msgOff, msgLen);
    }

    /**
     * Finishes the HMAC started with begin() and writes the 32-byte MAC at mac[macOff].
     * key must be the key given to begin(); mac may be the key itself (K = HMAC(K, ...)).
     * @return HASHSIZE
     */
    public static short finish(byte[] key, short keyOff, byte[] mac, short macOff) {
        // inner hash
        Sha256.doFinal(data, (short) 0, (short) 0, data, BLOCKSIZE);
        // outer hash
        padKey(key, keyOff, (byte) 0x5c);
        Sha256.reset();
        Sha256.doFinal(data, (short) 0, SCRATCH_SIZE, mac, macOff);
        // the scratch area holds key^opad and the inner hash
        Util.arrayFillNonAtomic(data, (short) 0, SCRATCH_SIZE, (byte) 0);
        return HASHSIZE;
    }

    /** data[0..64) = key ^ pad, zero-extended to the block size. */
    private static void padKey(byte[] key, short keyOff, byte pad) {
        for (short i = (short) 0; i < KEYSIZE; i++) {
            data[i] = (byte) (key[(short) (keyOff + i)] ^ pad);
        }
        Util.arrayFillNonAtomic(data, KEYSIZE, (short) (BLOCKSIZE - KEYSIZE), pad);
    }
}
