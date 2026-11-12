/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015-2026 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.satochip.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 * TEST-ONLY capability probe. It lives in the test source set, is never converted into the CAP
 * and is only ever installed in the JCardEngine simulator by {@link PlatformProbeTest}.
 *
 * <p>It answers one question per command: what does the platform do when asked for a raw RSA
 * exponentiation, or for an EC key agreement with a given algorithm number, key type and base
 * point? All inputs are public test values supplied by the test; no wallet key is involved.
 *
 * <p>Response: {@code 00 | output} on success, {@code EE | ascii message} when the platform threw.
 */
public class ProbeApplet extends Applet {

    static final byte INS_SET_MODULUS = (byte) 0x01;
    static final byte INS_SET_EXPONENT = (byte) 0x02;
    /** P1 = KeyBuilder RSA key type, P2 = Cipher mode, data = input block. */
    static final byte INS_RSA = (byte) 0x03;
    /** P1 = KeyAgreement algorithm number, P2 = KeyBuilder EC private key type, data = scalar(32) | point(65). */
    static final byte INS_EC = (byte) 0x10;

    private final byte[] modulus = new byte[128];
    private short modulusLen;
    private final byte[] exponent = new byte[128];
    private short exponentLen;
    private final byte[] out = new byte[256];

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ProbeApplet().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short len = apdu.setIncomingAndReceive();
        short off = ISO7816.OFFSET_CDATA;

        switch (ins) {
            case INS_SET_MODULUS:
                modulusLen = len;
                Util.arrayCopyNonAtomic(buf, off, modulus, (short) 0, len);
                return;
            case INS_SET_EXPONENT:
                exponentLen = len;
                Util.arrayCopyNonAtomic(buf, off, exponent, (short) 0, len);
                return;
            case INS_RSA:
                reply(apdu, rsa(p1, p2, buf, off, len));
                return;
            case INS_EC:
                reply(apdu, ec(p1, p2, buf, off, len));
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void reply(APDU apdu, short outLen) {
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(out, (short) 0, buf, (short) 0, outLen);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private short rsa(byte keyType, byte mode, byte[] in, short inOff, short inLen) {
        String stage = "buildKey";
        try {
            Key key = KeyBuilder.buildKey(keyType, (short) (modulusLen * 8), false);
            stage = "setModulus";
            if (keyType == KeyBuilder.TYPE_RSA_PUBLIC) {
                ((RSAPublicKey) key).setModulus(modulus, (short) 0, modulusLen);
                stage = "setExponent";
                ((RSAPublicKey) key).setExponent(exponent, (short) 0, exponentLen);
            } else {
                ((RSAPrivateKey) key).setModulus(modulus, (short) 0, modulusLen);
                stage = "setExponent";
                ((RSAPrivateKey) key).setExponent(exponent, (short) 0, exponentLen);
            }
            stage = "getInstance";
            Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            stage = "init";
            cipher.init(key, mode);
            stage = "doFinal";
            short n = cipher.doFinal(in, inOff, inLen, out, (short) 1);
            out[0] = (byte) 0x00;
            return (short) (n + 1);
        } catch (Throwable t) {
            return failure(stage, t);
        }
    }

    private short ec(byte alg, byte keyType, byte[] in, short inOff, short inLen) {
        String stage = "buildKey";
        try {
            ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(keyType, KeyBuilder.LENGTH_EC_FP_256, false);
            stage = "setCurve";
            Secp256k1.setCommonCurveParameters(key);
            stage = "setS";
            key.setS(in, inOff, (short) 32);
            stage = "getInstance";
            KeyAgreement ka = KeyAgreement.getInstance(alg, false);
            stage = "init";
            ka.init(key);
            stage = "generateSecret";
            short n = ka.generateSecret(in, (short) (inOff + 32), (short) (inLen - 32), out, (short) 1);
            out[0] = (byte) 0x00;
            return (short) (n + 1);
        } catch (Throwable t) {
            return failure(stage, t);
        }
    }

    private short failure(String stage, Throwable t) {
        String detail = (t instanceof CryptoException)
                ? "CryptoException reason=" + ((CryptoException) t).getReason()
                : t.getClass().getSimpleName() + " " + t.getMessage();
        byte[] msg = (stage + ": " + detail).getBytes();
        short n = (short) Math.min(msg.length, 200);
        out[0] = (byte) 0xEE;
        Util.arrayCopyNonAtomic(msg, (short) 0, out, (short) 1, n);
        return (short) (n + 1);
    }
}
