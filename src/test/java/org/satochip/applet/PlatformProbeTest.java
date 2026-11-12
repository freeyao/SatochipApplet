package org.satochip.applet;

import javacard.framework.AID;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Stage-1 platform probes (simulator only): what the JCardEngine simulator does for the platform
 * primitives the self-built ECDSA is going to rest on. Every probe is reported as a dynamic test
 * whose NAME carries the result, so the findings can be read straight from the Gradle log. The
 * probes never fail the build: they record behaviour, they do not assert it.
 *
 * <p>On a card these questions have to be asked of the card itself; nothing here says anything
 * about hardware.
 */
@DisplayName("Platform probes")
public class PlatformProbeTest {

  private static final byte[] PROBE_AID = "SatoProbe".getBytes();
  private static final String BC_UNSAFE_MOD = "org.bouncycastle.rsa.allow_unsafe_mod";

  // javacard constants, by value (JavaCard 3.0.4 / 3.0.5 API)
  private static final int RSA_PUBLIC = 4, RSA_PRIVATE = 5;
  private static final int MODE_DECRYPT = 1, MODE_ENCRYPT = 2;
  private static final int EC_PRIVATE = 12, EC_PRIVATE_TRANSIENT_RESET = 31;
  private static final int ALG_EC_SVDP_DH_PLAIN = 3, ALG_EC_PACE_GM = 5, ALG_EC_SVDP_DH_PLAIN_XY = 6;

  private static final BigInteger N = Vectors.SECP256K1_N;

  private CardChannel channel;
  private final List<DynamicTest> results = new ArrayList<>();

  @TestFactory
  List<DynamicTest> probes() throws Exception {
    Assumptions.assumeTrue("simulator".equals(System.getProperty("org.satochip.test.target", "card")),
        "platform probes run on the simulator only");

    JavaCardEngine engine = JavaCardEngine.create();
    engine.installApplet(new AID(PROBE_AID, (short) 0, (byte) PROBE_AID.length), ProbeApplet.class);
    channel = engine.toTerminalFactory().terminals().list().get(0).connect("*").getBasicChannel();
    ResponseAPDU sel = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PROBE_AID));
    if (sel.getSW() != 0x9000) {
      report("select probe applet: SW=" + Integer.toHexString(sel.getSW()));
      return results;
    }

    // ---- 1. RSA squaring exactly as Biginteger.init() does it: 768-bit modulus, exponent 2, 3 -> 9
    Field f = Biginteger.class.getDeclaredField("RSA_SQUARING_MODULUS");
    f.setAccessible(true);
    BigInteger sqMod = new BigInteger(1, (byte[]) f.get(null));
    BigInteger two = BigInteger.valueOf(2), three = BigInteger.valueOf(3);
    rsaCase("1a RSA square, applet's way (pub key, e=2, ENCRYPT, 3->9)", RSA_PUBLIC, MODE_ENCRYPT, sqMod, 96, two, three);
    rsaCase("1b RSA square, private key type (e=2, DECRYPT, 3->9)", RSA_PRIVATE, MODE_DECRYPT, sqMod, 96, two, three);
    rsaCase("1c RSA cube, control (pub key, e=3, ENCRYPT, 3->27)", RSA_PUBLIC, MODE_ENCRYPT, sqMod, 96, three, three);

    // ---- 2. modular exponentiation with an arbitrary exponent: x^(n-2) mod n = x^-1
    BigInteger x = new BigInteger("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
    BigInteger e = N.subtract(two);
    rsaCase("2a modexp mod n, n zero-padded to 512 bit (pub key, ENCRYPT)", RSA_PUBLIC, MODE_ENCRYPT, N, 64, e, x);
    rsaCase("2b modexp mod n, n zero-padded to 512 bit (private key, DECRYPT)", RSA_PRIVATE, MODE_DECRYPT, N, 64, e, x);
    // full-length odd multiple of n: N' = n*c, c a 256-bit prime; (x^e mod N') mod n = x^-1 mod n
    BigInteger c = BigInteger.ONE.shiftLeft(255).add(BigInteger.valueOf(12345)).nextProbablePrime();
    BigInteger nc = N.multiply(c);
    rsaCase("2c modexp mod n*c, 512-bit full-length modulus (pub key, ENCRYPT)", RSA_PUBLIC, MODE_ENCRYPT, nc, 64, e, x);
    rsaCase("2d modexp mod n*c, 512-bit full-length modulus (private key, DECRYPT)", RSA_PRIVATE, MODE_DECRYPT, nc, 64, e, x);

    // ---- 3./4. EC key agreement: with y, arbitrary base point, point addition
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPoint g = spec.getG();
    BigInteger k = new BigInteger("7a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff", 16);
    BigInteger w = new BigInteger("0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321", 16);
    ECPoint q = g.multiply(w).normalize();
    byte[] kG = g.multiply(k).normalize().getEncoded(false);
    byte[] kQ = q.multiply(k).normalize().getEncoded(false);
    byte[] kGplusQ = g.multiply(k).add(q).normalize().getEncoded(false);
    for (int keyType : new int[]{EC_PRIVATE, EC_PRIVATE_TRANSIENT_RESET}) {
      String kt = keyType == EC_PRIVATE ? "persistent key" : "transient(RESET) key";
      ecCase("3a ECDH with y (alg 6), base G, " + kt, ALG_EC_SVDP_DH_PLAIN_XY, keyType, k, g, kG);
      ecCase("3b ECDH with y (alg 6), arbitrary base Q, " + kt, ALG_EC_SVDP_DH_PLAIN_XY, keyType, k, q, kQ);
      ecCase("3c ECDH x only (alg 3), arbitrary base Q, " + kt, ALG_EC_SVDP_DH_PLAIN, keyType, k, q, Arrays.copyOfRange(kQ, 1, 33));
      ecCase("4  point addition ALG_EC_PACE_GM (alg 5): k*G + Q, " + kt, ALG_EC_PACE_GM, keyType, k, q, kGplusQ);
    }
    return results;
  }

  private void rsaCase(String name, int keyType, int mode, BigInteger modulus, int size, BigInteger exp, BigInteger in)
      throws Exception {
    String plain = rsaRun(keyType, mode, modulus, size, exp, in);
    if (plain.startsWith("OK")) {
      report(name + " => " + plain);
      return;
    }
    // BouncyCastle (under the simulator) validates RSA moduli; retry with its check switched off
    System.setProperty(BC_UNSAFE_MOD, "true");
    String relaxed;
    try {
      relaxed = rsaRun(keyType, mode, modulus, size, exp, in);
    } finally {
      System.clearProperty(BC_UNSAFE_MOD);
    }
    report(name + " => " + plain + " || with -D" + BC_UNSAFE_MOD + "=true: " + relaxed);
  }

  private String rsaRun(int keyType, int mode, BigInteger modulus, int size, BigInteger exp, BigInteger in)
      throws Exception {
    send(ProbeApplet.INS_SET_MODULUS, 0, 0, fixed(modulus, size));
    send(ProbeApplet.INS_SET_EXPONENT, 0, 0, exp.bitLength() <= 8 ? new byte[]{exp.byteValue()} : fixed(exp, 32));
    byte[] r = send(ProbeApplet.INS_RSA, keyType, mode, fixed(in, size));
    if (r.length == 0) return "NO DATA";
    byte[] body = Arrays.copyOfRange(r, 1, r.length);
    if (r[0] != 0x00) return "THROWS [" + new String(body) + "]";
    BigInteger got = new BigInteger(1, body);
    BigInteger want = in.modPow(exp, modulus);
    String verdict = got.equals(want) ? "OK, correct" : "WRONG RESULT got=" + got.toString(16) + " want=" + want.toString(16);
    return verdict + " (output " + body.length + " bytes)";
  }

  private void ecCase(String name, int alg, int keyType, BigInteger scalar, ECPoint point, byte[] want) throws Exception {
    byte[] data = new byte[97];
    System.arraycopy(fixed(scalar, 32), 0, data, 0, 32);
    System.arraycopy(point.getEncoded(false), 0, data, 32, 65);
    byte[] r = send(ProbeApplet.INS_EC, alg, keyType, data);
    String res;
    if (r.length == 0) {
      res = "NO DATA";
    } else {
      byte[] body = Arrays.copyOfRange(r, 1, r.length);
      if (r[0] != 0x00) res = "THROWS [" + new String(body) + "]";
      else if (Arrays.equals(body, want)) res = "OK, correct (output " + body.length + " bytes)";
      else res = "WRONG RESULT (" + body.length + " bytes) got=" + Hex.toHexString(body) + " want=" + Hex.toHexString(want);
    }
    report(name + " => " + res);
  }

  private byte[] send(int ins, int p1, int p2, byte[] data) throws Exception {
    ResponseAPDU r = channel.transmit(new CommandAPDU(0x80, ins & 0xFF, p1, p2, data, 256));
    if (r.getSW() != 0x9000) {
      return ("îSW=" + Integer.toHexString(r.getSW())).getBytes("ISO-8859-1");
    }
    return r.getData();
  }

  private void report(String line) {
    results.add(DynamicTest.dynamicTest(line, () -> { }));
  }

  private static byte[] fixed(BigInteger v, int size) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[size];
    int n = Math.min(raw.length, size);
    System.arraycopy(raw, raw.length - n, out, size - n, n);
    return out;
  }
}
