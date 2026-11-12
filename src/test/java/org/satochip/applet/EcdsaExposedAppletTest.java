package org.satochip.applet;

import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.satochip.desktop.PCSCCardChannel;
import pro.javacard.engine.JavaCardEngine;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests of the self-built ECDSA that need more than the APDU interface gives, on a second
 * simulator instance (simulator target only; skipped on a card).
 *
 * <p>The applet is installed <i>exposed</i>, i.e. without the class isolation the main suite
 * runs under, and with the install option that selects the bytecode SHA-256 backend. Two things
 * follow that {@link SatochipTest} cannot do:
 * <ul>
 * <li>the test can read which SHA-256 backend the installed applet really uses, and so prove
 *     that the BIP461 vectors pass on the bytecode backend (the main suite runs the platform
 *     one);</li>
 * <li>the test can call the applet's private signature check directly, to see it refuse a
 *     tampered signature: there is no APDU that makes the card sign wrongly, and none is added
 *     for testing.</li>
 * </ul>
 * The applet itself is unchanged: no test hook, no debug command.
 */
@DisplayName("Self-built ECDSA, exposed applet with the bytecode SHA-256 backend")
public class EcdsaExposedAppletTest {

  static final int SLOT = 0;
  /** Enough to cover the official vectors, the edge cases and many grinding depths. */
  static final int VECTOR_COUNT = 60;

  private static JavaCardEngine engine;
  private static TestSatochipCommandSet cmd;

  @BeforeAll
  static void install() throws Exception {
    Assumptions.assumeTrue("simulator".equals(System.getProperty("org.satochip.test.target", "card")),
        "needs the simulator");
    engine = JavaCardEngine.create();
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    engine.installExposedApplet(new AID(aid, (short) 0, (byte) aid.length), Satochip.class,
        new byte[]{Sha256.BACKEND_BYTECODE});

    cmd = new TestSatochipCommandSet(new PCSCCardChannel(
        engine.toTerminalFactory().terminals().list().get(0).connect("*").getBasicChannel()));
    cmd.setLoggerLevel("SEVERE");
    cmd.cardSelect().checkOK();
    SatochipTest.setupCard(cmd);
    cmd.setPin0(SatochipTest.PIN);
    assertEquals(SatochipTest.SW_OK,
        cmd.sendRawSecure(SatochipTest.INS_VERIFY_PIN, 0x00, 0x00, SatochipTest.PIN).getSw());
  }

  @Test
  @DisplayName("The install option selects the bytecode SHA-256, and the BIP461 vectors pass on it")
  void bip461VectorsOnBytecodeSha256Test() throws Exception {
    assertEquals(Sha256.BACKEND_BYTECODE, Sha256.getBackend(),
        "install data 0x01 must select the bytecode backend");
    SatochipTest.checkBip461Vectors(cmd, SLOT, VECTOR_COUNT);
  }

  // ---- the signature check, called directly ---------------------------------------------------

  static final int SW_ECDSA_VERIFY_FAILED = 0x9C4D;

  @Test
  @DisplayName("The card's signature check accepts the right signature and refuses any altered one")
  void ecdsaVerifyRefusesAlteredSignaturesTest() throws Exception {
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    Satochip applet = (Satochip) engine.getApplet(new AID(aid, (short) 0, (byte) aid.length));
    assertNotNull(applet, "the exposed applet instance should be reachable");
    Field eckeys = Satochip.class.getDeclaredField("eckeys");
    eckeys.setAccessible(true);

    List<Bip461.Vector> vectors = Bip461.vectors();
    // 0: grinding to counter 7; 2: msghash = 0 mod n, where u1 = 0 and no point addition is done;
    // 10: an ordinary one
    for (int index : new int[]{0, 2, 10}) {
      Bip461.Vector v = vectors.get(index);
      String id = "vector " + index;
      assertEquals(SatochipTest.SW_OK, SatochipTest.importSlotKey(cmd, SLOT, v.seckey), id);
      try {
        ECPrivateKey key = (ECPrivateKey) ((Key[]) eckeys.get(applet))[SLOT];
        byte[] h = Bip461.fixed32(new BigInteger(1, v.msghash).mod(Bip461.N));
        byte[] r = Arrays.copyOfRange(v.sig, 0, 32);
        byte[] s = Arrays.copyOfRange(v.sig, 32, 64);

        assertEquals(SatochipTest.SW_OK, verifyOnCard(applet, key, h, r, s), "valid signature, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, h, r, flip(s, 31)), "s altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, h, r, flip(s, 0)), "s altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, h, flip(r, 31), s), "r altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, h, flip(r, 5), s), "r altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, flip(h, 31), r, s), "hash altered, " + id);
        // the high-S twin (r, n-s) is a valid ECDSA signature too: the check is the textbook one
        byte[] highS = Bip461.fixed32(Bip461.N.subtract(new BigInteger(1, s)));
        assertEquals(SatochipTest.SW_OK, verifyOnCard(applet, key, h, r, highS), "(r, n-s), " + id);
        // a signature made with another key
        Bip461.Vector other = vectors.get(index + 1);
        byte[] foreign = Bip461.deterministicSign(other.seckey, v.msghash);
        assertEquals(SW_ECDSA_VERIFY_FAILED, verifyOnCard(applet, key, h,
            Arrays.copyOfRange(foreign, 0, 32), Arrays.copyOfRange(foreign, 32, 64)), "other key, " + id);
      } finally {
        cmd.sendRawSecure(SatochipTest.INS_RESET_KEY, SLOT, 0x00, new byte[0]);
      }
    }
    // the card still signs correctly after the direct calls
    SatochipTest.checkBip461Vectors(cmd, SLOT, 3);
  }

  /**
   * Lays r, s and h out where signEcdsa() leaves them for ecdsaVerify(), calls it, and returns
   * 0x9000 or the status word it threw. The scratch buffers are erased afterwards, as the
   * finally block of signEcdsa() would do.
   */
  private static int verifyOnCard(Satochip applet, ECPrivateKey key, byte[] h, byte[] r, byte[] s) throws Exception {
    Method verify = Satochip.class.getDeclaredMethod("ecdsaVerify", ECPrivateKey.class, byte[].class);
    verify.setAccessible(true);
    byte[] recvBuffer = (byte[]) field(applet, "recvBuffer");
    byte[] tmpBuffer = (byte[]) field(applet, "tmpBuffer");
    byte[] apdu = new byte[constant("ECDSA_APDU_SIZE")];
    System.arraycopy(h, 0, recvBuffer, constant("ECDSA_OFFSET_H"), 32);
    System.arraycopy(r, 0, apdu, constant("ECDSA_APDU_R") + 1, 32);
    System.arraycopy(s, 0, apdu, constant("ECDSA_APDU_T"), 32);
    try {
      verify.invoke(applet, key, apdu);
      // the check must leave r and s untouched: they are encoded and output right after it
      assertArrayEquals(r, Arrays.copyOfRange(apdu, constant("ECDSA_APDU_R") + 1, constant("ECDSA_APDU_R") + 33));
      assertArrayEquals(s, Arrays.copyOfRange(apdu, constant("ECDSA_APDU_T"), constant("ECDSA_APDU_T") + 32));
      return SatochipTest.SW_OK;
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof ISOException) {
        return ((ISOException) e.getCause()).getReason() & 0xFFFF;
      }
      throw e;
    } finally {
      Arrays.fill(recvBuffer, (byte) 0);
      Arrays.fill(tmpBuffer, (byte) 0);
    }
  }

  private static Object field(Satochip applet, String name) throws Exception {
    Field f = Satochip.class.getDeclaredField(name);
    f.setAccessible(true);
    return f.get(applet);
  }

  private static int constant(String name) throws Exception {
    Field f = Satochip.class.getDeclaredField(name);
    f.setAccessible(true);
    return f.getShort(null);
  }

  private static byte[] flip(byte[] in, int index) {
    byte[] out = in.clone();
    out[index] ^= 0x01;
    return out;
  }
}
