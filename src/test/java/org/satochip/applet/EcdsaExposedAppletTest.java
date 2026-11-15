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
import org.satochip.io.APDUResponse;
import org.bouncycastle.util.encoders.Hex;
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
        new byte[]{Sha256.BACKEND_BYTECODE, (byte) 0x01}); // and the bytecode multiplication

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
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    Satochip applet = (Satochip) engine.getApplet(new AID(aid, (short) 0, (byte) aid.length));
    assertEquals(Boolean.TRUE, field(applet, "mulBytecode"),
        "second install byte 0x01 must select the bytecode multiplication");
    // and GET_STATUS reports both
    byte[] status = cmd.cardGetStatus().getData();
    assertEquals(20, status.length);
    assertEquals(0x01, status[18], "GET_STATUS: SHA-256 backend");
    assertEquals(0x01, status[19], "GET_STATUS: multiplication backend");
    SatochipTest.checkBip461Vectors(cmd, SLOT, VECTOR_COUNT);
  }

  @Test
  @DisplayName("BIP340 signatures match the reference signer on the bytecode SHA-256 backend")
  void bip340OnBytecodeSha256Test() {
    // the nonce hash of SignSchnorrHash goes through the backend selected at install
    assertEquals(Sha256.BACKEND_BYTECODE, Sha256.getBackend());
    SatochipTest.checkBip340Reference(cmd, SLOT, 4);
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
    byte[] ecdsaRam = (byte[]) field(applet, "ecdsaRam");
    byte[] apdu = new byte[constant("ECDSA_APDU_SIZE")];
    // the verification reads the second copies of h and s
    System.arraycopy(h, 0, ecdsaRam, constant("ECDSA_RAM_H2"), 32);
    System.arraycopy(r, 0, apdu, constant("ECDSA_APDU_R") + 1, 32);
    System.arraycopy(s, 0, ecdsaRam, constant("ECDSA_RAM_S2"), 32);
    try {
      verify.invoke(applet, key, apdu);
      // the check must leave r and s untouched: they are encoded and output right after it
      assertArrayEquals(r, Arrays.copyOfRange(apdu, constant("ECDSA_APDU_R") + 1, constant("ECDSA_APDU_R") + 33));
      assertArrayEquals(s, Arrays.copyOfRange(ecdsaRam, constant("ECDSA_RAM_S2"), constant("ECDSA_RAM_S2") + 32));
      return SatochipTest.SW_OK;
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof ISOException) {
        return ((ISOException) e.getCause()).getReason() & 0xFFFF;
      }
      throw e;
    } finally {
      Arrays.fill(recvBuffer, (byte) 0);
      Arrays.fill(ecdsaRam, (byte) 0);
      Arrays.fill(tmpBuffer, (byte) 0);
    }
  }

  // ---- the Schnorr signature check, called directly --------------------------------------------

  @Test
  @DisplayName("The card's Schnorr signature check accepts the right signature and refuses any altered one")
  void schnorrVerifyRefusesAlteredSignaturesTest() throws Exception {
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    Satochip applet = (Satochip) engine.getApplet(new AID(aid, (short) 0, (byte) aid.length));
    assertNotNull(applet, "the exposed applet instance should be reachable");

    boolean sawOddP = false, sawEvenP = false;
    try {
      for (int i = 0; i < 6; i++) {
        String id = "key " + i;
        byte[] seckey = SatochipTest.sha256(("schnorr verify key " + i).getBytes());
        byte[] tweaked = SatochipTest.bip86TweakedKey(seckey);
        assertEquals(SatochipTest.SW_OK, SatochipTest.importSlotKey(cmd, SLOT, seckey), id);
        APDUResponse tweak = cmd.sendRawSecure(SatochipTest.INS_TAPROOT_TWEAK_PRIVKEY, SLOT, 0x00, new byte[]{0x00});
        assertEquals(SatochipTest.SW_OK, tweak.getSw(), id);
        // the verification must handle both: BIP340 always takes the even-y point for P
        if ((tweak.getData()[2 + 64] & 1) != 0) sawOddP = true; else sawEvenP = true;

        byte[] m = SatochipTest.sha256(("schnorr verify message " + i).getBytes());
        byte[] sig = SatochipTest.signBip340(tweaked, m, new byte[32]);
        byte[] r = Arrays.copyOfRange(sig, 0, 32);
        byte[] s = Arrays.copyOfRange(sig, 32, 64);

        assertEquals(SatochipTest.SW_OK, schnorrVerifyOnCard(applet, m, r, s), "valid signature, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m, r, flip(s, 31)), "s altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m, r, flip(s, 0)), "s altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m, flip(r, 31), s), "R altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m, flip(r, 5), s), "R altered, " + id);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, flip(m, 31), r, s), "message altered, " + id);
        // (R, n-s) is the signature with the nonce and the key negated: not valid in BIP340
        byte[] negS = Bip461.fixed32(Bip461.N.subtract(new BigInteger(1, s)));
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m, r, negS), "(R, n-s), " + id);
        // a valid signature of the same message under another key
        byte[] foreign = SatochipTest.signBip340(SatochipTest.sha256(("another key " + i).getBytes()), m, new byte[32]);
        assertEquals(SW_ECDSA_VERIFY_FAILED, schnorrVerifyOnCard(applet, m,
            Arrays.copyOfRange(foreign, 0, 32), Arrays.copyOfRange(foreign, 32, 64)), "other key, " + id);
        assertEquals(SatochipTest.SW_OK,
            cmd.sendRawSecure(SatochipTest.INS_RESET_KEY, SLOT, 0x00, new byte[0]).getSw());
      }
    } finally {
      cmd.sendRawSecure(SatochipTest.INS_RESET_KEY, SLOT, 0x00, new byte[0]);
    }
    assertTrue(sawOddP && sawEvenP, "the keys should cover both parities of y(P)");
    // the card still signs correctly after the direct calls
    SatochipTest.checkBip340Reference(cmd, SLOT, 2);
  }

  /**
   * Lays R, s and m out where signSchnorr() leaves them for schnorrVerify(), calls it, and
   * returns 0x9000 or the status word it threw. The scratch buffers are erased afterwards.
   */
  private static int schnorrVerifyOnCard(Satochip applet, byte[] m, byte[] r, byte[] s) throws Exception {
    Method verify = Satochip.class.getDeclaredMethod("schnorrVerify", byte[].class);
    verify.setAccessible(true);
    byte[] recvBuffer = (byte[]) field(applet, "recvBuffer");
    byte[] tmpBuffer = (byte[]) field(applet, "tmpBuffer");
    byte[] ecdsaRam = (byte[]) field(applet, "ecdsaRam");
    byte[] apdu = new byte[constant("SCHNORR_APDU_SIZE")];
    // the verification reads the second copies of m and s
    System.arraycopy(m, 0, ecdsaRam, constant("ECDSA_RAM_H2"), 32);
    System.arraycopy(r, 0, apdu, constant("ECDSA_APDU_R") + 1, 32);
    System.arraycopy(s, 0, ecdsaRam, constant("ECDSA_RAM_S2"), 32);
    try {
      verify.invoke(applet, (Object) apdu);
      assertArrayEquals(r, Arrays.copyOfRange(apdu, constant("ECDSA_APDU_R") + 1, constant("ECDSA_APDU_R") + 33));
      assertArrayEquals(s, Arrays.copyOfRange(ecdsaRam, constant("ECDSA_RAM_S2"), constant("ECDSA_RAM_S2") + 32));
      return SatochipTest.SW_OK;
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof ISOException) {
        return ((ISOException) e.getCause()).getReason() & 0xFFFF;
      }
      throw e;
    } finally {
      Arrays.fill(recvBuffer, (byte) 0);
      Arrays.fill(ecdsaRam, (byte) 0);
      Arrays.fill(tmpBuffer, (byte) 0);
    }
  }

  // ---- MuSig2 ---------------------------------------------------------------------------------

  /**
   * The NonceGen vectors of BIP327 (nonce_gen_vectors.json) that the card's input format can
   * express (a private key is given, the message is at most 32 bytes):
   * {rand_, sk, aggpk, msg, extra_in, expected_secnonce (k1 | k2 | pk), expected_pubnonce}.
   */
  static final String[][] BIP327_NONCE_GEN_VECTORS = {
      {"0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
       "0202020202020202020202020202020202020202020202020202020202020202",
       "0707070707070707070707070707070707070707070707070707070707070707",
       "0101010101010101010101010101010101010101010101010101010101010101",
       "0808080808080808080808080808080808080808080808080808080808080808",
       "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
       "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"},
      {"0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
       "0202020202020202020202020202020202020202020202020202020202020202",
       "0707070707070707070707070707070707070707070707070707070707070707",
       "",
       "0808080808080808080808080808080808080808080808080808080808080808",
       "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
       "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109"}
  };

  @Test
  @DisplayName("BIP327 NonceGen vectors are reproduced, and MuSig2 partial signatures verify, on the bytecode backends")
  void musig2NonceGenVectorsTest() throws Exception {
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    Satochip applet = (Satochip) engine.getApplet(new AID(aid, (short) 0, (byte) aid.length));
    Method nonceGen = Satochip.class.getDeclaredMethod("musig2NonceGen", byte[].class,
        javacard.security.ECPrivateKey.class, boolean.class);
    nonceGen.setAccessible(true);
    Method getSigningKey = Satochip.class.getDeclaredMethod("getSigningKey", byte.class);
    getSigningKey.setAccessible(true);
    byte[] recvBuffer = (byte[]) field(applet, "recvBuffer");
    byte[] slots = (byte[]) field(applet, "musig2Slots");
    int slotSize = constant("MUSIG2_SLOT_SIZE");
    int randOff = constant("OFFSET_BIP327_RAND");

    try {
      for (String[] v : BIP327_NONCE_GEN_VECTORS) {
        // the command draws rand' from the card and appends its counter to extra_in: the vectors
        // fix both, so the derivation is called directly, with the key of a slot
        assertEquals(SatochipTest.SW_OK, SatochipTest.importSlotKey(cmd, SLOT, Hex.decode(v[1])));
        Object key = getSigningKey.invoke(applet, (byte) SLOT);
        byte[] aggpk = Hex.decode(v[2]), msg = Hex.decode(v[3]), extra = Hex.decode(v[4]);
        byte[] data = SatochipTest.concat(new byte[]{(byte) aggpk.length}, aggpk, new byte[]{(byte) msg.length}, msg,
            new byte[]{(byte) extra.length}, extra);
        byte[] apdu = new byte[261];
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        System.arraycopy(Hex.decode(v[0]), 0, recvBuffer, randOff, 32);

        assertEquals((short) 68, nonceGen.invoke(applet, apdu, key, false));
        assertEquals(v[6], Hex.toHexString(apdu, 0, 66).toUpperCase(), "pubnonce");
        int id = ((apdu[66] & 0xff) << 8) | (apdu[67] & 0xff);
        int slot = (id & (constant("MUSIG2_NB_SLOTS") - 1)) * slotSize;
        // slot = [id | pk | k1 | k1 | k2 | k2]
        String secnonce = Hex.toHexString(slots, slot + 35, 32) + Hex.toHexString(slots, slot + 99, 32)
            + Hex.toHexString(slots, slot + 2, 33);
        assertEquals(v[5], secnonce.toUpperCase(), "secnonce");
        assertArrayEquals(Arrays.copyOfRange(slots, slot + 35, slot + 67), Arrays.copyOfRange(slots, slot + 67, slot + 99), "k1, twice");
        assertArrayEquals(Arrays.copyOfRange(slots, slot + 99, slot + 131), Arrays.copyOfRange(slots, slot + 131, slot + 163), "k2, twice");
        // nothing of the derivation is left in the working buffers
        assertArrayEquals(new byte[recvBuffer.length], recvBuffer, "recvBuffer erased");
        assertArrayEquals(new byte[((byte[]) field(applet, "ecdsaRam")).length], (byte[]) field(applet, "ecdsaRam"), "ecdsaRam erased");
      }
    } finally {
      cmd.sendRawSecure(SatochipTest.INS_RESET_KEY, SLOT, 0x00, new byte[0]);
    }

    // a secnonce whose two copies differ (one bit flipped in the card's memory) gives no
    // partial signature: the verification compares the two
    assertEquals(SatochipTest.SW_OK, cmd.cardBip32ImportSeed(Vectors.BIP32_SEED).getSw());
    cmd.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/3");
    byte[] ctx = SatochipTest.concat(SatochipTest.sha256("b".getBytes()), SatochipTest.sha256("ea".getBytes()), new byte[]{0x00, 0x01});
    for (int offset : new int[]{35 + 31, 67 + 0, 99 + 5, 131 + 31}) {
      APDUResponse init = cmd.sendRawSecure(SatochipTest.INS_MUSIG2_GENERATE_NONCE, 0xFF, SatochipTest.OP_INIT,
          new byte[]{0x00, (byte) 0xFF, 0x00});
      assertEquals(SatochipTest.SW_OK, init.getSw());
      byte[] id = Arrays.copyOfRange(init.getData(), 66, 68);
      int slot = (id[1] & (constant("MUSIG2_NB_SLOTS") - 1)) * slotSize;
      slots[slot + offset] ^= 0x04;
      assertEquals(SW_ECDSA_VERIFY_FAILED, cmd.sendRawSecure(SatochipTest.INS_MUSIG2_SIGN_HASH, 0xFF,
          SatochipTest.OP_FINALIZE, SatochipTest.concat(id, ctx)).getSw(), "slot byte " + offset + " altered");
      assertArrayEquals(new byte[slotSize], Arrays.copyOfRange(slots, slot, slot + slotSize), "the slot is erased all the same");
    }

    // and through the commands, on these backends
    SatochipTest.checkMusig2PartialSignatures(cmd);
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
