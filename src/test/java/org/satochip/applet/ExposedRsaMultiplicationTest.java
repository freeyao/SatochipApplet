package org.satochip.applet;

import javacard.framework.AID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.satochip.desktop.PCSCCardChannel;
import pro.javacard.engine.JavaCardEngine;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The fourth combination of the two install options: bytecode SHA-256 with the RSA squaring
 * engine for the multiplications (install data 01 00), on its own simulator instance
 * (simulator target only; skipped on a card).
 *
 * <p>{@link SatochipTest} runs platform SHA-256 with the RSA engine, and
 * {@link EcdsaExposedAppletTest} both bytecode backends. Platform SHA-256 with the bytecode
 * multiplication differs from the latter only in the hash, which the multiplications never see.
 * This class covers the combination that neither of them runs.
 */
@DisplayName("Exposed applet with the bytecode SHA-256 backend and the RSA multiplication backend")
public class ExposedRsaMultiplicationTest {

  static final int SLOT = 0;
  static final int VECTOR_COUNT = 30;

  private static JavaCardEngine engine;
  private static TestSatochipCommandSet cmd;

  @BeforeAll
  static void install() throws Exception {
    Assumptions.assumeTrue("simulator".equals(System.getProperty("org.satochip.test.target", "card")),
        "needs the simulator");
    engine = JavaCardEngine.create();
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    engine.installExposedApplet(new AID(aid, (short) 0, (byte) aid.length), Satochip.class,
        new byte[]{Sha256.BACKEND_BYTECODE, (byte) 0x00});

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
  @DisplayName("Install data 01 00 selects bytecode SHA-256 and the RSA engine, and GET_STATUS says so")
  void installOptionsTest() throws Exception {
    assertEquals(Sha256.BACKEND_BYTECODE, Sha256.getBackend());
    byte[] aid = SatochipTest.SATOCHIP_INSTANCE_AID;
    Satochip applet = (Satochip) engine.getApplet(new AID(aid, (short) 0, (byte) aid.length));
    Field f = Satochip.class.getDeclaredField("mulBytecode");
    f.setAccessible(true);
    assertEquals(Boolean.FALSE, f.get(applet), "second install byte 0x00 must select the RSA engine");
    byte[] status = cmd.cardGetStatus().getData();
    assertEquals(20, status.length);
    assertEquals(0x01, status[18], "GET_STATUS: SHA-256 backend");
    assertEquals(0x00, status[19], "GET_STATUS: multiplication backend");
  }

  @Test
  @DisplayName("The BIP461 vectors pass on bytecode SHA-256 with the RSA multiplication backend")
  void bip461VectorsTest() throws Exception {
    SatochipTest.checkBip461Vectors(cmd, SLOT, VECTOR_COUNT);
  }

  @Test
  @DisplayName("BIP340 signatures match the reference signer on bytecode SHA-256 with the RSA multiplication backend")
  void bip340ReferenceTest() {
    SatochipTest.checkBip340Reference(cmd, SLOT, 4);
  }

  @Test
  @DisplayName("MuSig2 partial signatures verify on bytecode SHA-256 with the RSA multiplication backend")
  void musig2PartialSignatureTest() {
    assertEquals(SatochipTest.SW_OK, cmd.cardBip32ImportSeed(Vectors.BIP32_SEED).getSw());
    SatochipTest.checkMusig2PartialSignatures(cmd);
  }
}
