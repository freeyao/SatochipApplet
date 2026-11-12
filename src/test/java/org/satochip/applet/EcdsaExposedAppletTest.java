package org.satochip.applet;

import javacard.framework.AID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.satochip.desktop.PCSCCardChannel;
import pro.javacard.engine.JavaCardEngine;

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
}
