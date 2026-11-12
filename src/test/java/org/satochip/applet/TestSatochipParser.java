package org.satochip.applet;

import org.satochip.client.SatochipParser;
import org.satochip.io.APDUResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses the response formats of applet v0.17, in which the card returns full public keys
 * instead of an x coordinate and a self-signature:
 * <pre>
 * InitiateSecureChannel (0x81): [pubkey_size(2)=65 | pubkey(65) | sig_size(2) | authentikey-sig | coordx_size(2) | authentikey_coordx(32)]
 * getBIP32ExtendedKey   (0x6D): [chaincode(32) | pubkey_size(2)=65 | pubkey(65) | sig_size(2) | authentikey-sig]
 * </pre>
 * The Satochip-Java release the suite depends on only knows the formats up to v0.16, where the
 * public key is recovered from the self-signature. {@link TestSatochipCommandSet} installs this
 * parser in its place. A response in the old format (size field 32) is handed to the SDK parser,
 * so that scripts/benchmark-commits.sh can still drive applets built from older commits.
 *
 * <p>This is also the description of what a real client has to change: take the 65-byte key as
 * is, and check the authentikey signature over the bytes that precede its size field.
 */
public class TestSatochipParser extends SatochipParser {

  static final int PUBKEY_SIZE = 65;

  private static int size(byte[] data, int offset) {
    return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
  }

  /** The card's ephemeral public key, the first field of the response. */
  @Override
  public byte[] parseInitiateSecureChannel(APDUResponse rapdu) {
    byte[] data = rapdu.getData();
    if (size(data, 0) != PUBKEY_SIZE) {
      return super.parseInitiateSecureChannel(rapdu); // format up to v0.16
    }
    if (data[2] != 0x04) {
      throw new IllegalStateException("InitiateSecureChannel: not an uncompressed public key");
    }
    return Arrays.copyOfRange(data, 2, 2 + PUBKEY_SIZE);
  }

  /**
   * The authentikey: recovered from its signature of [pubkey_size | pubkey] and its x coordinate,
   * which also verifies that signature (recoverPubkey only returns a key the signature verifies under).
   */
  @Override
  public List<byte[]> parseInitiateSecureChannelGetPossibleAuthentikeys(APDUResponse rapdu) {
    byte[] data = rapdu.getData();
    if (size(data, 0) != PUBKEY_SIZE) {
      return super.parseInitiateSecureChannelGetPossibleAuthentikeys(rapdu); // format up to v0.16
    }
    int offset = 2 + PUBKEY_SIZE;
    byte[] signed = Arrays.copyOfRange(data, 0, offset);
    int sigSize = size(data, offset);
    byte[] sig = Arrays.copyOfRange(data, offset + 2, offset + 2 + sigSize);
    offset += 2 + sigSize;
    int coordxSize = size(data, offset);
    byte[] coordx = Arrays.copyOfRange(data, offset + 2, offset + 2 + coordxSize);
    if (coordxSize != 32 || offset + 2 + coordxSize != data.length) {
      throw new IllegalStateException("InitiateSecureChannel: unexpected response length");
    }
    List<byte[]> authentikeys = new ArrayList<>();
    authentikeys.add(recoverPubkey(signed, sig, coordx));
    return authentikeys;
  }

  /** {public key (65 bytes), chaincode (32 bytes)}, as the SDK parser returns them. */
  @Override
  public byte[][] parseBip32GetExtendedKey(APDUResponse rapdu) {
    byte[] data = rapdu.getData();
    if (size(data, 32) != PUBKEY_SIZE) {
      return super.parseBip32GetExtendedKey(rapdu); // format up to v0.16
    }
    byte[] chaincode = Arrays.copyOfRange(data, 0, 32);
    byte[] pubkey = Arrays.copyOfRange(data, 34, 34 + PUBKEY_SIZE);
    if (pubkey[0] != 0x04) {
      throw new IllegalStateException("getBIP32ExtendedKey: not an uncompressed public key");
    }
    return new byte[][]{pubkey, chaincode};
  }
}
