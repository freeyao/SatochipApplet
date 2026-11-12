package org.satochip.applet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Host-side helpers for the BIP461 (deterministic ECDSA) tests: the signing vectors, a strict DER
 * parser, and a transcription of the BIP's reference.py (nonce_rfc6979, sign, deterministic_sign)
 * used to compute the expected signature for keys that are not in the vector file, such as the
 * BIP32-derived ones. The transcription is itself checked against the vector file by
 * {@link SatochipTest}, so it is not an independent authority: the vectors are.
 */
final class Bip461 {
  private Bip461() { }

  static final BigInteger N = Vectors.SECP256K1_N;
  static final BigInteger HALF_N = N.subtract(BigInteger.ONE).shiftRight(1);

  /** One line of bip461_sign_vectors.csv. */
  static final class Vector {
    final byte[] seckey, msghash, sig;
    final String comment;
    Vector(byte[] seckey, byte[] msghash, byte[] sig, String comment) {
      this.seckey = seckey; this.msghash = msghash; this.sig = sig; this.comment = comment;
    }
  }

  /** The official BIP461 signing vectors, then vectors generated with the BIP's reference.py. */
  static List<Vector> vectors() throws Exception {
    List<Vector> out = new ArrayList<>();
    try (InputStream in = Bip461.class.getResourceAsStream("bip461_sign_vectors.csv")) {
      if (in == null) throw new IllegalStateException("bip461_sign_vectors.csv is not on the test classpath");
      BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
      String line = r.readLine(); // header
      while ((line = r.readLine()) != null) {
        if (line.isEmpty()) continue;
        String[] f = line.split(",", 4);
        out.add(new Vector(Hex.decode(f[0]), Hex.decode(f[1]), Hex.decode(f[2]), f.length > 3 ? f[3] : ""));
      }
    }
    return out;
  }

  /**
   * Parses a DER ECDSA signature into r | s (64 bytes), accepting only the one canonical encoding:
   * exact lengths, minimal integers, both positive. Throws IllegalArgumentException otherwise.
   */
  static byte[] parseStrictDer(byte[] der) {
    if (der.length < 8 || der.length > 72 || der[0] != 0x30 || (der[1] & 0xff) != der.length - 2) {
      throw new IllegalArgumentException("not a DER sequence of the announced length: " + Hex.toHexString(der));
    }
    byte[] out = new byte[64];
    int off = 2;
    for (int i = 0; i < 2; i++) {
      if (der[off] != 0x02) throw new IllegalArgumentException("integer tag expected at " + off);
      int len = der[off + 1] & 0xff;
      if (len < 1 || len > 33 || off + 2 + len > der.length) throw new IllegalArgumentException("bad integer length");
      byte[] v = Arrays.copyOfRange(der, off + 2, off + 2 + len);
      if ((v[0] & 0x80) != 0) throw new IllegalArgumentException("negative integer");
      if (len > 1 && v[0] == 0 && (v[1] & 0x80) == 0) throw new IllegalArgumentException("non-minimal integer");
      byte[] fixed = fixed32(new BigInteger(1, v));
      System.arraycopy(fixed, 0, out, 32 * i, 32);
      off += 2 + len;
    }
    if (off != der.length) throw new IllegalArgumentException("trailing bytes");
    return out;
  }

  static boolean isLowR(byte[] rs) { return (rs[0] & 0x80) == 0; }

  static boolean isLowS(byte[] rs) {
    return new BigInteger(1, Arrays.copyOfRange(rs, 32, 64)).compareTo(HALF_N) <= 0;
  }

  // ---- reference.py -----------------------------------------------------------------------------

  private static byte[] hmac(byte[] key, byte[]... parts) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    for (byte[] p : parts) mac.update(p);
    return mac.doFinal();
  }

  static byte[] nonceRfc6979(byte[] seckey, byte[] msghash, byte[] extra, int count) throws Exception {
    byte[] h = fixed32(new BigInteger(1, msghash).mod(N));
    byte[] v = new byte[32];
    Arrays.fill(v, (byte) 0x01);
    byte[] k = new byte[32];
    k = hmac(k, v, new byte[]{0x00}, seckey, h, extra);
    v = hmac(k, v);
    k = hmac(k, v, new byte[]{0x01}, seckey, h, extra);
    v = hmac(k, v);
    v = hmac(k, v);
    for (int i = 0; i < count; i++) {
      k = hmac(k, v, new byte[]{0x00});
      v = hmac(k, v);
      v = hmac(k, v);
    }
    return v;
  }

  private static BigInteger[] sign(byte[] seckey, byte[] msghash, byte[] extra) throws Exception {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    BigInteger d = new BigInteger(1, seckey);
    BigInteger z = new BigInteger(1, msghash);
    for (int count = 0; ; count++) {
      BigInteger k = new BigInteger(1, nonceRfc6979(seckey, msghash, extra, count));
      if (k.signum() == 0 || k.compareTo(N) >= 0) continue;
      BigInteger r = spec.getG().multiply(k).normalize().getAffineXCoord().toBigInteger().mod(N);
      if (r.signum() == 0) continue;
      BigInteger s = k.modInverse(N).multiply(d.multiply(r).add(z)).mod(N);
      if (s.signum() == 0) continue;
      return new BigInteger[]{r, s};
    }
  }

  /** The grind counter at which deterministic_sign() stops: 0 when the first nonce already gives a low r. */
  static int grindCount(byte[] seckey, byte[] msghash) throws Exception {
    int i = 0;
    BigInteger[] rs = sign(seckey, msghash, new byte[0]);
    while (rs[0].bitLength() > 255) {
      i++;
      byte[] extra = new byte[32];
      extra[0] = (byte) i; extra[1] = (byte) (i >> 8); extra[2] = (byte) (i >> 16); extra[3] = (byte) (i >> 24);
      rs = sign(seckey, msghash, extra);
    }
    return i;
  }

  /** BIP461 deterministic_sign(): r | s, low-r by grinding, low-S. */
  static byte[] deterministicSign(byte[] seckey, byte[] msghash) throws Exception {
    BigInteger[] rs = sign(seckey, msghash, new byte[0]);
    for (int i = 1; rs[0].bitLength() > 255; i++) {
      byte[] extra = new byte[32];
      extra[0] = (byte) i; extra[1] = (byte) (i >> 8); extra[2] = (byte) (i >> 16); extra[3] = (byte) (i >> 24);
      rs = sign(seckey, msghash, extra);
    }
    if (rs[1].compareTo(HALF_N) > 0) rs[1] = N.subtract(rs[1]);
    byte[] out = new byte[64];
    System.arraycopy(fixed32(rs[0]), 0, out, 0, 32);
    System.arraycopy(fixed32(rs[1]), 0, out, 32, 32);
    return out;
  }

  // ---- anti-exfil (secp256k1-zkp ecdsa_s2c) ----------------------------------------------------

  /** One line of antiexfil_vectors.csv, generated with secp256k1-zkp. */
  static final class AntiExfilVector {
    final byte[] seckey, msghash, rho, commitment, opening, sig;
    AntiExfilVector(String[] f) {
      seckey = Hex.decode(f[0]); msghash = Hex.decode(f[1]); rho = Hex.decode(f[2]);
      commitment = Hex.decode(f[3]); opening = Hex.decode(f[4]); sig = Hex.decode(f[5]);
    }
  }

  static List<AntiExfilVector> antiExfilVectors() throws Exception {
    List<AntiExfilVector> out = new ArrayList<>();
    try (InputStream in = Bip461.class.getResourceAsStream("antiexfil_vectors.csv")) {
      if (in == null) throw new IllegalStateException("antiexfil_vectors.csv is not on the test classpath");
      BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
      String line = r.readLine(); // header
      while ((line = r.readLine()) != null) {
        if (!line.isEmpty()) out.add(new AntiExfilVector(line.split(",")));
      }
    }
    return out;
  }

  /** BIP340-style tagged hash: SHA256(SHA256(tag) | SHA256(tag) | msg). */
  static byte[] taggedHash(String tag, byte[]... parts) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    byte[] t = md.digest(tag.getBytes(StandardCharsets.US_ASCII));
    md.update(t);
    md.update(t);
    for (byte[] p : parts) md.update(p);
    return md.digest();
  }

  /** What the host sends first: its commitment to rho. */
  static byte[] antiExfilCommitment(byte[] rho) throws Exception {
    return taggedHash("s2c/ecdsa/data", rho);
  }

  /**
   * The host's check of an anti-exfil signature (what secp256k1_anti_exfil_host_verify does on
   * top of the ordinary verification): x(R0 + t*G) mod n must be r, with
   * t = tagged_hash("s2c/ecdsa/point", R0 | rho).
   */
  static boolean antiExfilNonceCommitsTo(byte[] r0Compressed, byte[] rho, byte[] rs) throws Exception {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    BigInteger t = new BigInteger(1, taggedHash("s2c/ecdsa/point", r0Compressed, rho));
    if (t.compareTo(N) >= 0) return false;
    org.bouncycastle.math.ec.ECPoint r = spec.getCurve().decodePoint(r0Compressed).add(spec.getG().multiply(t)).normalize();
    if (r.isInfinity()) return false;
    return r.getAffineXCoord().toBigInteger().mod(N).equals(new BigInteger(1, Arrays.copyOfRange(rs, 0, 32)));
  }

  static byte[] fixed32(BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    int n = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - n, out, 32 - n, n);
    return out;
  }
}
