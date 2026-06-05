// deno-lint-ignore-file no-namespace

import { Curve, JacobianPoint, mod, modInv, modSqrt } from "./curve.js"
import {
  bigintToBytes32, bytes32ToBigint, bytesToHex, hexToBytes,
  concat, sha256, keccak256, randomScalar, rfc6979, toChecksumAddress,
} from "./utils.js"

// ─── Point ────────────────────────────────────────────────────────────────────

/**
 * An affine point on secp256k1.
 * Supports arithmetic, SEC1 serialisation, and casting to PublicKey.
 */
export class Point {
  constructor(
    readonly x: bigint,
    readonly y: bigint,
  ) {}

  /** The generator point G */
  static readonly G = new Point(Curve.Gx, Curve.Gy)

  /** The point at infinity (identity element) */
  static readonly ZERO = Symbol("Point.ZERO")

  /** Import from compressed (33 bytes, 02/03 prefix) or uncompressed (65 bytes, 04 prefix) SEC1 */
  static fromSec1(bytes: Uint8Array): Point {
    if ((bytes[0] ?? 0) === 0x04) {
      if (bytes.length !== 65) throw new Error("SEC1 uncompressed: expected 65 bytes")
      return new Point(bytes32ToBigint(bytes.slice(1, 33)), bytes32ToBigint(bytes.slice(33, 65)))
    }
    if ((bytes[0] ?? 0) === 0x02 || (bytes[0] ?? 0) === 0x03) {
      if (bytes.length !== 33) throw new Error("SEC1 compressed: expected 33 bytes")
      const x = bytes32ToBigint(bytes.slice(1))
      const { P, B } = Curve
      const y2 = mod(x * x * x + B, P)
      let y  = modSqrt(y2, P)
      const parity = (bytes[0] ?? 0) & 1
      if ((Number(y) & 1) !== parity) y = mod(-y, P)
      return new Point(x, y)
    }
    throw new Error("SEC1: invalid prefix byte")
  }

  /** Export to SEC1 compressed (33 bytes) */
  toCompressed(): Uint8Array {
    const prefix = (this.y & 1n) === 0n ? 0x02 : 0x03
    return concat(new Uint8Array([prefix]), bigintToBytes32(this.x))
  }

  /** Export to SEC1 uncompressed (65 bytes) */
  toUncompressed(): Uint8Array {
    return concat(new Uint8Array([0x04]), bigintToBytes32(this.x), bigintToBytes32(this.y))
  }

  /** Scalar multiplication */
  mul(scalar: bigint): Point {
    const j = new JacobianPoint(this.x, this.y, 1n).mul(scalar)
    if (j.isZero) throw new Error("Point.mul: result is point at infinity")
    const a = j.toAffine()
    return new Point(a.x, a.y)
  }

  /** Point addition */
  add(other: Point): Point {
    const j1 = new JacobianPoint(this.x, this.y, 1n)
    const j2 = new JacobianPoint(other.x, other.y, 1n)
    const r  = j1.add(j2)
    if (r.isZero) throw new Error("Point.add: result is point at infinity")
    const a = r.toAffine()
    return new Point(a.x, a.y)
  }

  /** Point subtraction */
  sub(other: Point): Point {
    return this.add(new Point(other.x, mod(-other.y, Curve.P)))
  }

  /** Negate a point */
  negate(): Point {
    return new Point(this.x, mod(-this.y, Curve.P))
  }

  equals(other: Point): boolean {
    return this.x === other.x && this.y === other.y
  }

  /** Cast to PublicKey */
  toPublicKey(): PublicKey {
    return new PublicKey(this)
  }

  toString(): string {
    return `Point(${this.x.toString(16)}, ${this.y.toString(16)})`
  }
}

// ─── SecretKey ────────────────────────────────────────────────────────────────

/**
 * A secp256k1 private key (32-byte scalar).
 *
 * @example
 * ```ts
 * const key = SecretKey.random()
 * const pub = key.toPublicKey()
 * const sig = await key.sign(msgHash)
 * ```
 */
export class SecretKey {
  constructor(readonly scalar: bigint) {
    if (scalar <= 0n || scalar >= Curve.N)
      throw new Error("SecretKey: scalar out of range [1, N-1]")
  }

  /** Generate a random secret key */
  static random(): SecretKey {
    return new SecretKey(randomScalar())
  }

  /** Import from 32 raw bytes */
  static fromBytes(bytes: Uint8Array): SecretKey {
    if (bytes.length !== 32) throw new Error("SecretKey: expected 32 bytes")
    return new SecretKey(bytes32ToBigint(bytes))
  }

  /** Import from a hex string (with or without 0x prefix) */
  static fromHex(hex: string): SecretKey {
    return SecretKey.fromBytes(hexToBytes(hex))
  }

  /** Derive a secret key from a BIP-39-style seed + index (HKDF-like) */
  static async fromSeed(seed: Uint8Array, index = 0): Promise<SecretKey> {
    const idx  = new Uint8Array(4)
    new DataView(idx.buffer).setUint32(0, index)
    const data = concat(seed, idx)
    const hash = await sha256(data)
    const n    = bytes32ToBigint(hash)
    return new SecretKey(mod(n, Curve.N - 1n) + 1n)
  }

  /** Export to 32 raw bytes */
  toBytes(): Uint8Array {
    return bigintToBytes32(this.scalar)
  }

  /** Export to hex string */
  toHex(): string {
    return bytesToHex(this.toBytes())
  }

  /** Derive the corresponding public key */
  toPublicKey(): PublicKey {
    const j = JacobianPoint.G.mul(this.scalar)
    const a = j.toAffine()
    return new PublicKey(new Point(a.x, a.y))
  }

  /**
   * Sign a 32-byte pre-hashed message (RFC 6979 deterministic ECDSA).
   * Returns a recoverable signature.
   */
  async sign(msgHash: Uint8Array): Promise<Signature> {
    if (msgHash.length !== 32) throw new Error("sign: msgHash must be 32 bytes")
    const z = bytes32ToBigint(msgHash)
    const k = await rfc6979(this.scalar, z)
    return this._signWithK(z, k)
  }

  /**
   * Sign with a random k (use only when you need a fresh nonce per sig).
   * Prefer `sign()` for deterministic behaviour.
   */
  signRandom(msgHash: Uint8Array): Signature {
    if (msgHash.length !== 32) throw new Error("signRandom: msgHash must be 32 bytes")
    const z = bytes32ToBigint(msgHash)
    const k = randomScalar()
    return this._signWithK(z, k)
  }

  private _signWithK(z: bigint, k: bigint): Signature {
    const { N } = Curve
    const R  = JacobianPoint.G.mul(k).toAffine()
    const r  = mod(R.x, N)
    if (r === 0n) throw new Error("sign: r = 0, retry with different k")
    const kinv = modInv(k, N)
    let s      = mod(kinv * (z + r * this.scalar), N)
    // Low-S normalisation (EIP-2)
    if (s > Curve.HALF_N) s = mod(-s, N)
    const v    = Number(R.y & 1n) ^ (s > Curve.HALF_N ? 1 : 0)
    return new Signature(r, s, v)
  }

  /** ECDH: compute a shared secret with another public key */
  ecdh(pub: PublicKey): Uint8Array {
    const shared = pub.point.mul(this.scalar)
    return bigintToBytes32(shared.x)
  }

  /** Tweak: add a scalar to this key (used in stealth / HD key derivation) */
  tweak(t: bigint): SecretKey {
    return new SecretKey(mod(this.scalar + t, Curve.N))
  }
}

// ─── PublicKey ────────────────────────────────────────────────────────────────

/**
 * A secp256k1 public key.
 *
 * @example
 * ```ts
 * const pub = key.toPublicKey()
 * const addr = pub.toEthAddress()
 * const ok = await sig.verify(msgHash, pub)
 * ```
 */
export class PublicKey {
  constructor(readonly point: Point) {}

  /** Import from SEC1 bytes (compressed 33 or uncompressed 65) */
  static fromSec1(bytes: Uint8Array): PublicKey {
    return new PublicKey(Point.fromSec1(bytes))
  }

  /** Import from hex string */
  static fromHex(hex: string): PublicKey {
    return PublicKey.fromSec1(hexToBytes(hex))
  }

  /**
   * Recover the public key from a recoverable signature and message hash.
   * Equivalent to `ecrecover` in Solidity.
   */
  static recover(msgHash: Uint8Array, sig: Signature): PublicKey {
    if (msgHash.length !== 32) throw new Error("recover: msgHash must be 32 bytes")
    const { N, P } = Curve
    const z = bytes32ToBigint(msgHash)
    const { r, s, v } = sig

    // Reconstruct R from r and parity bit v
    const x = r  // assume x < P (no overflow handling needed for standard keys)
    const y2 = mod(x * x * x + Curve.B, P)
    let y  = modSqrt(y2, P)
    if ((Number(y) & 1) !== v) y = mod(-y, P)
    const R = new Point(x, y)

    // pub = r⁻¹ · (s·R − z·G)
    const rinv = modInv(r, N)
    const sR   = R.mul(s)
    const zG   = Point.G.mul(mod(-z, N))
    const pub  = sR.add(zG).mul(rinv)
    return new PublicKey(pub)
  }

  /** Verify an ECDSA signature */
  async verify(msgHash: Uint8Array, sig: Signature): Promise<boolean> {
    try {
      const recovered = PublicKey.recover(msgHash, sig)
      return recovered.point.equals(this.point)
    } catch { return false }
  }

  /** Export to SEC1 compressed (33 bytes) */
  toCompressed(): Uint8Array {
    return this.point.toCompressed()
  }

  /** Export to SEC1 uncompressed (65 bytes) */
  toUncompressed(): Uint8Array {
    return this.point.toUncompressed()
  }

  /** Export to hex string (compressed by default) */
  toHex(compressed = true): string {
    return bytesToHex(compressed ? this.toCompressed() : this.toUncompressed())
  }

  /**
   * Derive the Ethereum address from this public key.
   * keccak256(uncompressed_pubkey[1:])[12:] — EIP-55 checksummed.
   */
  toEthAddress(): string {
    const uncompressed = this.toUncompressed().slice(1)  // drop 0x04
    const hash         = keccak256(uncompressed)
    const addr         = hash.slice(12)  // last 20 bytes
    return toChecksumAddress(addr)
  }

  /**
   * Tweak: add a scalar·G to this key (matching SecretKey.tweak).
   * Useful for stealth addresses, HD derivation, etc.
   */
  tweak(t: bigint): PublicKey {
    const tG = Point.G.mul(t)
    return new PublicKey(this.point.add(tG))
  }
}

// ─── Signature ───────────────────────────────────────────────────────────────

/**
 * A recoverable ECDSA signature (r, s, v).
 *
 * @example
 * ```ts
 * const sig = await key.sign(msgHash)
 * const rsv = sig.toRSV()          // 65 bytes
 * const der = sig.toDER()          // DER encoded
 * const pub = Signature.recover(msgHash, sig)
 * ```
 */
export class Signature {
  constructor(
    readonly r: bigint,
    readonly s: bigint,
    /** Recovery bit (0 or 1) */
    readonly v: number,
  ) {}

  /** Import from 65-byte RSV (r[32] + s[32] + v[1]) */
  static fromRSV(bytes: Uint8Array): Signature {
    if (bytes.length !== 65) throw new Error("Signature.fromRSV: expected 65 bytes")
    const r = bytes32ToBigint(bytes.slice(0, 32))
    const s = bytes32ToBigint(bytes.slice(32, 64))
    const v = bytes[64] ?? 0
    return new Signature(r, s, v)
  }

  /** Import from 65-byte VRS (v[1] + r[32] + s[32]) — Ethereum ecrecover format */
  static fromVRS(bytes: Uint8Array): Signature {
    if (bytes.length !== 65) throw new Error("Signature.fromVRS: expected 65 bytes")
    const b0 = bytes[0] ?? 0
    const v = b0 >= 27 ? b0 - 27 : b0
    const r = bytes32ToBigint(bytes.slice(1, 33))
    const s = bytes32ToBigint(bytes.slice(33, 65))
    return new Signature(r, s, v)
  }

  /** Export to 65-byte RSV */
  toRSV(): Uint8Array {
    return concat(bigintToBytes32(this.r), bigintToBytes32(this.s), new Uint8Array([this.v]))
  }

  /** Export to 65-byte VRS (v+27 Ethereum convention) */
  toVRS(): Uint8Array {
    return concat(new Uint8Array([this.v + 27]), bigintToBytes32(this.r), bigintToBytes32(this.s))
  }

  /** Export to hex string (RSV) */
  toHex(): string {
    return bytesToHex(this.toRSV())
  }

  /** DER encoding for EVM / standard tooling */
  toDER(): Uint8Array {
    const encodeInt = (n: bigint): Uint8Array => {
      let bytes = hexToBytes(n.toString(16).padStart(64, "0"))
      // strip leading zeros but keep at least one byte
      let start = 0
      while (start < bytes.length - 1 && bytes[start] === 0) start++
      bytes = bytes.slice(start)
      // prepend 0x00 if high bit set
      if ((bytes[0] ?? 0) & 0x80) bytes = concat(new Uint8Array([0x00]), bytes)
      return concat(new Uint8Array([0x02, bytes.length]), bytes)
    }
    const rEnc = encodeInt(this.r)
    const sEnc = encodeInt(this.s)
    const body  = concat(rEnc, sEnc)
    return concat(new Uint8Array([0x30, body.length]), body)
  }

  /** Recover the signer's public key */
  recover(msgHash: Uint8Array): PublicKey {
    return PublicKey.recover(msgHash, this)
  }

  /** Verify against a known public key */
  async verify(msgHash: Uint8Array, pub: PublicKey): Promise<boolean> {
    return pub.verify(msgHash, this)
  }
}
