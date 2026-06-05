// deno-lint-ignore-file no-namespace

/**
 * @module ring
 *
 * Linkable Spontaneous Anonymous Group (LSAG) signatures.
 *
 * A ring signature proves:
 *   "One of the public keys in this ring signed this message"
 * without revealing WHICH key signed.
 *
 * Additionally, the "key image" I = x · H(P) is deterministic for the
 * same private key, which allows double-spend detection without
 * breaking anonymity.
 *
 * Algorithm reference: Liu et al., "Linkable Spontaneous Anonymous Group
 * Signature for Ad Hoc Groups" (2004).
 */

import { SecretKey, PublicKey, Point } from "./keys.js"
import { sha256, keccak256, bytes32ToBigint, bigintToBytes32, bytesToHex, hexToBytes, concat } from "./utils.js"
import { Curve, JacobianPoint, mod } from "./curve.js"

export interface RingSignature {
  /** Message hash that was signed */
  msgHash: Uint8Array
  /** Public keys in the ring */
  ring: PublicKey[]
  /** Challenge values c[0..n-1] */
  c: bigint[]
  /** Response values s[0..n-1] */
  s: bigint[]
  /** Key image I = x·H(P) — used for linkability / double-spend detection */
  keyImage: Point
}

/** Hash a point to another point: H_p(P) = hashToScalar(P) · G */
async function hashToPoint(p: Point): Promise<Point> {
  const compressed = p.toCompressed()
  const hash       = await sha256(concat(new Uint8Array([0x02]), compressed))
  const scalar     = mod(bytes32ToBigint(hash), Curve.N)
  return Point.G.mul(scalar)
}

async function challengeHash(
  msgHash:  Uint8Array,
  ring:     PublicKey[],
  L:        Point,
  R:        Point,
): Promise<bigint> {
  const ringBytes = concat(...ring.map(pk => pk.toCompressed()))
  const data = concat(msgHash, ringBytes, L.toCompressed(), R.toCompressed())
  const hash = await sha256(data)
  return mod(bytes32ToBigint(hash), Curve.N)
}

/**
 * Create a ring signature.
 *
 * @param msgHash - 32-byte pre-hashed message
 * @param signerKey - The actual signer's secret key
 * @param ring - The full ring of public keys (must include signerKey.toPublicKey())
 * @param signerIndex - Index of the signer's public key in `ring`
 *
 * @example
 * ```ts
 * const ring = [alice.toPublicKey(), bob.toPublicKey(), carol.toPublicKey()]
 * const sig = await Ring.sign(msgHash, alice, ring, 0)
 * const valid = await Ring.verify(msgHash, sig)
 * ```
 */
export async function sign(
  msgHash:     Uint8Array,
  signerKey:   SecretKey,
  ring:        PublicKey[],
  signerIndex: number,
): Promise<RingSignature> {
  const n   = ring.length
  if (signerIndex < 0 || signerIndex >= n) throw new Error("Ring.sign: signerIndex out of range")

  const x = signerKey.scalar
  const P = (ring[signerIndex] ?? (() => { throw new Error("invalid signerIndex") })()).point

  // Key image: I = x · H_p(P)
  const Hp       = await hashToPoint(P)
  const keyImage = Hp.mul(x)

  // Random scalars for all positions except signer
  const alpha   = mod(bytes32ToBigint(crypto.getRandomValues(new Uint8Array(32))), Curve.N)
  const sArr    = new Array<bigint>(n)
  const cArr    = new Array<bigint>(n)

  for (let i = 0; i < n; i++) {
    if (i !== signerIndex)
      (sArr[i]!) = mod(bytes32ToBigint(crypto.getRandomValues(new Uint8Array(32))), Curve.N)
  }

  // Compute initial L, R for signer position
  const L0 = Point.G.mul(alpha)
  const Hp0 = await hashToPoint(P)
  const R0  = Hp0.mul(alpha)

  // Hash around the ring starting at (signerIndex + 1)
  const startIdx = (signerIndex + 1) % n
  cArr[startIdx] = await challengeHash(msgHash, ring, L0, R0)

  for (let step = 1; step < n; step++) {
    const i    = (signerIndex + step) % n
    const next = (i + 1) % n

    const curC = cArr[i] as bigint
    const curS = sArr[i] as bigint
    const Li = Point.G.mul(curS).add((ring[i]!).point.mul(curC))
    const Hpi = await hashToPoint((ring[i]!).point)
    const Ri  = Hpi.mul(curS).add(keyImage.mul(curC))

    cArr[next] = await challengeHash(msgHash, ring, Li, Ri)
  }

  // Close the ring: compute signer's s using the challenge that wrapped back
  const cS = cArr[signerIndex] as bigint
  sArr[signerIndex] = mod(alpha - x * cS, Curve.N)

  return { msgHash, ring, c: cArr, s: sArr, keyImage }
}

/**
 * Verify a ring signature.
 *
 * @example
 * ```ts
 * const valid = await Ring.verify(msgHash, sig)
 * console.log(valid) // true
 * ```
 */
export async function verify(msgHash: Uint8Array, sig: RingSignature): Promise<boolean> {
  try {
    const { ring, c, s, keyImage } = sig
    const n = ring.length

    let cCheck = c[0]!
    for (let i = 0; i < n; i++) {
      const Li = Point.G.mul(s[i]!).add((ring[i]!).point.mul(c[i]!))
      const Hpi = await hashToPoint((ring[i]!).point)
      const Ri  = Hpi.mul(s[i]!).add(keyImage.mul(c[i]!))
      if (i < n - 1) {
        const computed = await challengeHash(msgHash, ring, Li, Ri)
        if (computed !== (c[i + 1] ?? 0n)) return false
      } else {
        // Final challenge must wrap back to c[0]
        const computed = await challengeHash(msgHash, ring, Li, Ri)
        cCheck = computed
      }
    }

    return cCheck === c[0]
  } catch { return false }
}

/**
 * Check if two ring signatures share the same key image.
 * If true, the same private key signed both messages (double-spend / linkability).
 */
export function isLinked(a: RingSignature, b: RingSignature): boolean {
  return a.keyImage.equals(b.keyImage)
}

export interface SerializedRingSignature {
  msgHash:  string
  ring:     string[]
  c:        string[]
  s:        string[]
  keyImage: string
}

export function serialize(sig: RingSignature): SerializedRingSignature {
  return {
    msgHash:  bytesToHex(sig.msgHash),
    ring:     sig.ring.map(pk => pk.toHex()),
    c:        sig.c.map(v => v.toString(16).padStart(64, "0")),
    s:        sig.s.map(v => v.toString(16).padStart(64, "0")),
    keyImage: bytesToHex(sig.keyImage.toCompressed()),
  }
}

export function deserialize(raw: SerializedRingSignature): RingSignature {
  return {
    msgHash:  hexToBytes(raw.msgHash),
    ring:     raw.ring.map(h => PublicKey.fromHex(h)),
    c:        raw.c.map(h => BigInt("0x" + h)),
    s:        raw.s.map(h => BigInt("0x" + h)),
    keyImage: Point.fromSec1(hexToBytes(raw.keyImage)),
  }
}
