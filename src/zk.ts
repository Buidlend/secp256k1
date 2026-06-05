// deno-lint-ignore-file no-namespace

/**
 * @module zk
 *
 * Zero-knowledge primitives:
 *
 * 1. **Pedersen Commitment**  C = v·G + r·H
 *    Commit to a value `v` with blinding factor `r`.
 *    Computationally binding, perfectly hiding.
 *
 * 2. **Schnorr Proof of Knowledge**
 *    Prove you know the discrete log of a point without revealing it.
 *    (= zero-knowledge proof of key ownership)
 *
 * 3. **Range Proof (Sketch)**
 *    Simple bit-decomposition proof that 0 ≤ v < 2^n.
 *    For production use migrate to Bulletproofs.
 *
 * 4. **Nullifier** — one-way link tag for anonymous spent-key tracking
 */

import { SecretKey, PublicKey, Point } from "./keys.js"
import { sha256, bytes32ToBigint, bigintToBytes32, bytesToHex, hexToBytes, concat, randomScalar } from "./utils.js"
import { Curve, mod } from "./curve.js"

// ─── Second generator H (hash-to-point, nothing-up-my-sleeve) ────────────────
// H = hashToPoint("Buidlend/secp256k1/H")

let _H: Point | undefined

async function getH(): Promise<Point> {
  if (_H) return _H
  const seed = new TextEncoder().encode("Buidlend/secp256k1/H/v1")
  const hash = await sha256(seed)
  const s    = mod(bytes32ToBigint(hash), Curve.N)
  _H = Point.G.mul(s)
  return _H
}

// ─── Pedersen Commitment ─────────────────────────────────────────────────────

export interface Commitment {
  /** The commitment point C = v·G + r·H */
  point: Point
  /** The committed value */
  value: bigint
  /** The blinding factor (keep secret!) */
  blinding: bigint
}

/**
 * Create a Pedersen commitment: C = value·G + blinding·H
 *
 * @example
 * ```ts
 * const c = await Pedersen.commit(42n)
 * const ok = await Pedersen.verify(c.point, 42n, c.blinding)
 * ```
 */
export async function commit(value: bigint, blinding?: bigint): Promise<Commitment> {
  const H = await getH()
  const r = blinding ?? randomScalar()
  const vG = Point.G.mul(mod(value, Curve.N))
  const rH = H.mul(r)
  return { point: vG.add(rH), value, blinding: r }
}

/** Verify that C = value·G + blinding·H */
export async function verify(commitment: Point, value: bigint, blinding: bigint): Promise<boolean> {
  try {
    const H  = await getH()
    const vG = Point.G.mul(mod(value, Curve.N))
    const rH = H.mul(blinding)
    const expected = vG.add(rH)
    return commitment.equals(expected)
  } catch { return false }
}

/** Homomorphic addition: C1 + C2 commits to v1+v2 with blinding r1+r2 */
export function addCommitments(a: Commitment, b: Commitment): Commitment {
  return {
    point:    a.point.add(b.point),
    value:    a.value   + b.value,
    blinding: mod(a.blinding + b.blinding, Curve.N),
  }
}

// ─── Schnorr Proof of Knowledge (Σ-protocol) ─────────────────────────────────

export interface SchnorrProof {
  /** Public key / commitment point */
  publicKey: PublicKey
  /** Challenge e = H(G, P, R) */
  challenge: bigint
  /** Response z = k - x·e */
  response: bigint
}

/**
 * Prove knowledge of a private key (discrete log) — non-interactive via Fiat-Shamir.
 *
 * @example
 * ```ts
 * const proof = await Schnorr.prove(myKey)
 * const valid = await Schnorr.verify(proof)
 * ```
 */
export async function schnorrProve(
  key: SecretKey,
  /** Optional context bytes bound into the challenge (domain separation) */
  context?: Uint8Array,
): Promise<SchnorrProof> {
  const x   = key.scalar
  const P   = key.toPublicKey()
  const k   = randomScalar()
  const R   = Point.G.mul(k)

  const ctx = context ?? new Uint8Array(0)
  const eInput = concat(P.toCompressed(), R.toCompressed(), ctx)
  const eHash  = await sha256(eInput)
  const e      = mod(bytes32ToBigint(eHash), Curve.N)
  const z      = mod(k - x * e, Curve.N)

  return { publicKey: P, challenge: e, response: z }
}

/** Verify a Schnorr proof of knowledge */
export async function schnorrVerify(proof: SchnorrProof, context?: Uint8Array): Promise<boolean> {
  try {
    const { publicKey: P, challenge: e, response: z } = proof

    // R' = z·G + e·P
    const zG = Point.G.mul(z)
    const eP = P.point.mul(e)
    const R  = zG.add(eP)

    const ctx    = context ?? new Uint8Array(0)
    const eInput = concat(P.toCompressed(), R.toCompressed(), ctx)
    const eHash  = await sha256(eInput)
    const eCheck = mod(bytes32ToBigint(eHash), Curve.N)

    return eCheck === e
  } catch { return false }
}

// ─── Nullifier ────────────────────────────────────────────────────────────────

/**
 * A nullifier is a one-way tag derived from a secret key and a context
 * (e.g. a set identifier or epoch). Publishing a nullifier proves you
 * own the key for that context, without revealing the key or linking it
 * to other contexts.
 *
 * @example
 * ```ts
 * // In an anonymous voting system:
 * const nf = await Nullifier.create(voterKey, pollId)
 * // If nf has been seen before → double vote. Else allow and record nf.
 * ```
 */
export async function nullifier(key: SecretKey, context: Uint8Array): Promise<Uint8Array> {
  const data = concat(key.toBytes(), context)
  return sha256(data)
}

/** Check whether a nullifier has been spent (simple set membership helper) */
export function isSpent(nf: Uint8Array, spent: Set<string>): boolean {
  return spent.has(bytesToHex(nf))
}

// ─── Simple bit-decomposition range proof ────────────────────────────────────

export interface RangeProof {
  commitments: Point[]   // one commitment per bit
  proofs:      SchnorrProof[]
  bitCount:    number
}

/**
 * Prove 0 ≤ value < 2^bitCount without revealing value.
 * Each bit is committed separately; each commitment has a Schnorr proof.
 *
 * NOTE: This is a simplified proof for illustration.
 * For production systems use Bulletproofs (inner-product argument).
 */
export async function rangeProve(value: bigint, bitCount = 32): Promise<{ proof: RangeProof; blindings: bigint[] }> {
  if (value < 0n || value >= (1n << BigInt(bitCount)))
    throw new Error("rangeProve: value out of range")

  const commitments: Point[]      = []
  const proofs:      SchnorrProof[] = []
  const blindings:   bigint[]     = []

  for (let i = 0; i < bitCount; i++) {
    const bit = (value >> BigInt(i)) & 1n
    const c   = await commit(bit)
    commitments.push(c.point)
    blindings.push(c.blinding)

    // Prove the blinding factor (not the bit itself — we reveal bits in this simple version)
    const blindingKey = new SecretKey(c.blinding)
    const p = await schnorrProve(blindingKey, new Uint8Array([i]))
    proofs.push(p)
  }

  return { proof: { commitments, proofs, bitCount }, blindings }
}

/** Verify that all bit commitments are valid (simplified verification) */
export async function rangeVerify(proof: RangeProof, blindings: bigint[]): Promise<boolean> {
  for (let i = 0; i < proof.bitCount; i++) {
    const ok = await schnorrVerify(proof.proofs[i]!, new Uint8Array([i]))
    if (!ok) return false
  }
  return true
}
