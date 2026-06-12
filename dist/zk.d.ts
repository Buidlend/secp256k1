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
import { SecretKey, PublicKey, Point } from "./keys.js";
export interface Commitment {
    /** The commitment point C = v·G + r·H */
    point: Point;
    /** The committed value */
    value: bigint;
    /** The blinding factor (keep secret!) */
    blinding: bigint;
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
export declare function commit(value: bigint, blinding?: bigint): Promise<Commitment>;
/** Verify that C = value·G + blinding·H */
export declare function verify(commitment: Point, value: bigint, blinding: bigint): Promise<boolean>;
/** Homomorphic addition: C1 + C2 commits to v1+v2 with blinding r1+r2 */
export declare function addCommitments(a: Commitment, b: Commitment): Commitment;
export interface SchnorrProof {
    /** Public key / commitment point */
    publicKey: PublicKey;
    /** Challenge e = H(G, P, R) */
    challenge: bigint;
    /** Response z = k - x·e */
    response: bigint;
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
export declare function schnorrProve(key: SecretKey, 
/** Optional context bytes bound into the challenge (domain separation) */
context?: Uint8Array): Promise<SchnorrProof>;
/** Verify a Schnorr proof of knowledge */
export declare function schnorrVerify(proof: SchnorrProof, context?: Uint8Array): Promise<boolean>;
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
export declare function nullifier(key: SecretKey, context: Uint8Array): Promise<Uint8Array>;
/** Check whether a nullifier has been spent (simple set membership helper) */
export declare function isSpent(nf: Uint8Array, spent: Set<string>): boolean;
export interface RangeProof {
    commitments: Point[];
    proofs: SchnorrProof[];
    bitCount: number;
}
/**
 * Prove 0 ≤ value < 2^bitCount without revealing value.
 * Each bit is committed separately; each commitment has a Schnorr proof.
 *
 * NOTE: This is a simplified proof for illustration.
 * For production systems use Bulletproofs (inner-product argument).
 */
export declare function rangeProve(value: bigint, bitCount?: number): Promise<{
    proof: RangeProof;
    blindings: bigint[];
}>;
/** Verify that all bit commitments are valid (simplified verification) */
export declare function rangeVerify(proof: RangeProof, blindings: bigint[]): Promise<boolean>;
//# sourceMappingURL=zk.d.ts.map