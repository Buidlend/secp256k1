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
import { SecretKey, PublicKey, Point } from "./keys.js";
export interface RingSignature {
    /** Message hash that was signed */
    msgHash: Uint8Array;
    /** Public keys in the ring */
    ring: PublicKey[];
    /** Challenge values c[0..n-1] */
    c: bigint[];
    /** Response values s[0..n-1] */
    s: bigint[];
    /** Key image I = x·H(P) — used for linkability / double-spend detection */
    keyImage: Point;
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
export declare function sign(msgHash: Uint8Array, signerKey: SecretKey, ring: PublicKey[], signerIndex: number): Promise<RingSignature>;
/**
 * Verify a ring signature.
 *
 * @example
 * ```ts
 * const valid = await Ring.verify(msgHash, sig)
 * console.log(valid) // true
 * ```
 */
export declare function verify(msgHash: Uint8Array, sig: RingSignature): Promise<boolean>;
/**
 * Check if two ring signatures share the same key image.
 * If true, the same private key signed both messages (double-spend / linkability).
 */
export declare function isLinked(a: RingSignature, b: RingSignature): boolean;
export interface SerializedRingSignature {
    msgHash: string;
    ring: string[];
    c: string[];
    s: string[];
    keyImage: string;
}
export declare function serialize(sig: RingSignature): SerializedRingSignature;
export declare function deserialize(raw: SerializedRingSignature): RingSignature;
//# sourceMappingURL=ring.d.ts.map