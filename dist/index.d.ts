/**
 * @Buidlend/secp256k1
 *
 * A zero-dependency, pure TypeScript 5 secp256k1 library for Ethereum.
 *
 * Features:
 *  - Key generation, import/export, ECDH
 *  - Recoverable ECDSA signatures (RFC 6979 deterministic)
 *  - Ethereum addresses (EIP-55 checksummed)
 *  - Stealth addresses (ERC-5564 — one-time use, permanent deletion)
 *  - Ring signatures (LSAG — anonymous sender, linkable)
 *  - Pedersen commitments + Schnorr ZK proofs of knowledge
 *  - Nullifiers for anonymous spent-key tracking
 *  - EIP-191 personal_sign, EIP-712 typed data, legacy tx signing
 *
 * @example
 * ```ts
 * import secp256k1 from "@Buidlend/secp256k1"
 *
 * // Basic sign + recover
 * const key = secp256k1.SecretKey.random()
 * const msg = crypto.getRandomValues(new Uint8Array(32))
 * const sig = await key.sign(msg)
 * const pub = secp256k1.PublicKey.recover(msg, sig)
 *
 * // Ethereum address
 * const addr = key.toPublicKey().toEthAddress()
 *
 * // Stealth payment
 * const { stealthAddress, ephemeralPubKey } = await secp256k1.Stealth.send(recipientPub)
 *
 * // Ring signature (anonymous)
 * const ring = [alice.toPublicKey(), bob.toPublicKey(), carol.toPublicKey()]
 * const ringSig = await secp256k1.Ring.sign(msg, alice, ring, 0)
 * const valid   = await secp256k1.Ring.verify(msg, ringSig)
 *
 * // ZK proof of key ownership
 * const proof = await secp256k1.ZK.schnorrProve(key)
 * const ok    = await secp256k1.ZK.schnorrVerify(proof)
 * ```
 */
export { Curve } from "./curve.js";
export { Point } from "./keys.js";
export { SecretKey } from "./keys.js";
export { PublicKey } from "./keys.js";
export { Signature } from "./keys.js";
export * as keys from "./keys.js";
export * as Stealth from "./stealth.js";
export * as Ring from "./ring.js";
export * as ZK from "./zk.js";
export * as Ethereum from "./ethereum.js";
export { mod, modInv, modPow, modSqrt, } from "./curve.js";
export { bigintToBytes32, bytes32ToBigint, bytesToHex, hexToBytes, concat, sha256, keccak256, randomScalar, rfc6979, toChecksumAddress, } from "./utils.js";
import { Curve } from "./curve.js";
import { Point, SecretKey, PublicKey, Signature } from "./keys.js";
import * as Stealth from "./stealth.js";
import * as Ring from "./ring.js";
import * as ZK from "./zk.js";
import * as Ethereum from "./ethereum.js";
import * as Utils from "./utils.js";
import * as keys from "./keys.js";
declare const secp256k1: {
    readonly Curve: typeof Curve;
    readonly Point: typeof Point;
    readonly SecretKey: typeof SecretKey;
    readonly PublicKey: typeof PublicKey;
    readonly Signature: typeof Signature;
    readonly keys: typeof keys;
    readonly Stealth: typeof Stealth;
    readonly Ring: typeof Ring;
    readonly ZK: typeof ZK;
    readonly Ethereum: typeof Ethereum;
    readonly Utils: typeof Utils;
};
export default secp256k1;
//# sourceMappingURL=index.d.ts.map