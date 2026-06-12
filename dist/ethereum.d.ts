/**
 * @module ethereum
 *
 * Ethereum-specific signing utilities:
 * - personal_sign  (EIP-191 prefix)
 * - eth_sign       (raw hash)
 * - EIP-712 typed data hashing
 * - ecrecover (recover address from signature)
 * - Transaction signing helper
 */
import { SecretKey, Signature } from "./keys.js";
/**
 * Hash a message the way MetaMask / eth_sign does (EIP-191).
 * prefix = "\x19Ethereum Signed Message:\n{len}{message}"
 */
export declare function personalSignHash(message: Uint8Array | string): Uint8Array;
/**
 * Sign a message with EIP-191 prefix (personal_sign).
 *
 * @example
 * ```ts
 * const sig = await Ethereum.personalSign(myKey, "Hello World")
 * const vrs = sig.toVRS()  // v is 27 or 28 per Ethereum convention
 * ```
 */
export declare function personalSign(key: SecretKey, message: Uint8Array | string): Promise<Signature>;
/**
 * Recover the Ethereum address from a personal_sign signature.
 *
 * @example
 * ```ts
 * const addr = Ethereum.personalRecover("Hello World", sig)
 * ```
 */
export declare function personalRecover(message: Uint8Array | string, sig: Signature): string;
export type EIP712Type = {
    name: string;
    type: string;
};
export type EIP712Domain = {
    name?: string;
    version?: string;
    chainId?: bigint | number;
    verifyingContract?: string;
    salt?: string;
};
/**
 * Hash typed data per EIP-712.
 *
 * @example
 * ```ts
 * const hash = Ethereum.hashTypedData({
 *   domain:      { name: "MyApp", version: "1", chainId: 1n, verifyingContract: "0x..." },
 *   types:       { Transfer: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }] },
 *   primaryType: "Transfer",
 *   message:     { to: "0x...", amount: 1000n },
 * })
 * const sig = await key.sign(hash)
 * ```
 */
export declare function hashTypedData(params: {
    domain: EIP712Domain;
    types: Record<string, EIP712Type[]>;
    primaryType: string;
    message: Record<string, unknown>;
}): Uint8Array;
/**
 * Sign typed data (EIP-712).
 *
 * @example
 * ```ts
 * const sig = await Ethereum.signTypedData(myKey, { domain, types, primaryType, message })
 * ```
 */
export declare function signTypedData(key: SecretKey, params: Parameters<typeof hashTypedData>[0]): Promise<Signature>;
/**
 * Recover an Ethereum address from a raw 32-byte hash and a signature.
 * This matches Solidity's `ecrecover(hash, v, r, s)`.
 *
 * @example
 * ```ts
 * const addr = Ethereum.ecrecover(hash, sig)
 * // or with individual components:
 * const addr = Ethereum.ecrecover(hash, Signature.fromVRS(concat(new Uint8Array([v]), r, s)))
 * ```
 */
export declare function ecrecover(msgHash: Uint8Array, sig: Signature): string;
export interface LegacyTx {
    nonce: bigint;
    gasPrice: bigint;
    gasLimit: bigint;
    to: string;
    value: bigint;
    data: Uint8Array;
    chainId: bigint;
}
/**
 * Sign a legacy (type-0) Ethereum transaction.
 * Returns the raw signed transaction bytes ready to broadcast.
 *
 * @example
 * ```ts
 * const raw = await Ethereum.signTx(myKey, {
 *   nonce: 0n, gasPrice: 20000000000n, gasLimit: 21000n,
 *   to: "0xRecipient", value: 1000000000000000000n, data: new Uint8Array(),
 *   chainId: 1n,
 * })
 * // broadcast: eth_sendRawTransaction("0x" + bytesToHex(raw))
 * ```
 */
export declare function signTx(key: SecretKey, tx: LegacyTx): Promise<Uint8Array>;
//# sourceMappingURL=ethereum.d.ts.map