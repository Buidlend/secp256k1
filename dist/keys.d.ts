/**
 * An affine point on secp256k1.
 * Supports arithmetic, SEC1 serialisation, and casting to PublicKey.
 */
export declare class Point {
    readonly x: bigint;
    readonly y: bigint;
    constructor(x: bigint, y: bigint);
    /** The generator point G */
    static readonly G: Point;
    /** The point at infinity (identity element) */
    static readonly ZERO: unique symbol;
    /** Import from compressed (33 bytes, 02/03 prefix) or uncompressed (65 bytes, 04 prefix) SEC1 */
    static fromSec1(bytes: Uint8Array): Point;
    /** Export to SEC1 compressed (33 bytes) */
    toCompressed(): Uint8Array;
    /** Export to SEC1 uncompressed (65 bytes) */
    toUncompressed(): Uint8Array;
    /** Scalar multiplication */
    mul(scalar: bigint): Point;
    /** Point addition */
    add(other: Point): Point;
    /** Point subtraction */
    sub(other: Point): Point;
    /** Negate a point */
    negate(): Point;
    equals(other: Point): boolean;
    /** Cast to PublicKey */
    toPublicKey(): PublicKey;
    toString(): string;
}
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
export declare class SecretKey {
    readonly scalar: bigint;
    constructor(scalar: bigint);
    /** Generate a random secret key */
    static random(): SecretKey;
    /** Import from 32 raw bytes */
    static fromBytes(bytes: Uint8Array): SecretKey;
    /** Import from a hex string (with or without 0x prefix) */
    static fromHex(hex: string): SecretKey;
    /** Derive a secret key from a BIP-39-style seed + index (HKDF-like) */
    static fromSeed(seed: Uint8Array, index?: number): Promise<SecretKey>;
    /** Export to 32 raw bytes */
    toBytes(): Uint8Array;
    /** Export to hex string */
    toHex(): string;
    /** Derive the corresponding public key */
    toPublicKey(): PublicKey;
    /**
     * Sign a 32-byte pre-hashed message (RFC 6979 deterministic ECDSA).
     * Returns a recoverable signature.
     */
    sign(msgHash: Uint8Array): Promise<Signature>;
    /**
     * Sign with a random k (use only when you need a fresh nonce per sig).
     * Prefer `sign()` for deterministic behaviour.
     */
    signRandom(msgHash: Uint8Array): Signature;
    private _signWithK;
    /** ECDH: compute a shared secret with another public key */
    ecdh(pub: PublicKey): Uint8Array;
    /** Tweak: add a scalar to this key (used in stealth / HD key derivation) */
    tweak(t: bigint): SecretKey;
}
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
export declare class PublicKey {
    readonly point: Point;
    constructor(point: Point);
    /** Import from SEC1 bytes (compressed 33 or uncompressed 65) */
    static fromSec1(bytes: Uint8Array): PublicKey;
    /** Import from hex string */
    static fromHex(hex: string): PublicKey;
    /**
     * Recover the public key from a recoverable signature and message hash.
     * Equivalent to `ecrecover` in Solidity.
     */
    static recover(msgHash: Uint8Array, sig: Signature): PublicKey;
    /** Verify an ECDSA signature */
    verify(msgHash: Uint8Array, sig: Signature): Promise<boolean>;
    /** Export to SEC1 compressed (33 bytes) */
    toCompressed(): Uint8Array;
    /** Export to SEC1 uncompressed (65 bytes) */
    toUncompressed(): Uint8Array;
    /** Export to hex string (compressed by default) */
    toHex(compressed?: boolean): string;
    /**
     * Derive the Ethereum address from this public key.
     * keccak256(uncompressed_pubkey[1:])[12:] — EIP-55 checksummed.
     */
    toEthAddress(): string;
    /**
     * Tweak: add a scalar·G to this key (matching SecretKey.tweak).
     * Useful for stealth addresses, HD derivation, etc.
     */
    tweak(t: bigint): PublicKey;
}
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
export declare class Signature {
    readonly r: bigint;
    readonly s: bigint;
    /** Recovery bit (0 or 1) */
    readonly v: number;
    constructor(r: bigint, s: bigint, 
    /** Recovery bit (0 or 1) */
    v: number);
    /** Import from 65-byte RSV (r[32] + s[32] + v[1]) */
    static fromRSV(bytes: Uint8Array): Signature;
    /** Import from 65-byte VRS (v[1] + r[32] + s[32]) — Ethereum ecrecover format */
    static fromVRS(bytes: Uint8Array): Signature;
    /** Export to 65-byte RSV */
    toRSV(): Uint8Array;
    /** Export to 65-byte VRS (v+27 Ethereum convention) */
    toVRS(): Uint8Array;
    /** Export to hex string (RSV) */
    toHex(): string;
    /** DER encoding for EVM / standard tooling */
    toDER(): Uint8Array;
    /** Recover the signer's public key */
    recover(msgHash: Uint8Array): PublicKey;
    /** Verify against a known public key */
    verify(msgHash: Uint8Array, pub: PublicKey): Promise<boolean>;
}
//# sourceMappingURL=keys.d.ts.map