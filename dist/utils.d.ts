/** bigint → 32-byte big-endian Uint8Array */
export declare function bigintToBytes32(n: bigint): Uint8Array<ArrayBuffer>;
/** 32-byte big-endian Uint8Array → bigint */
export declare function bytes32ToBigint(b: Uint8Array): bigint;
/** Uint8Array → lowercase hex string */
export declare function bytesToHex(bytes: Uint8Array): string;
/** hex string → Uint8Array */
export declare function hexToBytes(hex: string): Uint8Array<ArrayBuffer>;
/** Concatenate multiple Uint8Arrays */
export declare function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer>;
/** SHA-256 via Web Crypto */
export declare function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
/** Keccak-256 (pure TS, used for Ethereum addresses) */
export declare function keccak256(data: Uint8Array): Uint8Array<ArrayBuffer>;
/** HMAC-SHA256 */
export declare function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
/** Generate a cryptographically random scalar in [1, N-1] */
export declare function randomScalar(): bigint;
/** RFC 6979 deterministic k for ECDSA */
export declare function rfc6979(privateKey: bigint, msgHash: bigint): Promise<bigint>;
export declare function keccakHash(input: Uint8Array): Uint8Array<ArrayBuffer>;
/** EIP-55 checksum address from 20-byte address */
export declare function toChecksumAddress(addr: Uint8Array): string;
//# sourceMappingURL=utils.d.ts.map