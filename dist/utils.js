import { Curve, mod } from "./curve.js";
// ─── Encoding helpers ─────────────────────────────────────────────────────────
/** bigint → 32-byte big-endian Uint8Array */
export function bigintToBytes32(n) {
    const hex = n.toString(16).padStart(64, "0");
    return hexToBytes(hex);
}
/** 32-byte big-endian Uint8Array → bigint */
export function bytes32ToBigint(b) {
    return BigInt("0x" + bytesToHex(b));
}
/** Uint8Array → lowercase hex string */
export function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
/** hex string → Uint8Array */
export function hexToBytes(hex) {
    if (hex.startsWith("0x"))
        hex = hex.slice(2);
    if (hex.length % 2)
        hex = "0" + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        out[i] = byte;
    }
    return out;
}
/** Concatenate multiple Uint8Arrays */
export function concat(...arrays) {
    const total = arrays.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}
// ─── Hashing ──────────────────────────────────────────────────────────────────
/** SHA-256 via Web Crypto */
export async function sha256(data) {
    const buf = await crypto.subtle.digest("SHA-256", data.buffer);
    return new Uint8Array(buf);
}
/** Keccak-256 (pure TS, used for Ethereum addresses) */
export function keccak256(data) {
    return keccakHash(data);
}
/** HMAC-SHA256 */
export async function hmacSha256(key, data) {
    const k = await crypto.subtle.importKey("raw", key.buffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", k, data.buffer);
    return new Uint8Array(sig);
}
// ─── Random scalars ───────────────────────────────────────────────────────────
/** Generate a cryptographically random scalar in [1, N-1] */
export function randomScalar() {
    while (true) {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        const n = bytes32ToBigint(bytes);
        if (n > 0n && n < Curve.N)
            return n;
    }
}
/** RFC 6979 deterministic k for ECDSA */
export async function rfc6979(privateKey, msgHash) {
    const bx = bigintToBytes32(privateKey);
    const bh = bigintToBytes32(msgHash);
    let V = new Uint8Array(32).fill(0x01);
    let K = new Uint8Array(32).fill(0x00);
    K = await hmacSha256(K, concat(V, new Uint8Array([0x00]), bx, bh));
    V = await hmacSha256(K, V);
    K = await hmacSha256(K, concat(V, new Uint8Array([0x01]), bx, bh));
    V = await hmacSha256(K, V);
    while (true) {
        V = await hmacSha256(K, V);
        const k = bytes32ToBigint(V);
        if (k > 0n && k < Curve.N)
            return k;
        K = await hmacSha256(K, concat(V, new Uint8Array([0x00])));
        V = await hmacSha256(K, V);
    }
}
// ─── Pure-TS Keccak-256 ───────────────────────────────────────────────────────
function rotl32(val, n) {
    return ((val << n) | (val >>> (32 - n))) >>> 0;
}
function rotl64(lo, hi, n) {
    lo = lo >>> 0;
    hi = hi >>> 0;
    if (n === 0)
        return [lo, hi];
    if (n === 32)
        return [hi, lo];
    if (n < 32) {
        return [((lo << n) | (hi >>> (32 - n))) >>> 0, ((hi << n) | (lo >>> (32 - n))) >>> 0];
    }
    n -= 32;
    return [((hi << n) | (lo >>> (32 - n))) >>> 0, ((lo << n) | (hi >>> (32 - n))) >>> 0];
}
const RC_LO = new Uint32Array([
    0x00000001, 0x00008082, 0x0000808A, 0x80008000, 0x0000808B, 0x80000001,
    0x80008081, 0x00008009, 0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
    0x8000808B, 0x0000008B, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
    0x0000800A, 0x8000000A, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
]);
const RC_HI = new Uint32Array([
    0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
    0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
    0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
]);
const RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
function keccakF(S) {
    const C = new Uint32Array(10);
    const B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
        // θ
        const g = (a, i) => a[i] ?? 0;
        for (let x = 0; x < 5; x++) {
            C[2 * x] = (g(S, 2 * x) ^ g(S, 2 * (x + 5)) ^ g(S, 2 * (x + 10)) ^ g(S, 2 * (x + 15)) ^ g(S, 2 * (x + 20))) >>> 0;
            C[2 * x + 1] = (g(S, 2 * x + 1) ^ g(S, 2 * (x + 5) + 1) ^ g(S, 2 * (x + 10) + 1) ^ g(S, 2 * (x + 15) + 1) ^ g(S, 2 * (x + 20) + 1)) >>> 0;
        }
        for (let x = 0; x < 5; x++) {
            const xp = (x + 1) % 5;
            const xm = (x + 4) % 5;
            const [dlo, dhi] = rotl64(C[2 * xp], C[2 * xp + 1], 1);
            const dL = (dlo ^ C[2 * xm]) >>> 0;
            const dH = (dhi ^ C[2 * xm + 1]) >>> 0;
            for (let y = 0; y < 5; y++) {
                S[2 * (x + 5 * y)] = (S[2 * (x + 5 * y)] ^ dL) >>> 0;
                S[2 * (x + 5 * y) + 1] = (S[2 * (x + 5 * y) + 1] ^ dH) >>> 0;
            }
        }
        // ρ + π
        let [tlo, thi] = [S[2], S[3]];
        for (let i = 0; i < 24; i++) {
            const pi = PI[i];
            const [nlo, nhi] = rotl64(tlo, thi, RHO[i]);
            [tlo, thi] = [S[2 * pi], S[2 * pi + 1]];
            B[2 * pi] = nlo;
            B[2 * pi + 1] = nhi;
        }
        B[0] = S[0];
        B[1] = S[1];
        for (let k = 0; k < 50; k++)
            S[k] = B[k];
        // χ
        for (let y = 0; y < 5; y++) {
            const row = new Uint32Array(10);
            for (let x = 0; x < 5; x++) {
                row[2 * x] = S[2 * (x + 5 * y)];
                row[2 * x + 1] = S[2 * (x + 5 * y) + 1];
            }
            for (let x = 0; x < 5; x++) {
                S[2 * (x + 5 * y)] = (row[2 * x] ^ (~row[2 * ((x + 1) % 5)] & row[2 * ((x + 2) % 5)])) >>> 0;
                S[2 * (x + 5 * y) + 1] = (row[2 * x + 1] ^ (~row[2 * ((x + 1) % 5) + 1] & row[2 * ((x + 2) % 5) + 1])) >>> 0;
            }
        }
        // ι
        S[0] = (S[0] ^ RC_LO[round]) >>> 0;
        S[1] = (S[1] ^ RC_HI[round]) >>> 0;
    }
}
export function keccakHash(input) {
    const rate = 136;
    const padded = new Uint8Array(Math.ceil((input.length + 1) / rate) * rate);
    padded.set(input);
    padded[input.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    const state = new Uint32Array(50);
    for (let i = 0; i < padded.length; i += rate) {
        for (let j = 0; j < rate; j += 8) {
            const lane = j >> 3;
            state[2 * lane] = (state[2 * lane] ^ ((padded[i + j] | (padded[i + j + 1] << 8) | (padded[i + j + 2] << 16) | (padded[i + j + 3] << 24)))) >>> 0;
            state[2 * lane + 1] = (state[2 * lane + 1] ^ ((padded[i + j + 4] | (padded[i + j + 5] << 8) | (padded[i + j + 6] << 16) | (padded[i + j + 7] << 24)))) >>> 0;
        }
        keccakF(state);
    }
    const output = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
        const lo = state[2 * i];
        const hi = state[2 * i + 1];
        output[8 * i + 0] = lo & 0xff;
        output[8 * i + 1] = (lo >> 8) & 0xff;
        output[8 * i + 2] = (lo >> 16) & 0xff;
        output[8 * i + 3] = (lo >> 24) & 0xff;
        output[8 * i + 4] = hi & 0xff;
        output[8 * i + 5] = (hi >> 8) & 0xff;
        output[8 * i + 6] = (hi >> 16) & 0xff;
        output[8 * i + 7] = (hi >> 24) & 0xff;
    }
    return output;
}
/** EIP-55 checksum address from 20-byte address */
export function toChecksumAddress(addr) {
    const hex = bytesToHex(addr);
    const hashed = bytesToHex(keccak256(new TextEncoder().encode(hex)));
    let out = "0x";
    for (let i = 0; i < 40; i++)
        out += (parseInt(hashed[i], 16) >= 8) ? hex[i].toUpperCase() : hex[i];
    return out;
}
//# sourceMappingURL=utils.js.map