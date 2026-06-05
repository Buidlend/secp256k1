// deno-lint-ignore-file no-namespace

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

import { SecretKey, PublicKey, Signature } from "./keys.js"
import { sha256, keccak256, bytes32ToBigint, bigintToBytes32, bytesToHex, hexToBytes, concat } from "./utils.js"

// ─── EIP-191 personal_sign ───────────────────────────────────────────────────

const PERSONAL_SIGN_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n")

/**
 * Hash a message the way MetaMask / eth_sign does (EIP-191).
 * prefix = "\x19Ethereum Signed Message:\n{len}{message}"
 */
export function personalSignHash(message: Uint8Array | string): Uint8Array {
  const msg     = typeof message === "string" ? new TextEncoder().encode(message) : message
  const lenStr  = new TextEncoder().encode(String(msg.length))
  const prefixed = concat(PERSONAL_SIGN_PREFIX, lenStr, msg)
  return keccak256(prefixed)
}

/**
 * Sign a message with EIP-191 prefix (personal_sign).
 *
 * @example
 * ```ts
 * const sig = await Ethereum.personalSign(myKey, "Hello World")
 * const vrs = sig.toVRS()  // v is 27 or 28 per Ethereum convention
 * ```
 */
export async function personalSign(key: SecretKey, message: Uint8Array | string): Promise<Signature> {
  return key.sign(personalSignHash(message))
}

/**
 * Recover the Ethereum address from a personal_sign signature.
 *
 * @example
 * ```ts
 * const addr = Ethereum.personalRecover("Hello World", sig)
 * ```
 */
export function personalRecover(message: Uint8Array | string, sig: Signature): string {
  const hash = personalSignHash(message)
  const pub  = PublicKey.recover(hash, sig)
  return pub.toEthAddress()
}

// ─── EIP-712 typed data ───────────────────────────────────────────────────────

export type EIP712Type = { name: string; type: string }
export type EIP712Domain = {
  name?:              string
  version?:           string
  chainId?:           bigint | number
  verifyingContract?: string
  salt?:              string
}

const EIP712_DOMAIN_TYPE: EIP712Type[] = [
  { name: "name",              type: "string"  },
  { name: "version",           type: "string"  },
  { name: "chainId",           type: "uint256" },
  { name: "verifyingContract", type: "address" },
]

function encodeType(primaryType: string, types: Record<string, EIP712Type[]>): string {
  const deps: string[] = []
  const queue = [primaryType]
  const visited = new Set<string>()
  while (queue.length) {
    const t = queue.shift()!
    if (visited.has(t)) continue
    visited.add(t)
    if (!types[t]) continue
    deps.push(t)
    for (const field of (types[t] ?? [])) {
      const base = field.type.replace(/\[\d*\]$/, "")
      if (types[base] && !visited.has(base)) queue.push(base)
    }
  }
  return deps.map(t => `${t}(${(types[t] ?? []).map(f => `${f.type} ${f.name}`).join(",")})`).join("")
}

function typeHash(primaryType: string, types: Record<string, EIP712Type[]>): Uint8Array {
  return keccak256(new TextEncoder().encode(encodeType(primaryType, types)))
}

function abiEncode(type: string, value: unknown): Uint8Array {
  if (type === "address") {
    const hex = (value as string).replace("0x", "").toLowerCase().padStart(64, "0")
    return hexToBytes(hex)
  }
  if (type === "bool") return bigintToBytes32(value ? 1n : 0n)
  if (type.startsWith("uint") || type.startsWith("int")) return bigintToBytes32(BigInt(value as number | string | bigint))
  if (type === "bytes32") return hexToBytes((value as string).replace("0x", "").padStart(64, "0"))
  if (type === "string") return keccak256(new TextEncoder().encode(value as string))
  if (type === "bytes")  return keccak256(hexToBytes((value as string).replace("0x", "")))
  throw new Error(`abiEncode: unsupported type ${type}`)
}

function encodeData(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, EIP712Type[]>,
): Uint8Array {
  const th     = typeHash(primaryType, types)
  const fields = types[primaryType] ?? []
  const parts  = fields.map(f => {
    const baseType = f.type.replace(/\[\d*\]$/, "")
    if (types[baseType]) {
      return keccak256(encodeData(baseType, data[f.name] as Record<string, unknown>, types))
    }
    return abiEncode(f.type, data[f.name])
  })
  return keccak256(concat(th, ...parts))
}

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
export function hashTypedData(params: {
  domain:      EIP712Domain
  types:       Record<string, EIP712Type[]>
  primaryType: string
  message:     Record<string, unknown>
}): Uint8Array {
  const { domain, types, primaryType, message } = params
  const allTypes = { EIP712Domain: EIP712_DOMAIN_TYPE, ...types }

  const domainFields = EIP712_DOMAIN_TYPE.filter(f => domain[f.name as keyof EIP712Domain] !== undefined)
  const domainTypes  = { EIP712Domain: domainFields }

  const domainSep = encodeData("EIP712Domain", domain as Record<string, unknown>, domainTypes)
  const msgHash   = encodeData(primaryType, message, allTypes)

  return keccak256(concat(new Uint8Array([0x19, 0x01]), domainSep, msgHash))
}

/**
 * Sign typed data (EIP-712).
 *
 * @example
 * ```ts
 * const sig = await Ethereum.signTypedData(myKey, { domain, types, primaryType, message })
 * ```
 */
export async function signTypedData(
  key: SecretKey,
  params: Parameters<typeof hashTypedData>[0],
): Promise<Signature> {
  return key.sign(hashTypedData(params))
}

// ─── ecrecover (Solidity-compatible) ─────────────────────────────────────────

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
export function ecrecover(msgHash: Uint8Array, sig: Signature): string {
  const pub = PublicKey.recover(msgHash, sig)
  return pub.toEthAddress()
}

// ─── Raw transaction signer (type-0, legacy) ─────────────────────────────────

export interface LegacyTx {
  nonce:    bigint
  gasPrice: bigint
  gasLimit: bigint
  to:       string     // "0x..." or "" for contract creation
  value:    bigint
  data:     Uint8Array
  chainId:  bigint
}

/** Simple RLP encoder (sufficient for legacy tx fields) */
function rlpEncode(input: Uint8Array | Array<Uint8Array>): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length === 1 && (input[0] ?? 0x80) < 0x80) return input
    return concat(rlpLength(input.length, 0x80), input)
  }
  const body = concat(...input.map(i => rlpEncode(i)))
  return concat(rlpLength(body.length, 0xc0), body)
}

function rlpLength(len: number, offset: number): Uint8Array {
  if (len < 56) return new Uint8Array([offset + len])
  const bytes = bigintToBytes32(BigInt(len)).filter((_, i, a) => {
    let start = 0; while (start < a.length - 1 && (a[start] ?? 0) === 0) start++; return i >= start
  })
  // strip leading zeros properly
  let s = 0; const b = bigintToBytes32(BigInt(len)); while (s < b.length - 1 && b[s] === 0) s++
  const lenBytes = b.slice(s)
  return concat(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes)
}

function bigintToRlpBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0)
  const hex  = n.toString(16)
  const padded = hex.length % 2 ? "0" + hex : hex
  return hexToBytes(padded)
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
export async function signTx(key: SecretKey, tx: LegacyTx): Promise<Uint8Array> {
  const toBytes = tx.to.startsWith("0x") ? hexToBytes(tx.to.slice(2)) : new Uint8Array(0)

  // EIP-155 signing hash
  const rlpUnsigned = rlpEncode([
    bigintToRlpBytes(tx.nonce),
    bigintToRlpBytes(tx.gasPrice),
    bigintToRlpBytes(tx.gasLimit),
    toBytes,
    bigintToRlpBytes(tx.value),
    tx.data,
    bigintToRlpBytes(tx.chainId),
    new Uint8Array(0),
    new Uint8Array(0),
  ])

  const hash = keccak256(rlpUnsigned)
  const sig  = await key.sign(hash)

  // EIP-155 v = chainId * 2 + 35 + recovery_bit
  const v = tx.chainId * 2n + 35n + BigInt(sig.v)

  const rlpSigned = rlpEncode([
    bigintToRlpBytes(tx.nonce),
    bigintToRlpBytes(tx.gasPrice),
    bigintToRlpBytes(tx.gasLimit),
    toBytes,
    bigintToRlpBytes(tx.value),
    tx.data,
    bigintToRlpBytes(v),
    bigintToRlpBytes(sig.r),
    bigintToRlpBytes(sig.s),
  ])

  return rlpSigned
}
