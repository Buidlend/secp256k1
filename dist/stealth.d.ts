/**
 * @module stealth
 *
 * ERC-5564-inspired stealth address protocol.
 *
 * The sender:
 *   1. Generates an ephemeral key pair (r, R = r·G)
 *   2. Computes a shared secret s = keccak256(r·P_spend)
 *   3. Derives the stealth public key  P_stealth = P_spend + s·G
 *   4. Publishes R (the "ephemeral public key" / "announcement")
 *   5. Sends funds to address(P_stealth)
 *
 * The recipient (who knows their spend key d_spend):
 *   1. Scans announcements for ephemeral keys R
 *   2. Computes s = keccak256(d_spend · R)
 *   3. Derives stealth private key d_stealth = d_spend + s
 *   4. Checks whether d_stealth·G matches the observed address
 *
 * The stealth address is used once and then the key is deleted — the
 * recipient's identity is never linkable on-chain.
 */
import { SecretKey, PublicKey } from "./keys.js";
export interface StealthAnnouncement {
    /** Ephemeral public key R (SEC1 compressed, 33 bytes) */
    ephemeralPubKey: Uint8Array;
    /** The one-time Ethereum address to send funds to */
    stealthAddress: string;
}
export interface StealthRecovery {
    /** The stealth private key — use once, then zero-out and discard */
    stealthKey: SecretKey;
    /** The stealth public key, should match what the sender targeted */
    stealthPub: PublicKey;
    /** The one-time address derived from the stealth key */
    address: string;
}
/**
 * Generate a stealth payment address for a recipient.
 *
 * @param recipientSpendPub - The recipient's long-term spending public key
 * @returns An announcement (ephemeral public key + target address) to broadcast
 *
 * @example
 * ```ts
 * const { stealthAddress, ephemeralPubKey } = await Stealth.send(recipientPub)
 * // broadcast ephemeralPubKey on-chain, send ETH to stealthAddress
 * ```
 */
export declare function send(recipientSpendPub: PublicKey): Promise<StealthAnnouncement>;
/**
 * Recover the stealth private key from an announcement.
 * The recipient scans announcements using their spend key.
 *
 * @param spendKey - The recipient's long-term spend secret key
 * @param ephemeralPubKey - The ephemeral public key from the announcement (33 bytes)
 * @returns The one-time stealth key + address, or null if this announcement is not for this recipient
 *
 * @example
 * ```ts
 * for (const ann of announcements) {
 *   const result = await Stealth.receive(mySpendKey, ann.ephemeralPubKey)
 *   if (result && result.address === ann.stealthAddress) {
 *     // It's mine! Use result.stealthKey to spend, then delete it
 *   }
 * }
 * ```
 */
export declare function receive(spendKey: SecretKey, ephemeralPubKey: Uint8Array): Promise<StealthRecovery>;
/**
 * Full stealth flow: scan a batch of announcements for funds.
 *
 * @example
 * ```ts
 * const mine = await Stealth.scan(mySpendKey, announcements)
 * for (const { announcement, stealthKey, address } of mine) {
 *   // spend from `address` using `stealthKey`, then permanently delete stealthKey
 * }
 * ```
 */
export declare function scan(spendKey: SecretKey, announcements: Array<{
    ephemeralPubKey: Uint8Array;
    stealthAddress: string;
}>): Promise<Array<{
    announcement: typeof announcements[0];
    stealthKey: SecretKey;
    address: string;
}>>;
/**
 * Permanently zero-out a secret key's memory (best-effort in JS).
 * Call this after spending a stealth key.
 */
export declare function destroyKey(key: SecretKey): void;
//# sourceMappingURL=stealth.d.ts.map