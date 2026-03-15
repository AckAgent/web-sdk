/**
 * SAS (Short Authentication String) generation for login verification.
 * Must match backend and iOS implementations exactly.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { SAS_WORDS, SAS_EMOJIS } from "./generated/sas-dictionary.js";

/** Approver key for SAS computation */
export interface SASApproverKey {
  encryptionPublicKeyHex: string; // Lowercase hex-encoded P-256 ECDH encryption public key
  publicKey: Uint8Array; // P-256 33 bytes (compressed SEC1)
}

/** Approver key info as returned by the API (approver_keys field) */
export interface ApproverKeyInfo {
  encryptionPublicKeyHex: string;
  approverPublicKey: Uint8Array;
}

/** SAS computation result */
export interface SASResult {
  words: string[];
  emojis: string[];
  wordString: string;
  emojiString: string;
}

/**
 * Compute the Short Authentication String from public keys.
 *
 * Algorithm:
 * 1. Sort approver keys by hex-encoded encryption public key (for determinism)
 * 2. Concatenate: requester_pub || approver_1_pub || approver_2_pub || ...
 * 3. SHA-256 hash the concatenation
 * 4. Take first 5 bytes as indices into word/emoji dictionaries (40 bits of entropy)
 *
 * @param requesterPubKey - The requester's P-256 public key (33 bytes compressed)
 * @param approverKeys - Array of approver keys to include in SAS
 * @returns SAS result with words and emojis
 */
export function computeSAS(
  requesterPubKey: Uint8Array,
  approverKeys: SASApproverKey[],
): SASResult {
  // Sort approver keys by hex-encoded encryption public key for deterministic ordering
  const sorted = [...approverKeys].sort((a, b) =>
    a.encryptionPublicKeyHex.localeCompare(b.encryptionPublicKeyHex),
  );

  // Concatenate all public keys
  const totalLength =
    requesterPubKey.length +
    sorted.reduce((acc, ak) => acc + ak.publicKey.length, 0);
  const data = new Uint8Array(totalLength);

  let offset = 0;
  data.set(requesterPubKey, offset);
  offset += requesterPubKey.length;

  for (const ak of sorted) {
    data.set(ak.publicKey, offset);
    offset += ak.publicKey.length;
  }

  // SHA-256 hash
  const hash = sha256(data);

  // Extract 5 bytes for indices (40 bits of entropy)
  const words: string[] = [];
  const emojis: string[] = [];

  for (let i = 0; i < 5; i++) {
    const idx = hash[i];
    words.push(SAS_WORDS[idx]);
    emojis.push(SAS_EMOJIS[idx]);
  }

  return {
    words,
    emojis,
    wordString: words.join("-"),
    emojiString: emojis.join(" "),
  };
}

/**
 * Compute SAS from API approver key format.
 * Convenience wrapper for auth.ts that takes ApproverKeyInfo directly.
 *
 * @param requesterPubKey - The requester's P-256 public key (33 bytes compressed)
 * @param approverKeys - Array of approver keys in API format
 * @returns SAS result with words and emojis
 */
export function computeSASFromApproverKeys(
  requesterPubKey: Uint8Array,
  approverKeys: ApproverKeyInfo[],
): SASResult {
  const sasApproverKeys = approverKeys.map((ak) => ({
    encryptionPublicKeyHex: ak.encryptionPublicKeyHex,
    publicKey: ak.approverPublicKey,
  }));
  return computeSAS(requesterPubKey, sasApproverKeys);
}
