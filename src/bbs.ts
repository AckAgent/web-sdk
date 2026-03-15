/**
 * BBS+ signature verification using @mattrglobal/pairing-crypto WASM.
 *
 * The web SDK is a verifier -- it verifies BBS+ credentials issued by the backend.
 * It does NOT sign or issue credentials.
 *
 * Uses the BLS12-381 SHA-256 ciphersuite to match the backend (zkryptium).
 *
 * The @mattrglobal/pairing-crypto package uses WASM internally and requires
 * async initialization. This module lazily imports the library on first use
 * to avoid bundling WASM when BBS+ verification is not needed.
 */

import type {
  BbsVerifyRequest,
  BbsVerifyProofRequest,
  BbsVerifyResult as PairingCryptoBbsVerifyResult,
} from "@mattrglobal/pairing-crypto";
import { verifyBbsProofWithPseudonymWasm } from "./bbs-ffi-wasm.js";

/** Result of a BBS+ verification operation. */
export interface BbsVerifyResult {
  /** Whether the verification succeeded. */
  verified: boolean;
  /** Error message if verification failed due to an error (not just invalid data). */
  error?: string;
}

/** BBS+ public key for verification. */
export interface BbsPublicKey {
  /** Raw BLS12-381 G2 public key bytes (96 bytes). */
  publicKeyBytes: Uint8Array;
}

/** A BBS+ credential containing a signature over message attributes. */
export interface BbsCredential {
  /** The BBS+ signature bytes. */
  signature: Uint8Array;
  /** The signed message attributes as byte arrays. */
  messages: Uint8Array[];
  /** Optional header used during signing. */
  header?: Uint8Array;
}

/** Expected length of a BLS12-381 G2 public key in bytes. */
const BLS12_381_PUBLIC_KEY_LENGTH = 96;

/** Expected length of a compressed BLS12-381 G1 point in bytes. */
const BLS12_381_G1_COMPRESSED_LENGTH = 48;

/**
 * Lazily load the @mattrglobal/pairing-crypto module.
 *
 * The module uses WASM and is loaded via dynamic import to avoid bundling
 * it when BBS+ verification is not needed. The module self-initializes
 * its WASM on first operation.
 */
let pairingCryptoModule: typeof import("@mattrglobal/pairing-crypto") | null =
  null;

async function getPairingCrypto(): Promise<
  typeof import("@mattrglobal/pairing-crypto")
> {
  if (pairingCryptoModule) return pairingCryptoModule;
  pairingCryptoModule = await import("@mattrglobal/pairing-crypto");
  return pairingCryptoModule;
}

/**
 * Verify a BBS+ signature over messages using the BLS12-381 SHA-256 ciphersuite.
 *
 * This verifies that the given signature was produced by the holder of the
 * private key corresponding to the provided public key, over the given
 * header and messages.
 *
 * @param publicKey - The issuer's BBS+ public key (96 bytes, BLS12-381 G2 point)
 * @param signature - The BBS+ signature bytes
 * @param header - The header used during signing (can be empty Uint8Array)
 * @param messages - The signed message attributes as byte arrays
 * @returns Verification result indicating success or failure
 */
export async function verifyBbsSignature(
  publicKey: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array,
  messages: Uint8Array[],
): Promise<BbsVerifyResult> {
  if (publicKey.length !== BLS12_381_PUBLIC_KEY_LENGTH) {
    return {
      verified: false,
      error: `public key must be ${BLS12_381_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
    };
  }

  try {
    const pc = await getPairingCrypto();

    const request: BbsVerifyRequest = {
      publicKey,
      signature,
      header,
      messages,
    };

    const result: PairingCryptoBbsVerifyResult =
      await pc.bbs.bls12381_sha256.verify(request);
    return {
      verified: result.verified,
      error: result.error,
    };
  } catch (err) {
    return {
      verified: false,
      error: `BBS+ verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Verify a BBS+ selective disclosure proof using the BLS12-381 SHA-256 ciphersuite.
 *
 * A selective disclosure proof allows a holder to reveal only a subset of the
 * signed messages while still proving they possess a valid BBS+ signature
 * from the issuer. This enables privacy-preserving credential verification.
 *
 * @param publicKey - The issuer's BBS+ public key (96 bytes, BLS12-381 G2 point)
 * @param proof - The selective disclosure proof bytes
 * @param header - The header used during the original signing
 * @param presentationHeader - Additional header for the proof presentation context
 * @param disclosedMessages - Map of disclosed message index to message bytes
 * @returns Verification result indicating success or failure
 */
export async function verifyBbsProof(
  publicKey: Uint8Array,
  proof: Uint8Array,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  disclosedMessages: Map<number, Uint8Array>,
): Promise<BbsVerifyResult> {
  if (publicKey.length !== BLS12_381_PUBLIC_KEY_LENGTH) {
    return {
      verified: false,
      error: `public key must be ${BLS12_381_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
    };
  }

  try {
    const pc = await getPairingCrypto();

    // Convert Map to the index-keyed object that pairing-crypto expects.
    // BbsVerifyProofRequest.messages is { [key: number]: Uint8Array }.
    const messagesObj: { [key: number]: Uint8Array } = {};
    for (const [index, value] of disclosedMessages) {
      messagesObj[index] = value;
    }

    const request: BbsVerifyProofRequest = {
      publicKey,
      proof,
      header,
      presentationHeader,
      messages: messagesObj,
    };

    const result: PairingCryptoBbsVerifyResult =
      await pc.bbs.bls12381_sha256.verifyProof(request);
    return {
      verified: result.verified,
      error: result.error,
    };
  } catch (err) {
    return {
      verified: false,
      error: `BBS+ proof verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Verify a BBS+ selective disclosure proof with pseudonym verification
 * using the BLS12-381 SHA-256 ciphersuite.
 *
 * A pseudonym is a scope-bound identifier derived from the holder's secret
 * and a scope value. Same secret + same scope = same pseudonym, enabling
 * replay detection. Different scopes produce unrelated pseudonyms, preventing
 * cross-request correlation.
 *
 * Uses the AckAgent `bbs-ffi` WASM verifier to perform true cryptographic
 * pseudonym binding verification (`proof_verify_with_nym`). This validates
 * that:
 * - the selective disclosure proof is valid
 * - the pseudonym is correctly derived from the hidden signed nym secret
 * - the pseudonym binding matches the provided scope
 *
 * @param issuerPublicKey - The issuer's BBS+ public key (96 bytes, BLS12-381 G2 point)
 * @param proof - The selective disclosure proof bytes
 * @param pseudonym - Scope-bound pseudonym (48 bytes, compressed BLS12-381 G1 point)
 * @param header - The header used during the original signing
 * @param presentationHeader - Additional header for the proof presentation context
 * @param scope - Scope used for pseudonym derivation
 * @param disclosedMessages - Map of disclosed signer message index to message bytes
 * @param totalSignerMessages - Total number of signer messages in the credential
 * @param disclosedCommittedMessages - Map of disclosed committed message index to message bytes
 * @param disclosedCommitmentIndices - Indices of disclosed committed messages
 * @returns Verification result indicating success or failure
 */
export async function verifyBbsProofWithPseudonym(
  issuerPublicKey: Uint8Array,
  proof: Uint8Array,
  pseudonym: Uint8Array,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  scope: Uint8Array,
  disclosedMessages: Map<number, Uint8Array>,
  totalSignerMessages: number,
  disclosedCommittedMessages: Map<number, Uint8Array>,
  disclosedCommitmentIndices: number[],
): Promise<BbsVerifyResult> {
  // Validate pseudonym format: must be 48 bytes (compressed BLS12-381 G1 point)
  if (pseudonym.length !== BLS12_381_G1_COMPRESSED_LENGTH) {
    return {
      verified: false,
      error: `pseudonym must be ${BLS12_381_G1_COMPRESSED_LENGTH} bytes (compressed G1 point), got ${pseudonym.length}`,
    };
  }

  // Validate pseudonym is not all zeros (would indicate identity point / degenerate case)
  if (pseudonym.every((b) => b === 0)) {
    return {
      verified: false,
      error: "pseudonym must not be the identity point (all zeros)",
    };
  }

  // Validate public key shape before invoking WASM FFI path.
  if (issuerPublicKey.length !== BLS12_381_PUBLIC_KEY_LENGTH) {
    return {
      verified: false,
      error: `public key must be ${BLS12_381_PUBLIC_KEY_LENGTH} bytes, got ${issuerPublicKey.length}`,
    };
  }

  return verifyBbsProofWithPseudonymWasm(
    issuerPublicKey,
    proof,
    pseudonym,
    header,
    presentationHeader,
    scope,
    disclosedMessages,
    totalSignerMessages,
    disclosedCommittedMessages,
    disclosedCommitmentIndices,
  );
}
