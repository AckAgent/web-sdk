/**
 * Anonymous attestation verification using BBS+ selective disclosure proofs.
 *
 * This module verifies that a signing response came from a genuine device
 * with a valid BBS+ credential from a known issuer, without revealing device
 * identity. The anonymous attestation travels inside the encrypted response
 * blob so the relay stays completely blind.
 *
 * Credential attributes (4 total, indices 0-3):
 *   0: attestationType  (disclosed)
 *   1: deviceType        (disclosed)
 *   2: issuedAt          (hidden)
 *   3: expiresAt         (disclosed)
 *
 * Message encoding:
 *   - Strings (attestationType, deviceType): UTF-8 bytes
 *   - Integers (issuedAt, expiresAt): 8-byte big-endian (int64)
 */

import { verifyBbsProofWithPseudonym, type BbsVerifyResult } from "./bbs.js";
import { hexEncode } from "./encoding.js";
import { NullifierStore } from "./nullifier-store.js";
import {
  isW3CAnonymousAttestationEnvelope,
  parseW3CAnonymousAttestationEnvelope,
  toW3CAnonymousAttestationEnvelope,
  type W3CAnonymousAttestationEnvelope,
} from "./attestation-vc.js";

// Re-export all types from attestation-types for backwards compatibility
export type {
  AttestationSecurityType,
  ApproverDeviceType,
  ScopedLinkingScopeType,
  AnonymousAttestationScopedLinking,
  AnonymousAttestation,
  AnonymousAttestationInput,
  AnonymousAttestationVerifyOptions,
  AnonymousAttestationScopedLinkingOptions,
  AnonymousAttestationVerificationResult,
} from "./attestation-types.js";

import type {
  AttestationSecurityType,
  ApproverDeviceType,
  AnonymousAttestation,
  AnonymousAttestationInput,
  AnonymousAttestationVerifyOptions,
  AnonymousAttestationVerificationResult,
} from "./attestation-types.js";

// =============================================================================
// Constants
// =============================================================================

/** Header used when signing BBS+ credentials for anonymous attestation. */
const CREDENTIAL_HEADER = "ackagent-anonymous-attestation-v2";

/** Total number of signer messages in the credential. */
const TOTAL_SIGNER_MESSAGES = 4;

/** Expected length of a compressed BLS12-381 G1 pseudonym in bytes. */
const PSEUDONYM_LENGTH = 48;

/** Allowed scope ID characters for scoped-linking namespaces. */
const SCOPED_LINKING_SCOPE_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/** Allowed handle format for scoped-linking identifiers (base64url-like). */
const SCOPED_LINKING_HANDLE_PATTERN = /^[A-Za-z0-9_-]{16,256}$/;

// =============================================================================
// Verifier
// =============================================================================

/**
 * Verifier for BBS+ anonymous attestation proofs.
 *
 * Verifies that a signing response contains a valid BBS+ selective disclosure
 * proof from a known issuer, with a valid scope-bound pseudonym. This proves
 * the response came from a genuine device without revealing device identity.
 *
 * @example
 * ```typescript
 * const verifier = new AnonymousAttestationVerifier();
 * const result = await verifier.verify(attestation, {
 *   credentialClient: new CredentialAPIClient('https://auth.example.com'),
 *   expectedRequestId: requestId,
 * });
 * if (result.valid) {
 *   console.log('Attestation verified:', result.attestationType);
 * }
 * ```
 */
export class AnonymousAttestationVerifier {
  /**
   * Verify an anonymous attestation from a decrypted signing response.
   *
   * Verification steps:
   * 1. Validate scope matches expected request ID (if provided)
   * 2. Check credential expiry (expiresAt > current time)
   * 3. Fetch issuer public key (via CredentialAPIClient or direct key)
   * 4. Encode revealed messages to bytes
   * 5. Verify the BBS+ selective disclosure proof with pseudonym
   * 6. Check pseudonym for replay (if NullifierStore provided)
   * 7. Optionally enforce scoped-linking policy (AA-06 prototype)
   */
  async verify(
    attestationInput: AnonymousAttestationInput,
    options: AnonymousAttestationVerifyOptions = {},
  ): Promise<AnonymousAttestationVerificationResult> {
    const seed = extractResultSeed(attestationInput);

    const result: AnonymousAttestationVerificationResult = {
      valid: false,
      proofValid: false,
      pseudonymVerified: false,
      notExpired: false,
      scopeValid: false,
      attestationType: seed.attestationType,
      deviceType: seed.deviceType,
      pseudonymHex: seed.pseudonymHex,
      verifiedAt: new Date(),
      errors: [],
      scopedLinkingVerified: false,
      scopedLinkingSeenBefore: false,
    };

    let attestation: AnonymousAttestation;
    try {
      const envelope =
        normalizeAnonymousAttestationInputToW3CEnvelope(attestationInput);
      attestation = parseW3CAnonymousAttestationEnvelope(envelope);
      result.attestationType = attestation.revealedMessages.attestationType;
      result.deviceType = attestation.revealedMessages.deviceType;
      result.pseudonymHex = hexEncode(attestation.pseudonym);
    } catch (err) {
      const parseErrorMessage =
        err instanceof Error
          ? err.message
          : "failed to parse anonymous attestation";
      result.errors.push(
        parseErrorMessage === "W3C envelope missing scope"
          ? "scope must not be empty"
          : parseErrorMessage,
      );
      return result;
    }

    // 1. Validate scope matches expected request ID
    if (options.expectedRequestId) {
      if (attestation.scope !== options.expectedRequestId) {
        result.errors.push(
          `scope mismatch: expected "${options.expectedRequestId}", got "${attestation.scope}"`,
        );
        return result;
      }
    }
    if (!attestation.scope || attestation.scope.length === 0) {
      result.errors.push("scope must not be empty");
      return result;
    }
    result.scopeValid = true;

    // 2. Check credential expiry
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    if (attestation.revealedMessages.expiresAt <= nowEpochSeconds) {
      result.errors.push(
        `credential expired: expiresAt=${attestation.revealedMessages.expiresAt}, now=${nowEpochSeconds}`,
      );
      return result;
    }
    result.notExpired = true;

    // 3. Validate pseudonym format
    if (attestation.pseudonym.length !== PSEUDONYM_LENGTH) {
      result.errors.push(
        `pseudonym must be ${PSEUDONYM_LENGTH} bytes, got ${attestation.pseudonym.length}`,
      );
      return result;
    }

    // 4. Obtain issuer public key
    let issuerPublicKey: Uint8Array;
    if (options.issuerPublicKey) {
      issuerPublicKey = options.issuerPublicKey;
    } else if (options.credentialClient) {
      try {
        const bbsKey = await options.credentialClient.getBbsPublicKey(
          attestation.issuerPublicKeyId,
        );
        issuerPublicKey = bbsKey.publicKeyBytes;
      } catch (err) {
        result.errors.push(
          `failed to fetch issuer public key: ${err instanceof Error ? err.message : String(err)}`,
        );
        return result;
      }
    } else {
      result.errors.push(
        "either issuerPublicKey or credentialClient must be provided",
      );
      return result;
    }

    // 5. Encode revealed messages to bytes for proof verification
    const disclosedMessages = encodeDisclosedMessages(
      attestation.revealedMessages.attestationType,
      attestation.revealedMessages.deviceType,
      attestation.revealedMessages.expiresAt,
    );

    // 6. Verify the BBS+ proof with pseudonym
    const headerBytes = new TextEncoder().encode(CREDENTIAL_HEADER);
    const scopeBytes = new TextEncoder().encode(attestation.scope);

    const bbsResult: BbsVerifyResult = await verifyBbsProofWithPseudonym(
      issuerPublicKey,
      attestation.bbsProof,
      attestation.pseudonym,
      headerBytes,
      attestation.presentationHeader,
      scopeBytes,
      disclosedMessages,
      TOTAL_SIGNER_MESSAGES,
      new Map(), // No disclosed committed messages
      [], // No disclosed commitment indices
    );

    if (!bbsResult.verified) {
      result.errors.push(bbsResult.error ?? "BBS+ proof verification failed");
      return result;
    }
    result.proofValid = true;
    result.pseudonymVerified = true;

    // 7. Check pseudonym for replay (if NullifierStore provided)
    if (options.nullifierStore) {
      const pseudonymHex = result.pseudonymHex;
      const alreadySpent = await options.nullifierStore.checkAndMarkSpent(
        attestation.scope,
        pseudonymHex,
      );
      if (alreadySpent) {
        result.errors.push("pseudonym already used for this scope");
        return result;
      }
    }

    // 8. Optional scoped-linking policy enforcement (AA-06 prototype)
    if (options.scopedLinking) {
      const linkingResult = await verifyScopedLinking(
        attestation,
        options,
        result,
      );
      if (!linkingResult) return result;
    }

    result.valid = true;
    return result;
  }
}

// =============================================================================
// Convenience functions
// =============================================================================

/**
 * Create an anonymous attestation verifier.
 */
export function createAnonymousAttestationVerifier(): AnonymousAttestationVerifier {
  return new AnonymousAttestationVerifier();
}

/**
 * Verify anonymous attestation data (convenience function).
 */
export async function verifyAnonymousAttestation(
  attestation: AnonymousAttestationInput,
  options: AnonymousAttestationVerifyOptions = {},
): Promise<AnonymousAttestationVerificationResult> {
  const verifier = new AnonymousAttestationVerifier();
  return verifier.verify(attestation, options);
}

/**
 * Create a verifier and nullifier store pair for anonymous attestation verification.
 */
export function createAnonymousVerifier(nullifierStorageKey?: string): {
  verifier: AnonymousAttestationVerifier;
  nullifierStore: NullifierStore;
} {
  return {
    verifier: new AnonymousAttestationVerifier(),
    nullifierStore: new NullifierStore(nullifierStorageKey),
  };
}

/**
 * Build a namespaced storage scope for scoped-linking records.
 */
export function buildScopedLinkingStoreScope(
  scopeType: string,
  scopeId: string,
): string {
  if (!SCOPED_LINKING_SCOPE_ID_PATTERN.test(scopeId)) {
    throw new Error(
      `invalid scoped linking scopeId: "${scopeId}" (allowed: [A-Za-z0-9._-], length 1-128)`,
    );
  }
  return `ackagent_link:${scopeType}:${scopeId}`;
}

// =============================================================================
// Internal helpers
// =============================================================================

/**
 * Encode the disclosed credential messages as a Map for BBS+ proof verification.
 */
function encodeDisclosedMessages(
  attestationType: string,
  deviceType: string,
  expiresAt: number,
): Map<number, Uint8Array> {
  const encoder = new TextEncoder();
  const messages = new Map<number, Uint8Array>();
  messages.set(0, encoder.encode(attestationType));
  messages.set(1, encoder.encode(deviceType));
  // Index 2 (issuedAt) is hidden
  messages.set(3, encodeInt64BigEndian(expiresAt));
  return messages;
}

function encodeInt64BigEndian(value: number): Uint8Array {
  const buf = new Uint8Array(8);
  const bigValue = BigInt(value);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number((bigValue >> BigInt((7 - i) * 8)) & 0xffn);
  }
  return buf;
}

function normalizeAnonymousAttestationInputToW3CEnvelope(
  attestation: AnonymousAttestationInput,
): W3CAnonymousAttestationEnvelope {
  if (isW3CAnonymousAttestationEnvelope(attestation)) {
    return attestation;
  }
  return toW3CAnonymousAttestationEnvelope(attestation);
}

function normalizeScopedLinkingHandle(handle: string): string | null {
  const normalized = handle.trim().toLowerCase();
  if (!SCOPED_LINKING_HANDLE_PATTERN.test(normalized)) {
    return null;
  }
  return normalized;
}

function extractResultSeed(
  attestation: AnonymousAttestationInput,
): Pick<
  AnonymousAttestationVerificationResult,
  "attestationType" | "deviceType" | "pseudonymHex"
> {
  if (!isW3CAnonymousAttestationEnvelope(attestation)) {
    return {
      attestationType: attestation.revealedMessages.attestationType,
      deviceType: attestation.revealedMessages.deviceType,
      pseudonymHex: hexEncode(attestation.pseudonym),
    };
  }

  const body = attestation.ackagentAnonymousAttestation;
  const revealed = body.revealedMessages;
  const attestationType = isAttestationType(revealed.attestationType)
    ? revealed.attestationType
    : "software";
  const deviceType: ApproverDeviceType =
    revealed.deviceType === "android" ? "android" : "ios";

  return { attestationType, deviceType, pseudonymHex: "" };
}

function isAttestationType(value: unknown): value is AttestationSecurityType {
  return (
    value === "ios_secure_enclave" ||
    value === "android_tee" ||
    value === "android_strongbox" ||
    value === "software"
  );
}

/**
 * Verify scoped-linking policy. Returns false if verification failed (errors added to result).
 */
async function verifyScopedLinking(
  attestation: AnonymousAttestation,
  options: AnonymousAttestationVerifyOptions,
  result: AnonymousAttestationVerificationResult,
): Promise<boolean> {
  const policy = options.scopedLinking!;
  const scopedLinking = attestation.scopedLinking;

  if (!scopedLinking) {
    result.errors.push(
      "scoped linking enabled but attestation.scopedLinking is missing",
    );
    return false;
  }
  if (scopedLinking.mode !== "pairwise_account_secret") {
    result.errors.push(
      `unsupported scoped linking mode: ${scopedLinking.mode}`,
    );
    return false;
  }
  if (scopedLinking.scopeType !== policy.scopeType) {
    result.errors.push(
      `scoped linking scopeType mismatch: expected "${policy.scopeType}", got "${scopedLinking.scopeType}"`,
    );
    return false;
  }
  if (scopedLinking.scopeId !== policy.scopeId) {
    result.errors.push(
      `scoped linking scopeId mismatch: expected "${policy.scopeId}", got "${scopedLinking.scopeId}"`,
    );
    return false;
  }

  const normalizedLinkHandle = normalizeScopedLinkingHandle(
    scopedLinking.linkHandle,
  );
  if (!normalizedLinkHandle) {
    result.errors.push(
      "scoped linking handle must be 16-256 URL-safe characters",
    );
    return false;
  }

  if (policy.expectedLinkHandle) {
    const expectedLinkHandle = normalizeScopedLinkingHandle(
      policy.expectedLinkHandle,
    );
    if (!expectedLinkHandle) {
      result.errors.push(
        "expectedLinkHandle must be 16-256 URL-safe characters",
      );
      return false;
    }
    if (normalizedLinkHandle !== expectedLinkHandle) {
      result.errors.push("scoped linking handle mismatch");
      return false;
    }
  }

  let scopedLinkingScope: string;
  try {
    scopedLinkingScope = buildScopedLinkingStoreScope(
      scopedLinking.scopeType,
      scopedLinking.scopeId,
    );
  } catch (err) {
    result.errors.push(
      err instanceof Error ? err.message : "invalid scoped linking scope",
    );
    return false;
  }

  const scopedLinkingStore = policy.store ?? options.nullifierStore;
  let scopedLinkingSeenBefore = false;
  if (scopedLinkingStore) {
    scopedLinkingSeenBefore = await scopedLinkingStore.checkAndMarkSpent(
      scopedLinkingScope,
      normalizedLinkHandle,
      policy.ttlMs,
    );
  }

  result.scopedLinkingVerified = true;
  result.scopedLinkingScope = scopedLinkingScope;
  result.scopedLinkingHandle = normalizedLinkHandle;
  result.scopedLinkingSeenBefore = scopedLinkingSeenBefore;
  return true;
}
