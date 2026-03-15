/**
 * Type definitions for anonymous attestation verification.
 *
 * Extracted from attestation.ts for maintainability.
 */

import type { NullifierStore } from "./nullifier-store.js";
import type { CredentialAPIClient } from "./credential-api.js";

/**
 * AttestationSecurityType represents the attestation security level.
 * Matches AckAgent.Common.AttestationSecurityType in the OpenAPI spec.
 */
export type AttestationSecurityType =
  | "ios_secure_enclave"
  | "android_tee"
  | "android_strongbox"
  | "software";

/**
 * Device platform type.
 * Matches AckAgent.Common.ApproverDeviceType in the OpenAPI spec.
 */
export type ApproverDeviceType = "ios" | "android";

/**
 * Scope taxonomy for optional scoped-linking mode.
 */
export type ScopedLinkingScopeType =
  | "request"
  | "relying_party"
  | "organization";

/**
 * Optional scoped-linking metadata attached to an anonymous attestation.
 *
 * This is an AA-06 prototype surface for pairwise account-secret linking.
 * Default flows do not require this field.
 */
export interface AnonymousAttestationScopedLinking {
  /**
   * Prototype linking mechanism identifier.
   */
  mode: "pairwise_account_secret";
  /**
   * Scope taxonomy for linkability boundaries.
   */
  scopeType: ScopedLinkingScopeType;
  /**
   * Scope identifier (for example relying-party ID or org ID).
   */
  scopeId: string;
  /**
   * Pairwise link handle (opaque, URL-safe identifier).
   */
  linkHandle: string;
}

/**
 * Anonymous attestation data extracted from a decrypted signing response.
 * Matches AckAgent.Common.AnonymousAttestation in the OpenAPI spec.
 */
export interface AnonymousAttestation {
  /** BBS+ selective disclosure proof with pseudonym. */
  bbsProof: Uint8Array;
  /** Scope-bound pseudonym (48 bytes compressed G1 point). */
  pseudonym: Uint8Array;
  /** Scope used for pseudonym derivation (request ID). */
  scope: string;
  /** Presentation header bound to the proof. */
  presentationHeader: Uint8Array;
  /** Issuer public key ID for key rotation support. */
  issuerPublicKeyId?: string;
  /** Messages disclosed by the BBS+ selective disclosure proof. */
  revealedMessages: {
    /** Attestation security type (e.g., "ios_secure_enclave"). */
    attestationType: AttestationSecurityType;
    /** Device platform type ("ios" or "android"). */
    deviceType: ApproverDeviceType;
    /** Credential expiry as Unix epoch seconds. */
    expiresAt: number;
  };
  /**
   * Optional scoped-linking metadata used by the AA-06 prototype.
   *
   * When verifier policy enables scoped linking, this field becomes required.
   */
  scopedLinking?: AnonymousAttestationScopedLinking;
}

/**
 * Accepted anonymous attestation input formats.
 *
 * - Native protocol payload (`AnonymousAttestation`)
 * - W3C/Data-Integrity envelope (`W3CAnonymousAttestationEnvelope`)
 */
export type AnonymousAttestationInput =
  | AnonymousAttestation
  | W3CAnonymousAttestationEnvelope;

/**
 * Options for anonymous attestation verification.
 */
export interface AnonymousAttestationVerifyOptions {
  /**
   * CredentialAPIClient for fetching issuer public keys.
   * If not provided, issuerPublicKey must be passed directly.
   */
  credentialClient?: CredentialAPIClient;
  /**
   * Issuer public key bytes (96 bytes, BLS12-381 G2 point).
   * Used when credentialClient is not provided, or to override the fetched key.
   */
  issuerPublicKey?: Uint8Array;
  /**
   * NullifierStore for pseudonym-based replay prevention.
   * If provided, the pseudonym is checked and recorded after successful verification.
   */
  nullifierStore?: NullifierStore;
  /**
   * Expected request ID that the scope must match.
   * If provided, verification fails when scope does not match this value.
   */
  expectedRequestId?: string;
  /**
   * Optional scoped-linking policy (AA-06 prototype).
   *
   * When provided, verifier enforces that attestation.scopedLinking matches
   * the configured scope boundary and link handle requirements.
   */
  scopedLinking?: AnonymousAttestationScopedLinkingOptions;
}

/**
 * Verifier policy for optional scoped-linking mode.
 */
export interface AnonymousAttestationScopedLinkingOptions {
  /**
   * Required scope taxonomy for this verifier path.
   */
  scopeType: ScopedLinkingScopeType;
  /**
   * Required scope identifier for this verifier path.
   */
  scopeId: string;
  /**
   * Optional expected link handle when caller has account context.
   */
  expectedLinkHandle?: string;
  /**
   * Optional store for deduplicating scoped link handles.
   *
   * If omitted, verifier falls back to `nullifierStore` when available.
   */
  store?: NullifierStore;
  /**
   * Optional TTL override for scoped-linking handle retention.
   */
  ttlMs?: number;
}

/**
 * Result of anonymous attestation verification.
 */
export interface AnonymousAttestationVerificationResult {
  /** Whether the overall verification succeeded. */
  valid: boolean;
  /** Whether the BBS+ proof verified successfully. */
  proofValid: boolean;
  /**
   * Whether the pseudonym is cryptographically verified as derived from the
   * holder's signed nymSecret and the proof scope.
   */
  pseudonymVerified: boolean;
  /** Whether the credential has not expired. */
  notExpired: boolean;
  /** Whether the scope matches the expected request ID. */
  scopeValid: boolean;
  /** The attestation security type from the revealed messages. */
  attestationType: AttestationSecurityType;
  /** The device type from the revealed messages. */
  deviceType: ApproverDeviceType;
  /** The scope-bound pseudonym (hex-encoded for storage). */
  pseudonymHex: string;
  /** When verification was performed. */
  verifiedAt: Date;
  /** Error messages for any checks that failed. */
  errors: string[];
  /** Whether optional scoped-linking policy checks passed. */
  scopedLinkingVerified: boolean;
  /** Namespaced scoped-linking storage scope when enabled. */
  scopedLinkingScope?: string;
  /** Normalized scoped-linking handle when enabled. */
  scopedLinkingHandle?: string;
  /** Whether the scoped-linking handle was previously observed. */
  scopedLinkingSeenBefore: boolean;
}

// Re-export the W3C envelope type from attestation-vc for convenience
import type { W3CAnonymousAttestationEnvelope } from "./attestation-vc.js";
export type { W3CAnonymousAttestationEnvelope };
