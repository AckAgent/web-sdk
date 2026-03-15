/**
 * Type definitions for the AckAgent Web SDK
 *
 * Types that correspond to OpenAPI schemas are derived from generated types
 * to prevent spec drift. The OpenAPI specs are the single source of truth.
 */

import type { components as RelayComponents } from "@ackagent/api/relay";
import type { components as AuthComponents } from "@ackagent/api/auth";

/**
 * Status of a signing request, derived from the relay OpenAPI spec.
 * Privacy: Backend only knows 'pending', 'responded', or 'expired' - never 'approved' or 'rejected'
 * The actual decision is E2E encrypted and must be decrypted by the requester
 */
export type RequestStatus = NonNullable<
  RelayComponents["schemas"]["SigningRequestStatus"]["status"]
>;

/** Standardized error codes for signing responses */
export enum SigningErrorCode {
  Rejected = 1, // User explicitly rejected the request
  Expired = 2, // Request expired before user responded
  UnsupportedAlgorithm = 3, // Requested signing algorithm not available
  InvalidPairing = 4, // Pairing ID unknown or revoked
  KeyNotFound = 5, // Specified key ID doesn't exist
  InternalError = 6, // Unexpected error occurred
}

/** Result of a signing request */
export interface SigningResult {
  /** Whether the signing was successful */
  success: boolean;
  /** The signature (if successful) */
  signature?: Uint8Array;
  /** Error code (if unsuccessful) */
  errorCode?: SigningErrorCode;
  /** Error message (if unsuccessful) */
  errorMessage?: string;
}

/** Options for creating a pairing session */
export interface PairingSessionOptions {
  /** URL of the relay server */
  relayUrl: string;
  /** Display name for this requester (shown on signer device) */
  name: string;
  /** Expiration time in seconds (default: 300) */
  expiresIn?: number;
}

// Re-export BrowserMetadata from generated protocol types
export type { BrowserMetadata } from "./generated/protocol.js";

/** Options for a web approval request */
export interface WebApprovalOptions {
  /** Action-oriented title (e.g., "Confirm Payment") */
  title: string;
  /** Short description (e.g., "Transfer $50 to merchant") */
  description?: string;
  /** Full plaintext content for user to review - iOS signs sha256(plaintext) */
  plaintext: string;
  /** Key ID to use (optional - uses default if not specified) */
  keyId?: string;
  /** Lowercase hex-encoded signing public key to match (optional) */
  signingPublicKeyHex?: string;
  /** Expiration time in seconds (default: 300) */
  expiresIn?: number;
}

/** Result of a web approval request */
export interface WebApprovalResult {
  /** Whether the approval was successful */
  success: boolean;
  /** The signature over sha256(plaintext) (if successful) */
  signature?: Uint8Array;
  /** The hash that was signed, format: "sha256:hex" (if successful) */
  plaintextHash?: string;
  /** Error code (if unsuccessful) */
  errorCode?: SigningErrorCode;
  /** Error message (if unsuccessful) */
  errorMessage?: string;
}

/**
 * Status response from backend relay service.
 * Field names match the relay OpenAPI spec (camelCase).
 * Binary fields are decoded from base64 to Uint8Array by the client.
 */
export interface BackendRequestStatus {
  id: string;
  status: RequestStatus;
  /** Approver's ephemeral public key for response decryption */
  approverEphemeralKey?: Uint8Array;
  /** E2E encrypted response payload */
  encryptedResponse?: Uint8Array;
  /** Nonce for response decryption */
  responseNonce?: Uint8Array;
  /** When the response was received */
  respondedAt?: string;
  /** When the request expires */
  expiresAt: string;
}

// Organization Types

/** A user's organization membership */
export interface UserOrganization {
  /** Organization ID */
  organizationId: string;
  /** Organization emoji index for client-side rendering via emojiFromIndex() */
  orgEmojiIndex: number;
  /** User's sequential emoji index within the organization */
  userEmojiIndex: number;
  /** User's role in the organization (owner, audit, user_manager, member) */
  role: string;
  /** Organization tier (free, enterprise) */
  tier: string;
  /** Current number of members in the organization */
  memberCount: number;
  /** Local name from approver device (E2E encrypted, backend never sees plaintext) */
  localName?: string;
}

// Multi-Device User Account Types

/** A device in a user's account */
export interface UserDevice {
  deviceId: string;
  deviceName: string;
  publicKey: Uint8Array; // P-256 33 bytes (compressed SEC1)
  isPrimary: boolean;
}

/** A stored user account with multiple devices */
export interface StoredAccount {
  /** User ID from backend */
  userId: string;
  /** Access token for API calls */
  accessToken: string;
  /** Refresh token for token renewal (optional) */
  refreshToken?: string;
  /** Token expiration time */
  expiresAt: Date;
  /** When the account was logged in */
  loggedInAt: Date;
  /** Whether SAS verification completed */
  sasVerified: boolean;
  /** User's devices */
  devices: UserDevice[];
  /** Our P-256 ECDH identity private key - non-extractable CryptoKey */
  identityPrivateKey: CryptoKey;
  /** Our P-256 identity public key (33 bytes compressed) */
  identityPublicKey: Uint8Array;
  /** Relay server URL */
  relayUrl: string;
  /** User's organization memberships */
  organizations?: UserOrganization[];
  /** Default organization ID (auto-set when user belongs to a single org) */
  defaultOrgId?: string;
}

/**
 * Requester session status, derived from the auth OpenAPI spec.
 * Used for QR code login flow where the Web SDK is the requester.
 */
export type RequesterSessionStatus = AuthComponents["schemas"]["SessionStatus"];

/** Requester session from backend */
export interface BackendRequesterSession {
  id: string;
  status: RequesterSessionStatus;
  userId: string;
  devices: UserDevice[];
  expiresAt: string;
}

/** Device attestation included in responses */
export interface DeviceAttestation {
  deviceId: string;
  requestIdHash: Uint8Array;
  payloadHash: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
  attestationPublicKeyHex: string;
}
