/**
 * Blob service types, interfaces, and error classes
 */

import { NetworkError, CryptoError } from "./errors.js";

// ============================================================================
// Types (camelCase field names matching the blob OpenAPI spec)
// ============================================================================

/** Per-device wrapped encryption key */
export interface BlobWrappedKey {
  encryptionPublicKeyHex: string;
  ephemeralPublic: Uint8Array;
  wrappedKey: Uint8Array;
  wrappedKeyNonce: Uint8Array;
}

/** Response from blob GET/POST/PUT operations */
export interface BlobResponse {
  encryptedBlob: Uint8Array;
  blobNonce: Uint8Array;
  wrappedKeys: BlobWrappedKey[];
  version: number;
  updatedAt: Date;
}

/** Request body for creating/updating a blob */
export interface BlobRequest {
  encryptedBlob: Uint8Array;
  blobNonce: Uint8Array;
  wrappedKeys: BlobWrappedKey[];
}

/** Internal JSON payload shape used for blob create/update requests. */
export interface SerializedBlobRequest {
  encryptedBlob: string;
  blobNonce: string;
  wrappedKeys: Array<{
    encryptionPublicKeyHex: string;
    ephemeralPublicHex: string;
    wrappedKey: string;
    wrappedKeyNonce: string;
  }>;
}

/** Blob result with ETag for optimistic locking */
export interface BlobResult {
  response: BlobResponse;
  etag: string;
}

/** History entry metadata */
export interface HistoryEntry {
  version: number;
  createdAt: Date;
}

/** History list response */
export interface HistoryListResponse {
  history: HistoryEntry[];
}

/** History detail response */
export interface HistoryDetailResponse {
  encryptedBlob: Uint8Array;
  blobNonce: Uint8Array;
  wrappedKeys: BlobWrappedKey[];
  version: number;
  createdAt: Date;
}

/** Device info needed for wrapping keys */
export interface DeviceEncryptionInfo {
  encryptionPublicKeyHex: string;
  publicKey: Uint8Array; // P-256 33 bytes (compressed SEC1)
}

/** Key metadata stored in the encrypted blob */
export interface KeyMetadata {
  publicKeyHex: string;
  purpose: "ssh" | "gpg" | "age";
  label: string;
  storageType: "secure_enclave" | "software";
  deviceName: string;
  approverId?: string;
  publicKey?: string;
  createdAt: string;
  /** Organization ID this key belongs to (undefined for personal keys) */
  orgId?: string;
}

/** The decrypted contents of the blob */
export interface KeyMetadataBlob {
  keys: KeyMetadata[];
  updatedAt: Date;
}

/** Configuration for the blob client */
export interface BlobClientConfig {
  /** Base URL of the blob service */
  baseUrl: string;
  /** Organization ID for org-scoped blob operations */
  orgId: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

// ============================================================================
// Errors
// ============================================================================

/** Blob not found error */
export class BlobNotFoundError extends NetworkError {
  constructor() {
    super("Blob not found");
    this.name = "BlobNotFoundError";
  }
}

/** Version conflict error (optimistic locking failed) */
export class BlobVersionConflictError extends NetworkError {
  constructor() {
    super("Version conflict - please refetch and retry");
    this.name = "BlobVersionConflictError";
  }
}

/** No wrapped key found for this device */
export class NoWrappedKeyError extends CryptoError {
  constructor() {
    super("No wrapped key found for this device");
    this.name = "NoWrappedKeyError";
  }
}
