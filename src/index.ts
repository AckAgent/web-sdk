/**
 * AckAgent Web SDK
 *
 * TypeScript SDK for web-based authentication and signing with Secure Enclave keys.
 *
 * This SDK uses Web Crypto P-256 ECDH with non-extractable keys for enhanced security.
 * Keys are stored in IndexedDB using structured cloning.
 *
 * Browser Requirements: Chrome 113+, Safari 17+, Firefox 100+
 *
 * @example
 * ```typescript
 * import {
 *   checkWebCryptoSupport,
 *   login,
 *   storeAccount,
 *   loadAccount,
 *   requestWebApproval,
 * } from '@ackagent/web-sdk';
 *
 * // Check browser support
 * if (!(await checkWebCryptoSupport())) {
 *   alert('Please use a modern browser');
 *   return;
 * }
 *
 * // Login with OAuth and SAS verification
 * const result = await login(
 *   {
 *     relayUrl: 'https://relay.example.com',
 *     provider: 'apple',
 *     idToken: appleIdToken,
 *     name: 'My Web App',
 *   },
 *   (sas, devices) => {
 *     // Display SAS to user for verification
 *     console.log('Verify on your iOS device:', sas.emojiString);
 *     return true; // Continue waiting
 *   }
 * );
 *
 * // Store the account in IndexedDB
 * await storeAccount(result.account);
 *
 * // Later, load the account
 * const account = await loadAccount(result.account.userId);
 *
 * // Request web approval - browser metadata collected automatically
 * const approvalResult = await requestWebApproval(pairing, {
 *   title: 'Confirm Payment',
 *   description: '$50.00 to Merchant Corp',
 *   plaintext: `
 *     Payment Authorization
 *     Amount: $50.00
 *     Recipient: Merchant Corp
 *     Reference: INV-12345
 *   `.trim(),
 * });
 *
 * if (approvalResult.success) {
 *   console.log('Signature:', approvalResult.signature);
 *   console.log('Hash:', approvalResult.plaintextHash);
 * } else {
 *   console.error('Failed:', approvalResult.errorMessage);
 * }
 * ```
 */

// Types
export type {
  RequestStatus,
  RequesterSessionStatus,
  StoredAccount,
  UserDevice,
  UserOrganization,
  SigningResult,
  PairingSessionOptions,
  BackendRequestStatus,
  BackendRequesterSession,
  DeviceAttestation,
  // Web approval types
  BrowserMetadata,
  WebApprovalOptions,
  WebApprovalResult,
} from "./types.js";

export { SigningErrorCode } from "./types.js";

// Errors
export {
  SignerError,
  PairingError,
  SigningError,
  SigningRejectedError,
  SigningExpiredError,
  NetworkError,
  CryptoError,
  TimeoutError,
} from "./errors.js";

// Encoding utilities
export {
  base64urlEncode,
  base64urlDecode,
  base64Encode,
  base64Decode,
  uuidToBytes,
  bytesToUuid,
  generateUuid,
} from "./encoding.js";

// Crypto
export {
  generateKeyPair,
  sharedSecret,
  deriveRequestKey,
  deriveResponseKey,
  deriveWrappingKey,
  encrypt,
  decrypt,
  generateRandomBytes,
  requestIdToBytes,
  encryptForMultipleDevices,
  decryptFromMultiDevice,
  compressPublicKey,
  decompressPublicKey,
  checkWebCryptoSupport,
  UnsupportedBrowserError,
  KEY_SIZE,
  PUBLIC_KEY_SIZE,
  UNCOMPRESSED_PUBLIC_KEY_SIZE,
  NONCE_SIZE,
} from "./crypto.js";

export type {
  KeyPair,
  DeviceKey,
  WrappedKey,
  MultiDevicePayload,
} from "./crypto.js";

// SAS (Short Authentication String)
export {
  computeSAS,
  computeSASFromApproverKeys,
} from "./sas.js";
export type {
  SASApproverKey,
  ApproverKeyInfo,
  SASResult,
} from "./sas.js";

// Client
export { SignerClient, SessionClient } from "./client.js";
export type {
  ClientConfig,
  PollConfig,
  ApproverAttestationResponse,
  SessionLinkedOrganization,
} from "./client.js";

// Transport (pluggable transport layer)
export {
  TransportManager,
  RelayTransport,
  createRelayTransport,
  TransportError,
  NoTransportsError,
  AllTransportsFailedError,
} from "./transport/index.js";
export type {
  Transport,
  TransportRequest,
  TransportResponse,
  RelayTransportOptions,
} from "./transport/index.js";

// Local transports (BLE)
export {
  BluetoothTransport,
  createBluetoothTransport,
  isWebBluetoothSupported,
  ACKAGENT_SERVICE_UUID,
  REQUEST_CHARACTERISTIC_UUID,
  RESPONSE_CHARACTERISTIC_UUID,
  STATUS_CHARACTERISTIC_UUID,
  BLEFragmenter,
  BLEReassembler,
  encodeFragment,
  decodeFragment,
  BLE_MAX_FRAGMENT_SIZE,
  FragmentFlags,
} from "./transport/local/index.js";
export type {
  BluetoothTransportOptions,
  BLEFragment,
} from "./transport/local/index.js";

// Storage (IndexedDB)
export {
  openDatabase,
  storeAccount,
  loadAccount,
  deleteAccount,
  listAccounts,
  clearAllData,
  isIndexedDBAvailable,
} from "./storage.js";

// Web approval (browser-based signing)
export {
  requestWebApproval,
  requestWebApprovalWithTransport,
  approveWeb,
  collectBrowserMetadata,
  isBrowser,
} from "./web.js";

// Display schema
export { DisplaySchemaBuilder } from "./display.js";

export type {
  DisplayField,
  GenericDisplaySchema,
} from "./generated/protocol.js";

// Organization utilities
export { emojiFromIndex } from "./org.js";
export type { OrgEmoji } from "./org.js";

// Auth (QR Code Login - Web SDK is the requester)
export {
  RequesterSession,
  createRequesterSession,
  login,
  generateQRCodeUrl,
  isAccountValid,
  needsTokenRefresh,
  refreshTokens,
  updateAccountTokens,
} from "./auth.js";

export type {
  RequesterSessionOptions,
  LoginResult,
  TokenRefreshResult,
} from "./auth.js";

// Anonymous attestation verification (BBS+ selective disclosure)
export {
  AnonymousAttestationVerifier,
  buildScopedLinkingStoreScope,
  createAnonymousAttestationVerifier,
  verifyAnonymousAttestation,
  createAnonymousVerifier,
} from "./attestation.js";

export type {
  AttestationSecurityType,
  ApproverDeviceType,
  AnonymousAttestation,
  AnonymousAttestationScopedLinking,
  AnonymousAttestationScopedLinkingOptions,
  AnonymousAttestationInput,
  ScopedLinkingScopeType,
  AnonymousAttestationVerifyOptions,
  AnonymousAttestationVerificationResult,
} from "./attestation.js";

export type {
  DataIntegrityProof,
  W3CAnonymousAttestationEnvelope,
} from "./attestation-vc.js";

export {
  isW3CAnonymousAttestationEnvelope,
  parseW3CAnonymousAttestationEnvelope,
  toW3CAnonymousAttestationEnvelope,
} from "./attestation-vc.js";

// Blob service (encrypted key metadata storage)
export {
  BlobClient,
  BlobNotFoundError,
  BlobVersionConflictError,
  NoWrappedKeyError,
  encryptKeyMetadata,
  decryptKeyMetadata,
  decryptHistoryVersion,
} from "./blob.js";

export type {
  BlobClientConfig,
  BlobWrappedKey,
  BlobResponse,
  BlobRequest,
  BlobResult,
  HistoryEntry,
  HistoryListResponse,
  HistoryDetailResponse,
  DeviceEncryptionInfo,
  KeyMetadata,
  KeyMetadataBlob,
} from "./blob.js";

// Nullifier store (anonymous attestation replay prevention)
export {
  createAtomicNullifierStoreAdapter,
  createInMemoryNullifierStoreAdapter,
  createLocalStorageNullifierStoreAdapter,
  NullifierStore,
  createNullifierStore,
} from "./nullifier-store.js";
export type {
  NullifierStoreAdapter,
  NullifierStoreOptions,
} from "./nullifier-store.js";

// BBS+ signature verification (pairing-crypto WASM)
export {
  verifyBbsSignature,
  verifyBbsProof,
  verifyBbsProofWithPseudonym,
} from "./bbs.js";

export type {
  BbsVerifyResult,
  BbsPublicKey,
  BbsCredential,
} from "./bbs.js";

// Credential API (BBS+ issuer public key fetching)
export { CredentialAPIClient } from "./credential-api.js";

export type { BBSIssuerPublicKey } from "./credential-api.js";

// Version
export { VERSION } from "./version.js";

// Type-safe API client factories
export {
  createRelayClient,
  createAuthClient,
  createBlobClient,
} from "./api.js";
export type { RelayClient, AuthClient, BlobApiClient } from "./api.js";

// Generated protocol types for advanced use cases
// Note: BrowserMetadata, GenericDisplaySchema, DisplayField are also re-exported from ./types.js and ./display.js
export type {
  WebPayload,
  WebApprovalResponse,
  BasePayload,
  AckAgentCommonTransactionType,
  AckAgentCommonSigningErrorCode,
} from "./generated/protocol.js";
