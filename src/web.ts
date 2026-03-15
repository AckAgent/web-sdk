/**
 * Web approval request management for browser-based signing
 */

import type {
  WebApprovalOptions,
  WebApprovalResult,
  StoredAccount,
  BackendRequestStatus,
  UserDevice,
} from "./types.js";
import { SigningErrorCode } from "./types.js";
import {
  SigningError,
  SigningRejectedError,
  SigningExpiredError,
  CryptoError,
} from "./errors.js";
import { base64Decode, base64Encode, hexEncode } from "./encoding.js";
import { SignerClient } from "./client.js";
import type { PollConfig } from "./client.js";
import {
  generateKeyPair,
  deriveResponseKey,
  decrypt,
  requestIdToBytes,
  encryptForMultipleDevices,
  type DeviceKey,
} from "./crypto.js";
import { collectBrowserMetadata } from "./browser.js";
import { DisplaySchemaBuilder } from "./display.js";
import type { TransportRequest, TransportResponse } from "./transport/index.js";
// Generated protocol types for type-safe payload construction
import type { WebPayload, WebApprovalResponse } from "./generated/protocol.js";

const DEFAULT_EXPIRES_IN = 300; // 5 minutes

type TransportSender = {
  send(
    request: TransportRequest,
    timeoutMs: number,
    pollConfig?: PollConfig,
  ): Promise<TransportResponse>;
};

type WebApprovalRequestBuild = {
  request: TransportRequest;
  requestIdBytes: Uint8Array;
  ephemeralPrivateKey: CryptoKey;
  expiresIn: number;
};

/**
 * Resolve the target devices for encryption.
 * If a deviceId is specified, returns only that device.
 * Otherwise, returns all account devices so the payload is encrypted for every device.
 * @internal
 */
function resolveTargetDevices(
  account: StoredAccount,
  deviceId?: string,
): UserDevice[] {
  if (deviceId) {
    const device = account.devices.find((d) => d.deviceId === deviceId);
    return device ? [device] : [];
  }
  return account.devices;
}

/**
 * Build a TransportRequest and associated crypto metadata for web approval.
 * Encrypts the payload for all account devices using per-device key wrapping,
 * so any device can decrypt the request.
 * @internal
 */
async function buildWebApprovalRequest(
  account: StoredAccount,
  devices: UserDevice[],
  options: WebApprovalOptions,
): Promise<WebApprovalRequestBuild> {
  const expiresIn = options.expiresIn ?? DEFAULT_EXPIRES_IN;

  // Collect browser metadata (throws if not in browser)
  const browserMetadata = collectBrowserMetadata();

  // Generate ephemeral key pair for response decryption (forward secrecy)
  const ephemeralKeyPair = await generateKeyPair();

  const requestId = crypto.randomUUID();
  const requestIdBytes = requestIdToBytes(requestId);

  // Build display schema for iOS UI
  const displayBuilder = new DisplaySchemaBuilder(options.title);

  if (options.description) {
    displayBuilder.subtitle(options.description);
  }

  // Add plaintext as an expandable multiline field
  displayBuilder.addCustomField("Content", options.plaintext, {
    multiline: true,
    expandable: true,
  });

  // Add browser context
  displayBuilder.addMonospaceField("Origin", browserMetadata.origin);

  if (browserMetadata.pageTitle) {
    displayBuilder.addField("Page", browserMetadata.pageTitle);
  }

  // Build the WebPayload with type safety from generated protocol types
  const webPayload: WebPayload = {
    type: "web",
    title: options.title,
    description: options.description,
    plaintext: options.plaintext,
    browserMetadata: browserMetadata,
    display: displayBuilder.build(),
  };
  const payload = JSON.stringify(webPayload);
  const payloadBytes = new TextEncoder().encode(payload);

  // Build device keys for multi-device encryption
  const deviceKeys: DeviceKey[] = devices
    .filter((d) => d.publicKey.length === 33)
    .map((d) => ({
      deviceId: d.deviceId,
      publicKey: d.publicKey,
    }));

  // Encrypt the payload for all devices using per-device key wrapping
  const multiDevicePayload = await encryptForMultipleDevices(
    payloadBytes,
    deviceKeys,
    requestIdBytes,
  );

  // Convert wrapped keys to the relay API format (hex/base64 encoded)
  const wrappedKeys = multiDevicePayload.wrapped_keys.map((wk) => ({
    encryptionPublicKeyHex: hexEncode(
      devices.find((d) => d.deviceId === wk.device_id)?.publicKey ??
        new Uint8Array(),
    ),
    wrappedKey: base64Encode(wk.wrapped_key),
    wrappedKeyNonce: base64Encode(wk.wrapped_key_nonce),
    requesterEphemeralKeyHex: hexEncode(wk.ephemeral_public),
  }));

  // Create the request
  const timestamp = Date.now();
  const request: TransportRequest = {
    id: requestId,
    pairingId: account.userId,
    keyId: options.keyId,
    signingPublicKeyHex: options.signingPublicKeyHex,
    ephemeralPublic: ephemeralKeyPair.publicKey,
    encryptedPayload: multiDevicePayload.encrypted_payload,
    payloadNonce: multiDevicePayload.payload_nonce,
    expiresIn,
    timestamp,
    wrappedKeys,
  };

  return {
    request,
    requestIdBytes,
    ephemeralPrivateKey: ephemeralKeyPair.privateKey,
    expiresIn,
  };
}

/**
 * Convert a transport response into the backend status shape expected by response processing.
 * @internal
 */
function transportResponseToBackendStatus(
  response: TransportResponse,
): BackendRequestStatus {
  return {
    id: response.id,
    status: response.status,
    approverEphemeralKey: response.ephemeralPublic,
    encryptedResponse: response.encryptedResponse,
    responseNonce: response.responseNonce,
    respondedAt: response.respondedAt,
    expiresAt: response.expiresAt,
  };
}

/**
 * Throw an appropriate error for an unsuccessful WebApprovalResult.
 * @internal
 */
function throwWebApprovalError(result: WebApprovalResult): never {
  if (result.errorCode === SigningErrorCode.Rejected) {
    throw new SigningRejectedError(result.errorMessage);
  }
  if (result.errorCode === SigningErrorCode.Expired) {
    throw new SigningExpiredError();
  }
  throw new SigningError(
    result.errorCode ?? SigningErrorCode.InternalError,
    result.errorMessage ?? "Unknown error",
  );
}

/**
 * Request web approval from a user's device.
 *
 * This function sends plaintext content to the iOS approver, which displays it
 * to the user, computes sha256(plaintext), and signs that hash. Browser metadata
 * is automatically collected and included in the request.
 *
 * @param account - The stored account with device(s)
 * @param options - Web approval options (title, description, plaintext)
 * @param deviceId - Optional device ID to send to (defaults to primary device)
 * @param timeoutMs - Maximum time to wait for response in milliseconds (default: expiresIn * 1000)
 * @returns The approval result with signature and plaintext hash
 *
 * @example
 * ```typescript
 * const result = await requestWebApproval(account, {
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
 * if (result.success) {
 *   console.log('Signature:', result.signature);
 *   console.log('Hash:', result.plaintextHash);
 * }
 * ```
 */
export async function requestWebApproval(
  account: StoredAccount,
  options: WebApprovalOptions,
  deviceId?: string,
  timeoutMs?: number,
): Promise<WebApprovalResult> {
  // Determine which devices to encrypt for
  const devices = resolveTargetDevices(account, deviceId);
  if (devices.length === 0) {
    return {
      success: false,
      errorCode: SigningErrorCode.KeyNotFound,
      errorMessage: deviceId
        ? `Device not found: ${deviceId}`
        : "No devices available in account",
    };
  }

  const { request, requestIdBytes, ephemeralPrivateKey, expiresIn } =
    await buildWebApprovalRequest(account, devices, options);

  const client = new SignerClient(account.relayUrl);
  const result = await client.createSigningRequest({
    id: request.id,
    pairingId: request.pairingId,
    keyId: request.keyId,
    signingPublicKeyHex: request.signingPublicKeyHex,
    ephemeralPublic: request.ephemeralPublic,
    encryptedPayload: request.encryptedPayload,
    payloadNonce: request.payloadNonce,
    expiresIn: request.expiresIn,
    timestamp: request.timestamp,
    wrappedKeys: request.wrappedKeys,
  });

  // Wait for response using exponential backoff polling
  const timeout = timeoutMs ?? expiresIn * 1000;
  const status = await client.pollSigningResponse(result.id, timeout);

  // Process the response
  return await processResponse(status, ephemeralPrivateKey, requestIdBytes);
}

/**
 * Request web approval using a custom transport (e.g. Web Bluetooth).
 *
 * The transport must support sending TransportRequest objects and returning
 * a TransportResponse. This enables local transport testing without using the relay.
 *
 * @param account - The stored account with device(s)
 * @param options - Web approval options (title, description, plaintext)
 * @param transport - Transport or manager used to send the request
 * @param deviceId - Optional device ID to send to (defaults to primary device)
 * @param timeoutMs - Maximum time to wait for response in milliseconds
 * @param pollConfig - Optional polling configuration (used by relay transport)
 */
export async function requestWebApprovalWithTransport(
  account: StoredAccount,
  options: WebApprovalOptions,
  transport: TransportSender,
  deviceId?: string,
  timeoutMs?: number,
  pollConfig?: PollConfig,
): Promise<WebApprovalResult> {
  // Determine which devices to encrypt for
  const devices = resolveTargetDevices(account, deviceId);
  if (devices.length === 0) {
    return {
      success: false,
      errorCode: SigningErrorCode.KeyNotFound,
      errorMessage: deviceId
        ? `Device not found: ${deviceId}`
        : "No devices available in account",
    };
  }

  const { request, requestIdBytes, ephemeralPrivateKey, expiresIn } =
    await buildWebApprovalRequest(account, devices, options);

  const timeout = timeoutMs ?? expiresIn * 1000;
  const response = await transport.send(request, timeout, pollConfig);
  const status = transportResponseToBackendStatus(response);

  return await processResponse(status, ephemeralPrivateKey, requestIdBytes);
}

/**
 * Process a web approval response from the backend.
 * Privacy: Backend only returns "responded" - we must decrypt to determine if approved or rejected.
 */
async function processResponse(
  status: BackendRequestStatus,
  ephemeralPrivateKey: CryptoKey,
  requestId: Uint8Array,
): Promise<WebApprovalResult> {
  if (status.status === "expired") {
    return {
      success: false,
      errorCode: SigningErrorCode.Expired,
      errorMessage: "Web approval request expired",
    };
  }

  // Privacy: Backend only knows "responded" - not approved or rejected
  if (status.status !== "responded") {
    return {
      success: false,
      errorCode: SigningErrorCode.InternalError,
      errorMessage: `Unexpected status: ${status.status}`,
    };
  }

  // Decrypt the response to learn the decision
  if (
    !status.encryptedResponse ||
    !status.responseNonce ||
    !status.approverEphemeralKey
  ) {
    return {
      success: false,
      errorCode: SigningErrorCode.InternalError,
      errorMessage: "Missing encrypted response data",
    };
  }

  try {
    // Derive response decryption key
    const responseKey = await deriveResponseKey(
      ephemeralPrivateKey,
      status.approverEphemeralKey,
      requestId,
    );

    // Decrypt the response (request ID as AAD binds response to this request)
    const decrypted = decrypt(
      responseKey,
      status.responseNonce,
      status.encryptedResponse,
      requestId,
    );
    const responseJson = new TextDecoder().decode(decrypted);
    const response = JSON.parse(responseJson) as WebApprovalResponse;

    // Check for successful response (has signature and plaintextHash)
    if (response.signature && response.plaintextHash) {
      const signature = base64Decode(response.signature);
      return {
        success: true,
        signature,
        plaintextHash: response.plaintextHash,
      };
    }

    // Check for error response
    if (response.errorCode !== undefined) {
      return {
        success: false,
        errorCode: response.errorCode as SigningErrorCode,
        errorMessage: response.errorMessage ?? "Unknown error",
      };
    }

    return {
      success: false,
      errorCode: SigningErrorCode.InternalError,
      errorMessage: "Invalid response format",
    };
  } catch (error) {
    if (error instanceof CryptoError) {
      return {
        success: false,
        errorCode: SigningErrorCode.InvalidPairing,
        errorMessage: "Failed to decrypt response - pairing may be invalid",
      };
    }
    throw error;
  }
}

/**
 * Request web approval and throw on failure.
 * Returns the signature and plaintext hash on success.
 *
 * @param account - The stored account with device(s)
 * @param options - Web approval options
 * @param deviceId - Optional device ID to send to (defaults to primary device)
 * @param timeoutMs - Maximum time to wait for response in milliseconds
 * @returns Object with signature bytes and plaintext hash
 * @throws SigningError on failure
 *
 * @example
 * ```typescript
 * try {
 *   const { signature, plaintextHash } = await approveWeb(account, {
 *     title: 'Confirm Action',
 *     description: 'Approve this action',
 *     plaintext: 'Action details here...',
 *   });
 *   console.log('Approved! Hash:', plaintextHash);
 * } catch (error) {
 *   if (error instanceof SigningRejectedError) {
 *     console.log('User rejected the request');
 *   }
 * }
 * ```
 */
export async function approveWeb(
  account: StoredAccount,
  options: WebApprovalOptions,
  deviceId?: string,
  timeoutMs?: number,
): Promise<{ signature: Uint8Array; plaintextHash: string }> {
  const result = await requestWebApproval(
    account,
    options,
    deviceId,
    timeoutMs,
  );

  if (!result.success) {
    throwWebApprovalError(result);
  }

  if (!result.signature || !result.plaintextHash) {
    throw new SigningError(
      SigningErrorCode.InternalError,
      "No signature in response",
    );
  }

  return {
    signature: result.signature,
    plaintextHash: result.plaintextHash,
  };
}

// Re-export browser utilities for convenience
export { collectBrowserMetadata, isBrowser } from "./browser.js";
