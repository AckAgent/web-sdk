/**
 * Transport layer abstraction for sending signing requests.
 * Different implementations can use HTTP relay, Web Bluetooth, etc.
 */

import type { PollConfig } from "../client.js";

/**
 * Request to be sent via a transport
 */
export interface TransportRequest {
  /** Unique request identifier (UUID) */
  id: string;

  /** User/pairing identifier for routing */
  pairingId: string;

  /** Optional specific key to use */
  keyId?: string;

  /** Optional lowercase hex-encoded signing public key filter */
  signingPublicKeyHex?: string;

  /** Requester's ephemeral P-256 public key (33 bytes compressed) */
  ephemeralPublic: Uint8Array;

  /** E2E encrypted request payload */
  encryptedPayload: Uint8Array;

  /** Nonce used for encryption */
  payloadNonce: Uint8Array;

  /** Request validity duration in seconds */
  expiresIn: number;

  /** When the request was created (Unix milliseconds) */
  timestamp: number;

  /** Per-device wrapped symmetric keys for multi-device encryption */
  wrappedKeys?: {
    encryptionPublicKeyHex: string;
    wrappedKey: string;
    wrappedKeyNonce: string;
    requesterEphemeralKeyHex: string;
  }[];
}

/**
 * Response received via a transport
 */
export interface TransportResponse {
  /** Request ID this response is for */
  id: string;

  /** Response status: "pending", "responded", "expired" */
  status: "pending" | "responded" | "expired";

  /** Signer's ephemeral public key for response decryption */
  ephemeralPublic?: Uint8Array;

  /** E2E encrypted response payload */
  encryptedResponse?: Uint8Array;

  /** Nonce used for response encryption */
  responseNonce?: Uint8Array;

  /** When the response was received */
  respondedAt?: string;

  /** When the request expires */
  expiresAt: string;
}

/**
 * Transport interface for sending signing requests
 */
export interface Transport {
  /** Human-readable name for this transport */
  readonly name: string;

  /** Priority (lower = higher priority, tried first) */
  readonly priority: number;

  /**
   * Check if this transport is currently available.
   * For local transports, this might discover devices.
   */
  isAvailable(): Promise<boolean>;

  /**
   * Send a signing request and wait for a response.
   * @param request - The request to send
   * @param timeoutMs - Maximum wait time in milliseconds
   * @param pollConfig - Optional polling configuration
   */
  send(
    request: TransportRequest,
    timeoutMs: number,
    pollConfig?: PollConfig,
  ): Promise<TransportResponse>;
}

/**
 * Error from a specific transport
 */
export class TransportError extends Error {
  constructor(
    public readonly transport: string,
    public readonly cause: Error,
  ) {
    super(`${transport}: ${cause.message}`);
    this.name = "TransportError";
  }
}
