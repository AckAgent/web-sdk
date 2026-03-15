/**
 * HTTP client for communicating with the relay backend.
 *
 * Uses openapi-fetch with generated types from the OpenAPI specs to ensure
 * type safety and prevent spec drift. All field names match the OpenAPI schemas.
 */

import type { BackendRequestStatus, RequestStatus } from "./types.js";
import { NetworkError, SigningExpiredError, TimeoutError } from "./errors.js";
import {
  base64Decode,
  base64Encode,
  hexEncode,
  hexDecode,
} from "./encoding.js";
import { createRelayClient, createAuthClient } from "./api.js";
import type { RelayClient, AuthClient } from "./api.js";

// Re-export types for consumers
export type { ApproverKeyInfo } from "./sas.js";

// Re-export SessionClient and SessionLinkedOrganization so index.ts doesn't need to change
export {
  SessionClient,
  type SessionLinkedOrganization,
} from "./session-client.js";

// Type guards for runtime validation of status values from backend
// Privacy: Backend only returns 'pending', 'responded', or 'expired' - never 'approved' or 'rejected'
const VALID_REQUEST_STATUSES: readonly RequestStatus[] = [
  "pending",
  "responded",
  "expired",
];

function isValidRequestStatus(status: unknown): status is RequestStatus {
  return (
    typeof status === "string" &&
    VALID_REQUEST_STATUSES.includes(status as RequestStatus)
  );
}

/** Configuration for the API client */
export interface ClientConfig {
  /** Base URL of the relay server */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/** Configuration for polling */
export interface PollConfig {
  /** Initial interval in milliseconds (default: 500) */
  initialInterval?: number;
  /** Maximum interval in milliseconds (default: 2000) */
  maxInterval?: number;
  /** Backoff multiplier (default: 1.5) */
  multiplier?: number;
}

/** Default HTTP request timeout in milliseconds (10 seconds) */
const DEFAULT_TIMEOUT = 10000;
const DEFAULT_POLL_CONFIG: Required<PollConfig> = {
  initialInterval: 500,
  maxInterval: 2000,
  multiplier: 1.5,
};

/**
 * Client for communicating with the relay backend.
 *
 * Uses openapi-fetch with generated types from the relay and auth OpenAPI specs
 * for type-safe API communication. All request/response field names are validated
 * at compile time against the OpenAPI schemas.
 */
export class SignerClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly debug: boolean;
  private relayClient: RelayClient;
  private authClient: AuthClient;

  constructor(config: ClientConfig | string) {
    if (typeof config === "string") {
      this.baseUrl = config.replace(/\/$/, "");
      this.timeout = DEFAULT_TIMEOUT;
      this.debug = false;
    } else {
      this.baseUrl = config.baseUrl.replace(/\/$/, "");
      this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
      this.debug = config.debug ?? false;
    }
    this.relayClient = createRelayClient(this.baseUrl);
    this.authClient = createAuthClient(this.baseUrl);
  }

  /**
   * Set the OIDC access token for authenticated requests
   */
  setAccessToken(token: string): void {
    // Recreate clients with the new token baked in
    this.relayClient = createRelayClient(this.baseUrl, token);
    this.authClient = createAuthClient(this.baseUrl, token);
  }

  /**
   * Generic polling helper with exponential backoff
   */
  private async poll<T>(
    fetcher: () => Promise<T>,
    isComplete: (result: T) => boolean,
    isFatalError: (error: unknown) => boolean,
    timeoutMs: number,
    pollConfig?: PollConfig,
    timeoutMessage = "Operation timed out",
  ): Promise<T> {
    const config = { ...DEFAULT_POLL_CONFIG, ...pollConfig };
    const deadline = Date.now() + timeoutMs;
    let interval = config.initialInterval;

    while (Date.now() < deadline) {
      try {
        const result = await fetcher();
        if (isComplete(result)) {
          return result;
        }
      } catch (error) {
        if (isFatalError(error)) {
          throw error;
        }
        // Continue polling on transient errors
      }

      // Wait before next poll
      await this.sleep(Math.min(interval, deadline - Date.now()));
      interval = Math.min(interval * config.multiplier, config.maxInterval);
    }

    throw new TimeoutError(timeoutMessage);
  }

  /**
   * Create a signing request.
   * Uses the relay OpenAPI spec types for type-safe field names.
   */
  async createSigningRequest(params: {
    id: string;
    pairingId: string;
    keyId?: string;
    signingPublicKeyHex?: string;
    ephemeralPublic: Uint8Array;
    encryptedPayload: Uint8Array;
    payloadNonce: Uint8Array;
    expiresIn: number;
    timestamp: number;
    wrappedKeys?: {
      encryptionPublicKeyHex: string;
      wrappedKey: string;
      wrappedKeyNonce: string;
      requesterEphemeralKeyHex: string;
    }[];
  }): Promise<{ id: string; status: RequestStatus; expiresAt: Date }> {
    if (this.debug) {
      console.debug("[AckAgent] Creating signing request:", {
        pairingId: params.pairingId,
        keyId: params.keyId,
        expiresIn: params.expiresIn,
      });
    }

    try {
      const { data, response } = await this.relayClient.POST(
        "/api/v1/requests",
        {
          body: {
            id: params.id,
            requesterId: params.pairingId,
            signingPublicKeyHex: params.signingPublicKeyHex,
            requesterEphemeralKeyHex: hexEncode(params.ephemeralPublic),
            encryptedPayload: base64Encode(params.encryptedPayload),
            payloadNonce: base64Encode(params.payloadNonce),
            expiresIn: params.expiresIn,
            timestamp: params.timestamp,
            wrappedKeys: params.wrappedKeys,
          },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (!response.ok || !data) {
        const text = await response.text().catch(() => "");
        if (this.debug) {
          console.debug(
            "[AckAgent] Signing request failed:",
            response.status,
            text,
          );
        }
        throw new NetworkError(
          `Failed to create signing request: ${response.status} - ${text}`,
        );
      }

      if (this.debug) {
        console.debug("[AckAgent] Signing request created:", {
          id: data.id,
          status: data.status,
        });
      }
      const requestId = this.requireStringField(
        data.id,
        "id",
        "create signing response",
      );
      const requestStatus = this.requireRequestStatus(
        data.status,
        "create signing response",
      );
      const expiresAtRaw = this.requireStringField(
        data.expiresAt,
        "expiresAt",
        "create signing response",
      );

      return {
        id: requestId,
        status: requestStatus,
        expiresAt: this.requireDate(
          expiresAtRaw,
          "expiresAt",
          "create signing response",
        ),
      };
    } catch (error) {
      if (error instanceof NetworkError || error instanceof TimeoutError)
        throw error;
      if (
        error instanceof Error &&
        (error.name === "AbortError" || error.name === "TimeoutError")
      ) {
        throw new TimeoutError("Request timed out");
      }
      throw new NetworkError(`Network error: ${error}`);
    }
  }

  /**
   * Get the status of a signing request.
   * Returns field names matching the relay OpenAPI spec.
   */
  async getRequestStatus(requestId: string): Promise<BackendRequestStatus> {
    try {
      const { data, response } = await this.relayClient.GET(
        "/api/v1/requests/{id}",
        {
          params: { path: { id: requestId } },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) {
        throw new NetworkError("Request not found");
      }
      if (response.status === 410) {
        throw new SigningExpiredError();
      }
      if (response.status === 401) {
        throw new NetworkError("Authentication required");
      }
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get request status: ${response.status}`,
        );
      }

      if (!isValidRequestStatus(data.status)) {
        throw new NetworkError(
          `Invalid request status from server: ${data.status}`,
        );
      }
      const responseRequestId = this.requireStringField(
        data.id,
        "id",
        "request status response",
      );
      const expiresAt = this.requireStringField(
        data.expiresAt,
        "expiresAt",
        "request status response",
      );

      return {
        id: responseRequestId,
        status: data.status,
        approverEphemeralKey: data.approverEphemeralKeyHex
          ? hexDecode(data.approverEphemeralKeyHex)
          : undefined,
        encryptedResponse: data.encryptedResponse
          ? base64Decode(data.encryptedResponse)
          : undefined,
        responseNonce: data.responseNonce
          ? base64Decode(data.responseNonce)
          : undefined,
        respondedAt: data.respondedAt,
        expiresAt,
      };
    } catch (error) {
      if (
        error instanceof NetworkError ||
        error instanceof TimeoutError ||
        error instanceof SigningExpiredError
      )
        throw error;
      if (
        error instanceof Error &&
        (error.name === "AbortError" || error.name === "TimeoutError")
      ) {
        throw new TimeoutError("Request timed out");
      }
      throw new NetworkError(`Network error: ${error}`);
    }
  }

  /**
   * Poll for signing response
   */
  async pollSigningResponse(
    requestId: string,
    timeoutMs: number,
    pollConfig?: PollConfig,
  ): Promise<BackendRequestStatus> {
    return this.poll(
      async () => {
        const status = await this.getRequestStatus(requestId);
        if (status.status === "expired") {
          throw new SigningExpiredError();
        }
        return status;
      },
      (status) => status.status === "responded",
      (error) => error instanceof SigningExpiredError,
      timeoutMs,
      pollConfig,
      "Request timed out",
    );
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
  }

  // ===========================================================================
  // Attestation Methods
  // ===========================================================================

  /**
   * Get approver attestation information
   *
   * @param approverId - Approver device UUID
   * @param accessToken - OIDC access token
   */
  async getApproverAttestation(
    approverId: string,
    accessToken: string,
  ): Promise<ApproverAttestationResponse> {
    try {
      const { data, response } = await this.authClient.GET(
        "/api/v1/approvers/{approverId}/attestation",
        {
          params: { path: { approverId } },
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) {
        throw new NetworkError("Approver not found");
      }
      if (response.status === 403) {
        throw new NetworkError("Approver belongs to different user");
      }
      if (!response.ok || !data) {
        throw new NetworkError(`Failed to get attestation: ${response.status}`);
      }

      const attestation = data.attestation;
      return {
        attestationPublicKey: attestation?.attestationPublicKeyHex
          ? hexDecode(attestation.attestationPublicKeyHex)
          : new Uint8Array(),
        attestationType: attestation?.attestationType ?? "software",
        mode: attestation?.mode ?? "identified",
        encryptionPublicKey: attestation?.encryptionPublicKeyHex
          ? hexDecode(attestation.encryptionPublicKeyHex)
          : undefined,
        certificateChain:
          attestation?.certificateChain?.map((cert: string) =>
            base64Decode(cert),
          ) ?? [],
        responseAssertion: attestation?.responseAssertion
          ? base64Decode(attestation.responseAssertion)
          : new Uint8Array(),
        timestamp: attestation?.timestamp ?? 0,
        attested: data.attested ?? false,
      };
    } catch (error) {
      if (error instanceof NetworkError || error instanceof TimeoutError)
        throw error;
      if (
        error instanceof Error &&
        (error.name === "AbortError" || error.name === "TimeoutError")
      ) {
        throw new TimeoutError("Request timed out");
      }
      throw new NetworkError(`Network error: ${error}`);
    }
  }

  /**
   * Require a string field in a backend response payload.
   */
  private requireStringField(
    fieldValue: string | undefined,
    fieldName: string,
    responseName: string,
  ): string {
    if (!fieldValue) {
      throw new NetworkError(`Invalid ${responseName}: missing ${fieldName}`);
    }
    return fieldValue;
  }

  /**
   * Require and validate a request status value from backend payloads.
   */
  private requireRequestStatus(
    statusValue: RequestStatus | string | undefined,
    responseName: string,
  ): RequestStatus {
    if (!isValidRequestStatus(statusValue)) {
      throw new NetworkError(
        `Invalid ${responseName}: invalid status ${statusValue}`,
      );
    }
    return statusValue;
  }

  /**
   * Parse and validate a backend date-time string field.
   */
  private requireDate(
    dateValue: string,
    fieldName: string,
    responseName: string,
  ): Date {
    const parsedDate = new Date(dateValue);
    if (Number.isNaN(parsedDate.getTime())) {
      throw new NetworkError(`Invalid ${responseName}: malformed ${fieldName}`);
    }
    return parsedDate;
  }
}

/** Approver attestation response from the API */
export interface ApproverAttestationResponse {
  /** Attestation key's public key (64 bytes: X || Y) */
  attestationPublicKey: Uint8Array;
  /** Security type of the attestation */
  attestationType: string;
  /** Attestation mode ("identified" or "anonymous") */
  mode: string;
  /** Device's P-256 ECDH public key for E2E encryption */
  encryptionPublicKey?: Uint8Array;
  /** DER-encoded certificate chain for verification */
  certificateChain: (Uint8Array | undefined)[];
  /** Direct attestation of the response by the attestation key */
  responseAssertion: Uint8Array;
  /** Unix timestamp in milliseconds when attestation was generated */
  timestamp: number;
  /** Whether the device has valid attestation */
  attested: boolean;
}
