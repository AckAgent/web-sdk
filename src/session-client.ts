/**
 * HTTP client for QR code requester session methods.
 *
 * Uses openapi-fetch with generated types from the auth OpenAPI spec to ensure
 * type safety and prevent spec drift. All field names match the OpenAPI schemas.
 */

import type { RequesterSessionStatus } from "./types.js";
import { NetworkError, TimeoutError } from "./errors.js";
import { hexEncode, hexDecode } from "./encoding.js";
import type { ApproverKeyInfo } from "./sas.js";
import { createAuthClient } from "./api.js";
import type { AuthClient } from "./api.js";
import type { ClientConfig, PollConfig } from "./client.js";

// Re-export types for consumers
export type { ApproverKeyInfo } from "./sas.js";

/** Organization linked during a requester session */
export interface SessionLinkedOrganization {
  /** Organization ID */
  id: string;
  /** Organization emoji index for client-side rendering via emojiFromIndex() */
  emojiIndex: number;
  /** Local name from approver device (E2E encrypted) */
  localName?: string;
}

// Type guard for runtime validation of status values from backend
const VALID_REQUESTER_SESSION_STATUSES: readonly RequesterSessionStatus[] = [
  "pending",
  "claimed",
  "verified",
  "rejected",
  "expired",
];

function isValidRequesterSessionStatus(
  status: unknown,
): status is RequesterSessionStatus {
  return (
    typeof status === "string" &&
    VALID_REQUESTER_SESSION_STATUSES.includes(status as RequesterSessionStatus)
  );
}

/** Default HTTP request timeout in milliseconds (10 seconds) */
const DEFAULT_TIMEOUT = 10000;
const DEFAULT_POLL_CONFIG: Required<PollConfig> = {
  initialInterval: 500,
  maxInterval: 2000,
  multiplier: 1.5,
};

/**
 * Client for QR code requester session operations.
 *
 * Uses openapi-fetch with generated types from the auth OpenAPI spec
 * for type-safe API communication. All request/response field names are validated
 * at compile time against the OpenAPI schemas.
 */
export class SessionClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private authClient: AuthClient;

  constructor(config: ClientConfig | string) {
    if (typeof config === "string") {
      this.baseUrl = config.replace(/\/$/, "");
      this.timeout = DEFAULT_TIMEOUT;
    } else {
      this.baseUrl = config.baseUrl.replace(/\/$/, "");
      this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
    }
    this.authClient = createAuthClient(this.baseUrl);
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

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
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

  // ===========================================================================
  // QR Code Requester Session Methods (Web SDK is the requester)
  // Uses the auth OpenAPI spec types for type-safe field names.
  // ===========================================================================

  /**
   * Create a requester session for QR code login (public, no auth required).
   * The Web SDK creates requester sessions since it initiates the login flow.
   */
  async createRequesterSession(params: {
    requesterName: string;
    requesterPublicKey: Uint8Array;
    expiresIn?: number;
  }): Promise<{
    sessionId: string;
    status: RequesterSessionStatus;
    expiresAt: Date;
  }> {
    try {
      const { data, response } = await this.authClient.POST(
        "/api/v1/requester-sessions",
        {
          body: {
            requesterName: params.requesterName,
            requesterPublicKeyHex: hexEncode(params.requesterPublicKey),
            expiresIn: params.expiresIn ?? 300,
          },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (!response.ok || !data) {
        const text = await response.text().catch(() => "");
        throw new NetworkError(
          `Failed to create requester session: ${response.status} - ${text}`,
        );
      }

      if (!isValidRequesterSessionStatus(data.status)) {
        throw new NetworkError(
          `Invalid requester session status from server: ${data.status}`,
        );
      }
      return {
        sessionId: data.sessionId,
        status: data.status as RequesterSessionStatus,
        expiresAt: new Date(data.expiresAt),
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
   * Get requester session status (public, no auth required).
   * Returns approver public keys after an approver device claims the session (scans QR code)
   * for local SAS computation.
   */
  async getRequesterSessionStatus(sessionId: string): Promise<{
    status: RequesterSessionStatus;
    expiresAt: Date;
    approverKeys?: ApproverKeyInfo[];
  }> {
    try {
      const { data, response } = await this.authClient.GET(
        "/api/v1/requester-sessions/{id}/status",
        {
          params: { path: { id: sessionId } },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) {
        throw new NetworkError("Requester session not found");
      }
      if (response.status === 410) {
        throw new NetworkError("Requester session expired");
      }
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get requester session status: ${response.status}`,
        );
      }

      if (!isValidRequesterSessionStatus(data.status)) {
        throw new NetworkError(
          `Invalid requester session status from server: ${data.status}`,
        );
      }

      // Parse approver public keys if present (returned after approver claims the session)
      let approverKeys: ApproverKeyInfo[] | undefined;
      if (data.approverKeys && Array.isArray(data.approverKeys)) {
        approverKeys = data.approverKeys.flatMap((approverKey) => {
          if (!approverKey.encryptionPublicKeyHex) {
            return [];
          }

          const approverPublicKey = hexDecode(
            approverKey.encryptionPublicKeyHex,
          );
          // 33-byte compressed P-256 key (0x02/0x03 || X = 66 hex chars)
          return [
            {
              encryptionPublicKeyHex: hexEncode(approverPublicKey),
              approverPublicKey,
            },
          ];
        });
      }

      const expiresAtRaw = this.requireStringField(
        data.expiresAt,
        "expiresAt",
        "requester session status response",
      );

      return {
        status: data.status as RequesterSessionStatus,
        expiresAt: this.requireDate(
          expiresAtRaw,
          "expiresAt",
          "requester session status response",
        ),
        approverKeys,
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
   * Get tokens after requester session verification (public, no auth required)
   */
  async getRequesterSessionTokens(sessionId: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn: number;
    userId: string;
  }> {
    try {
      const { data, response } = await this.authClient.GET(
        "/api/v1/requester-sessions/{id}/tokens",
        {
          params: { path: { id: sessionId } },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) {
        throw new NetworkError("Requester session not found");
      }
      if (response.status === 400) {
        const text = await response.text().catch(() => "");
        throw new NetworkError(`Requester session not verified: ${text}`);
      }
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get requester session tokens: ${response.status}`,
        );
      }

      return {
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresIn: data.expiresIn,
        userId: data.userId,
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
   * Poll for requester session verification (public, no auth required).
   * Returns approver public keys after an approver device claims the session (scans QR code)
   * so the caller can compute SAS locally.
   */
  async pollRequesterSessionVerification(
    sessionId: string,
    timeoutMs: number,
    pollConfig?: PollConfig,
    onApproverKeysAvailable?: (approverKeys: ApproverKeyInfo[]) => void,
  ): Promise<{
    status: RequesterSessionStatus;
    expiresAt: Date;
    approverKeys?: ApproverKeyInfo[];
  }> {
    let keysNotified = false;
    return this.poll(
      async () => {
        const status = await this.getRequesterSessionStatus(sessionId);
        if (status.status === "expired") {
          throw new NetworkError("Requester session expired");
        }
        // Notify when approver keys become available (after approver claims session)
        if (
          status.approverKeys &&
          status.approverKeys.length > 0 &&
          !keysNotified &&
          onApproverKeysAvailable
        ) {
          keysNotified = true;
          onApproverKeysAvailable(status.approverKeys);
        }
        return status;
      },
      (status) => status.status === "verified" || status.status === "rejected",
      (error) =>
        error instanceof NetworkError && error.message.includes("expired"),
      timeoutMs,
      pollConfig,
      "Requester session verification timed out",
    );
  }
}
