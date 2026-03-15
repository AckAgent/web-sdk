/**
 * Relay transport implementation using HTTP relay server.
 */

import type { PollConfig } from "../client.js";
import { SignerClient } from "../client.js";
import type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "./types.js";

/**
 * Options for creating a relay transport
 */
export interface RelayTransportOptions {
  /** Relay server URL */
  relayUrl: string;

  /** Optional access token for authenticated requests */
  accessToken?: string;

  /** Enable debug logging */
  debug?: boolean;
}

/**
 * Transport implementation using the HTTP relay server.
 * This is the default transport for cloud-based communication.
 */
export class RelayTransport implements Transport {
  readonly name = "relay";
  readonly priority = 50; // Lower priority so local transports are tried first

  private readonly client: SignerClient;

  constructor(options: RelayTransportOptions | string) {
    if (typeof options === "string") {
      this.client = new SignerClient(options);
    } else {
      this.client = new SignerClient({
        baseUrl: options.relayUrl,
        debug: options.debug,
      });
      if (options.accessToken) {
        this.client.setAccessToken(options.accessToken);
      }
    }
  }

  /**
   * Set the access token for authenticated requests
   */
  setAccessToken(token: string): void {
    this.client.setAccessToken(token);
  }

  /**
   * Check if relay is available.
   * For relay, we always return true since network errors are handled at send time.
   */
  async isAvailable(): Promise<boolean> {
    return true;
  }

  /**
   * Send a signing request via the relay server
   */
  async send(
    request: TransportRequest,
    timeoutMs: number,
    pollConfig?: PollConfig,
  ): Promise<TransportResponse> {
    // Create the signing request
    const result = await this.client.createSigningRequest({
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

    // Poll for response
    const status = await this.client.pollSigningResponse(
      result.id,
      timeoutMs,
      pollConfig,
    );

    return {
      id: status.id,
      status: status.status,
      ephemeralPublic: status.approverEphemeralKey,
      encryptedResponse: status.encryptedResponse,
      responseNonce: status.responseNonce,
      respondedAt: status.respondedAt,
      expiresAt: status.expiresAt,
    };
  }
}

/**
 * Create a relay transport from a relay URL
 */
export function createRelayTransport(relayUrl: string): RelayTransport {
  return new RelayTransport(relayUrl);
}
