/**
 * Client for the credential issuer API.
 * Used by verifiers to fetch the BBS+ issuer public key for proof verification.
 */

import type { BbsPublicKey } from "./bbs.js";
import { base64Decode } from "./encoding.js";

/** BBS+ issuer public key returned by the credential API. */
export interface BBSIssuerPublicKey {
  /** Unique identifier for this key. */
  id: string;
  /** Raw BLS12-381 public key bytes. */
  publicKey: Uint8Array;
  /** Algorithm identifier (e.g., "BBS+"). */
  algorithm: string;
  /** ISO 8601 timestamp of when this key was created. */
  createdAt: string;
}

/**
 * Raw JSON response from the credential public key endpoint.
 * Used internally for parsing the API response.
 */
interface RawPublicKeyResponse {
  id: string;
  publicKey: string; // base64-encoded
  algorithm: string;
  createdAt: string;
}

/**
 * Client for the credential issuer API.
 *
 * Fetches and caches BBS+ issuer public keys used for anonymous attestation
 * proof verification. Results are cached for the configured TTL to minimize
 * network requests.
 *
 * @example
 * ```typescript
 * const client = new CredentialAPIClient('https://auth.example.com');
 * const keys = await client.getIssuerPublicKeys();
 * // Use keys[0].publicKey for proof verification
 * ```
 */
export class CredentialAPIClient {
  private cachedPublicKeys: BBSIssuerPublicKey[] | null = null;
  private cacheExpiry = 0;

  /**
   * Create a credential API client.
   *
   * @param baseUrl - Base URL of the credential issuer service (e.g., "https://auth.example.com")
   * @param cacheTTLMs - Cache duration in milliseconds (default: 1 hour)
   */
  constructor(
    private readonly baseUrl: string,
    private readonly cacheTTLMs: number = 3600000,
  ) {}

  /**
   * Fetch the BBS+ issuer public keys for proof verification.
   * Results are cached for the configured TTL.
   *
   * @returns Array of BBS+ issuer public keys
   * @throws Error if the fetch fails or the response is malformed
   */
  async getIssuerPublicKeys(): Promise<BBSIssuerPublicKey[]> {
    const now = Date.now();

    if (this.cachedPublicKeys && now < this.cacheExpiry) {
      return this.cachedPublicKeys;
    }

    const url = `${this.baseUrl}/api/v1/credentials/public-key`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(
        `Failed to fetch issuer public keys: ${response.status} ${response.statusText}`,
      );
    }

    const rawData: unknown = await response.json();

    if (!Array.isArray(rawData)) {
      throw new Error("Expected array of issuer public keys from API");
    }

    const keys: BBSIssuerPublicKey[] = rawData.map(
      (raw: RawPublicKeyResponse) => ({
        id: raw.id,
        publicKey: base64Decode(raw.publicKey),
        algorithm: raw.algorithm,
        createdAt: raw.createdAt,
      }),
    );

    this.cachedPublicKeys = keys;
    this.cacheExpiry = now + this.cacheTTLMs;

    return keys;
  }

  /**
   * Fetch the BBS+ issuer public key as a {@link BbsPublicKey} for use
   * with the BBS+ verification functions in {@link bbs}.
   *
   * Returns the first (most recent) issuer public key. If a specific key ID
   * is provided, returns the key matching that ID.
   *
   * @param keyId - Optional key ID to look up a specific key
   * @returns A BbsPublicKey suitable for {@link verifyBbsSignature} and {@link verifyBbsProof}
   * @throws Error if no keys are available or the specified key ID is not found
   */
  async getBbsPublicKey(keyId?: string): Promise<BbsPublicKey> {
    const keys = await this.getIssuerPublicKeys();

    if (keys.length === 0) {
      throw new Error("no BBS+ issuer public keys available");
    }

    if (keyId) {
      const key = keys.find((k) => k.id === keyId);
      if (!key) {
        throw new Error(`BBS+ issuer public key not found: ${keyId}`);
      }
      return { publicKeyBytes: key.publicKey };
    }

    return { publicKeyBytes: keys[0].publicKey };
  }

  /**
   * Invalidate the cached public keys, forcing a fresh fetch on next call.
   */
  invalidateCache(): void {
    this.cachedPublicKeys = null;
    this.cacheExpiry = 0;
  }
}
