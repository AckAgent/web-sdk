/**
 * Type-safe API client factories using openapi-fetch
 *
 * These clients provide compile-time type checking for API requests and responses
 * based on the OpenAPI-generated types. The OpenAPI specs are the single source
 * of truth for all API types and field names.
 */

import createClient from "openapi-fetch";
import type { paths as RelayPaths } from "@ackagent/api/relay";
import type { paths as AuthPaths } from "@ackagent/api/auth";
import type { paths as BlobPaths } from "@ackagent/api/blob";

export type RelayClient = ReturnType<typeof createClient<RelayPaths>>;
export type AuthClient = ReturnType<typeof createClient<AuthPaths>>;
export type BlobApiClient = ReturnType<typeof createClient<BlobPaths>>;

/**
 * Create a type-safe client for the Relay service API.
 *
 * @param baseUrl - Base URL of the relay service (e.g., 'https://relay.ackagent.com')
 * @param accessToken - Optional OIDC access token for authenticated endpoints
 * @returns A typed fetch client for the Relay API
 *
 * @example
 * ```typescript
 * const client = createRelayClient('https://relay.ackagent.com', accessToken);
 *
 * // Type-safe request - TypeScript validates the body shape
 * const { data, error } = await client.POST('/api/v1/requests', {
 *   body: {
 *     id: crypto.randomUUID(),
 *     requesterId: pairingId,
 *     encryptedPayload: base64Encode(payload),
 *     payloadNonce: base64Encode(nonce),
 *     wrappedKeys: [...],
 *     expiresIn: 300,
 *   },
 * });
 * ```
 */
export function createRelayClient(
  baseUrl: string,
  accessToken?: string,
): RelayClient {
  return createClient<RelayPaths>({
    baseUrl: baseUrl.replace(/\/$/, ""),
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  });
}

/**
 * Create a type-safe client for the Auth service API.
 *
 * @param baseUrl - Base URL of the auth service (e.g., 'https://auth.ackagent.com')
 * @param accessToken - Optional OIDC access token for authenticated endpoints
 * @returns A typed fetch client for the Auth API
 *
 * @example
 * ```typescript
 * const client = createAuthClient('https://auth.ackagent.com');
 *
 * // Create requester session for QR login
 * const { data, error } = await client.POST('/api/v1/requester-sessions', {
 *   body: {
 *     requesterName: 'My Web App',
 *     requesterPublicKeyHex: hexEncode(publicKey),
 *     expiresIn: 300,
 *   },
 * });
 * ```
 */
export function createAuthClient(
  baseUrl: string,
  accessToken?: string,
): AuthClient {
  return createClient<AuthPaths>({
    baseUrl: baseUrl.replace(/\/$/, ""),
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  });
}

/**
 * Create a type-safe client for the Blob service API.
 *
 * @param baseUrl - Base URL of the blob service (e.g., 'https://blob.ackagent.com')
 * @param accessToken - Optional OIDC access token for authenticated endpoints
 * @returns A typed fetch client for the Blob API
 */
export function createBlobClient(
  baseUrl: string,
  accessToken?: string,
): BlobApiClient {
  return createClient<BlobPaths>({
    baseUrl: baseUrl.replace(/\/$/, ""),
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  });
}
