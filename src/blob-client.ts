/**
 * Blob service client for encrypted key metadata storage
 *
 * The blob service provides server-blind storage for key metadata.
 * All key information is E2E encrypted - the server never sees:
 * - SSH/GPG/Age key existence or purposes
 * - Key public keys or purposes
 * - Which device owns which key
 *
 * Uses openapi-fetch with generated types from the blob OpenAPI spec to ensure
 * type safety and prevent spec drift. All field names match the OpenAPI schemas.
 *
 * Uses optimistic locking with ETag/If-Match for concurrent updates.
 */

import { NetworkError } from "./errors.js";
import { createBlobClient } from "./api.js";
import type { BlobApiClient } from "./api.js";
import type {
  BlobRequest,
  BlobResult,
  HistoryListResponse,
  HistoryDetailResponse,
  BlobClientConfig,
} from "./blob-types.js";
import { BlobNotFoundError, BlobVersionConflictError } from "./blob-types.js";
import {
  parseETag,
  parseBlobResponse,
  serializeBlobRequest,
  parseHistoryListResponse,
  parseHistoryDetailResponse,
} from "./blob-parsing.js";

const DEFAULT_TIMEOUT = 30000;

/**
 * Client for the blob service (encrypted key metadata storage).
 *
 * Uses openapi-fetch with generated types from the blob OpenAPI spec
 * for type-safe API communication. All request/response field names are
 * validated at compile time against the OpenAPI schemas.
 */
export class BlobClient {
  private readonly baseUrl: string;
  private readonly orgId: string;
  private readonly timeout: number;
  private readonly blobApiClient: BlobApiClient;

  constructor(config: BlobClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.orgId = config.orgId;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
    this.blobApiClient = createBlobClient(this.baseUrl);
  }

  /**
   * Get the encrypted blob for the authenticated user
   */
  async getBlob(accessToken: string): Promise<BlobResult> {
    try {
      const { data, response } = await this.blobApiClient.GET(
        "/api/v1/organizations/{orgId}/blob",
        {
          params: { path: { orgId: this.orgId } },
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) throw new BlobNotFoundError();
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get blob: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return {
        response: parseBlobResponse(data),
        etag: parseETag(response.headers.get("ETag")),
      };
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * Create a new blob for the authenticated user
   */
  async createBlob(
    accessToken: string,
    request: BlobRequest,
  ): Promise<BlobResult> {
    try {
      const { data, response } = await this.blobApiClient.POST(
        "/api/v1/organizations/{orgId}/blob",
        {
          params: { path: { orgId: this.orgId } },
          headers: { Authorization: `Bearer ${accessToken}` },
          body: serializeBlobRequest(request),
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 409)
        throw new NetworkError("Blob already exists - use updateBlob instead");
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to create blob: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return {
        response: parseBlobResponse(data),
        etag: parseETag(response.headers.get("ETag")),
      };
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * Update the blob for the authenticated user
   * Uses optimistic locking with the provided etag (version)
   */
  async updateBlob(
    accessToken: string,
    etag: string,
    request: BlobRequest,
  ): Promise<BlobResult> {
    if (!etag) throw new Error("etag is required for updates");

    try {
      const { data, response } = await this.blobApiClient.PUT(
        "/api/v1/organizations/{orgId}/blob",
        {
          params: {
            path: { orgId: this.orgId },
            header: { "if-match": `"${etag}"` },
          },
          headers: { Authorization: `Bearer ${accessToken}` },
          body: serializeBlobRequest(request),
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 412) throw new BlobVersionConflictError();
      if (response.status === 404) throw new BlobNotFoundError();
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to update blob: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return {
        response: parseBlobResponse(data),
        etag: parseETag(response.headers.get("ETag")),
      };
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * Delete the blob for the authenticated user.
   * Requires device attestation headers for write authorization.
   */
  async deleteBlob(
    accessToken: string,
    deviceAuthKey: string,
    assertion: string,
  ): Promise<void> {
    try {
      const { response } = await this.blobApiClient.DELETE(
        "/api/v1/organizations/{orgId}/blob",
        {
          params: {
            path: { orgId: this.orgId },
            header: {
              "x-device-auth-key": deviceAuthKey,
              "x-assertion": assertion,
            },
          },
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 204) return;
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok) {
        throw new NetworkError(
          `Failed to delete blob: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * List previous versions of the blob
   */
  async getBlobHistory(
    accessToken: string,
    limit?: number,
  ): Promise<HistoryListResponse> {
    try {
      const { data, response } = await this.blobApiClient.GET(
        "/api/v1/organizations/{orgId}/blob/history",
        {
          params: {
            path: { orgId: this.orgId },
            query: limit && limit > 0 ? { limit } : undefined,
          },
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get blob history: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return parseHistoryListResponse(data);
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * Get a specific version from history
   */
  async getBlobHistoryVersion(
    accessToken: string,
    version: number,
  ): Promise<HistoryDetailResponse> {
    try {
      const { data, response } = await this.blobApiClient.GET(
        "/api/v1/organizations/{orgId}/blob/history/{version}",
        {
          params: { path: { orgId: this.orgId, version } },
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) throw new BlobNotFoundError();
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to get blob history version: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return parseHistoryDetailResponse(data);
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  /**
   * Restore a blob from a history version.
   * Requires device attestation headers for write authorization.
   */
  async restoreFromHistory(
    accessToken: string,
    version: number,
    deviceAuthKey: string,
    assertion: string,
  ): Promise<BlobResult> {
    try {
      const { data, response } = await this.blobApiClient.POST(
        "/api/v1/organizations/{orgId}/blob/restore/{version}",
        {
          params: {
            path: { orgId: this.orgId, version },
            header: {
              "x-device-auth-key": deviceAuthKey,
              "x-assertion": assertion,
            },
          },
          headers: { Authorization: `Bearer ${accessToken}` },
          signal: AbortSignal.timeout(this.timeout),
        },
      );

      if (response.status === 404) throw new BlobNotFoundError();
      if (response.status === 401)
        throw new NetworkError("Authentication required");
      if (!response.ok || !data) {
        throw new NetworkError(
          `Failed to restore blob: ${response.status} - ${await response.text().catch(() => "")}`,
        );
      }

      return {
        response: parseBlobResponse(data),
        etag: parseETag(response.headers.get("ETag")),
      };
    } catch (error) {
      throw this.wrapError(error);
    }
  }

  // ===========================================================================
  // Private helpers
  // ===========================================================================

  /**
   * Wrap non-NetworkError errors into NetworkError for consistent error handling.
   */
  private wrapError(error: unknown): Error {
    if (error instanceof NetworkError) return error;
    if (
      error instanceof Error &&
      (error.name === "AbortError" || error.name === "TimeoutError")
    ) {
      return new NetworkError("Request timed out");
    }
    return new NetworkError(`Network error: ${error}`);
  }
}
