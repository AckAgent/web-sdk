/**
 * Tests for API client factories (createRelayClient, createAuthClient, createBlobClient)
 *
 * Verifies URL normalization (trailing slash stripping) and Authorization header injection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  createRelayClient,
  createAuthClient,
  createBlobClient,
} from "../api.js";
import { createFetchMock, mockFetchResponse } from "./mocks.js";

describe("api", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    fetchMock = createFetchMock();
    originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  /**
   * Helper: make a GET request through a client and return the captured Request.
   * openapi-fetch passes a single Request object to fetch.
   */
  async function captureRequest(
    client: { GET: (path: string, options?: object) => Promise<unknown> },
    path: string,
  ): Promise<Request> {
    mockFetchResponse(fetchMock, 200, {});
    await client.GET(path);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    return fetchMock.mock.calls[0][0] as Request;
  }

  describe("createRelayClient", () => {
    it("should strip trailing slash from baseUrl", async () => {
      const client = createRelayClient("https://relay.example.com/");
      const request = await captureRequest(
        client,
        "/api/v1/requests/{requestId}",
      );
      expect(request.url).toMatch(/^https:\/\/relay\.example\.com\/api\//);
      expect(request.url).not.toMatch(/\.com\/\/api/);
    });

    it("should handle baseUrl without trailing slash", async () => {
      const client = createRelayClient("https://relay.example.com");
      const request = await captureRequest(
        client,
        "/api/v1/requests/{requestId}",
      );
      expect(request.url).toMatch(/^https:\/\/relay\.example\.com\/api\//);
    });

    it("should inject Authorization header when token is provided", async () => {
      const client = createRelayClient(
        "https://relay.example.com",
        "my-token-123",
      );
      const request = await captureRequest(
        client,
        "/api/v1/requests/{requestId}",
      );
      expect(request.headers.get("Authorization")).toBe("Bearer my-token-123");
    });

    it("should not send Authorization header when token is omitted", async () => {
      const client = createRelayClient("https://relay.example.com");
      const request = await captureRequest(
        client,
        "/api/v1/requests/{requestId}",
      );
      expect(request.headers.get("Authorization")).toBeNull();
    });
  });

  describe("createAuthClient", () => {
    it("should strip trailing slash from baseUrl", async () => {
      const client = createAuthClient("https://auth.example.com/");
      const request = await captureRequest(
        client,
        "/api/v1/requester-sessions",
      );
      expect(request.url).toMatch(/^https:\/\/auth\.example\.com\/api\//);
      expect(request.url).not.toMatch(/\.com\/\/api/);
    });

    it("should handle baseUrl without trailing slash", async () => {
      const client = createAuthClient("https://auth.example.com");
      const request = await captureRequest(
        client,
        "/api/v1/requester-sessions",
      );
      expect(request.url).toMatch(/^https:\/\/auth\.example\.com\/api\//);
    });

    it("should inject Authorization header when token is provided", async () => {
      const client = createAuthClient(
        "https://auth.example.com",
        "auth-token-456",
      );
      const request = await captureRequest(
        client,
        "/api/v1/requester-sessions",
      );
      expect(request.headers.get("Authorization")).toBe(
        "Bearer auth-token-456",
      );
    });

    it("should not send Authorization header when token is omitted", async () => {
      const client = createAuthClient("https://auth.example.com");
      const request = await captureRequest(
        client,
        "/api/v1/requester-sessions",
      );
      expect(request.headers.get("Authorization")).toBeNull();
    });
  });

  describe("createBlobClient", () => {
    it("should strip trailing slash from baseUrl", async () => {
      const client = createBlobClient("https://blob.example.com/");
      const request = await captureRequest(client, "/api/v1/blobs/{blobId}");
      expect(request.url).toMatch(/^https:\/\/blob\.example\.com\/api\//);
      expect(request.url).not.toMatch(/\.com\/\/api/);
    });

    it("should handle baseUrl without trailing slash", async () => {
      const client = createBlobClient("https://blob.example.com");
      const request = await captureRequest(client, "/api/v1/blobs/{blobId}");
      expect(request.url).toMatch(/^https:\/\/blob\.example\.com\/api\//);
    });

    it("should inject Authorization header when token is provided", async () => {
      const client = createBlobClient(
        "https://blob.example.com",
        "blob-token-789",
      );
      const request = await captureRequest(client, "/api/v1/blobs/{blobId}");
      expect(request.headers.get("Authorization")).toBe(
        "Bearer blob-token-789",
      );
    });

    it("should not send Authorization header when token is omitted", async () => {
      const client = createBlobClient("https://blob.example.com");
      const request = await captureRequest(client, "/api/v1/blobs/{blobId}");
      expect(request.headers.get("Authorization")).toBeNull();
    });
  });
});
