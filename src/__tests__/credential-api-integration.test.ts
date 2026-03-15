/**
 * Integration tests for CredentialAPIClient.
 *
 * Tests cover fetch/cache behavior, cache expiry, network error handling,
 * and cache invalidation for the BBS+ issuer public key retrieval.
 *
 * These tests complement the existing unit tests in credential-api.test.ts
 * by focusing on integration-level scenarios such as cache timing behavior
 * and multi-step fetch/invalidate/re-fetch cycles.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CredentialAPIClient } from "../credential-api.js";

/** Create a mock API response for issuer public keys. */
function makeMockKeysResponse(id = "key-001", fillByte = 0xaa) {
  return [
    {
      id,
      publicKey: btoa(
        String.fromCharCode(...new Uint8Array(48).fill(fillByte)),
      ),
      algorithm: "BBS+",
      createdAt: "2026-01-15T00:00:00Z",
    },
  ];
}

/** Create a mock Response with ok=true and the given JSON data. */
function mockOkResponse(data: unknown) {
  return {
    ok: true,
    json: () => Promise.resolve(data),
  };
}

/** Create a mock Response with ok=false. */
function mockErrorResponse(status: number, statusText: string) {
  return {
    ok: false,
    status,
    statusText,
  };
}

describe("CredentialAPIClient Integration", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("fetch and cache public key", () => {
    it("should fetch, parse, and cache the public key on first call", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue(mockOkResponse(mockData));

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      const keys1 = await client.getIssuerPublicKeys();
      expect(keys1).toHaveLength(1);
      expect(keys1[0].id).toBe("key-001");
      expect(keys1[0].publicKey).toBeInstanceOf(Uint8Array);
      expect(keys1[0].publicKey.length).toBe(48);

      // Second call should use cache.
      const keys2 = await client.getIssuerPublicKeys();
      expect(keys2).toEqual(keys1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("should return same cached reference on subsequent calls within TTL", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue(mockOkResponse(mockData));

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      const keys1 = await client.getIssuerPublicKeys();
      const keys2 = await client.getIssuerPublicKeys();
      const keys3 = await client.getIssuerPublicKeys();

      // All three should be the exact same reference (identity equality).
      expect(keys1).toBe(keys2);
      expect(keys2).toBe(keys3);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("cache expiry", () => {
    it("should re-fetch after cache TTL expires", async () => {
      vi.useFakeTimers();

      const initialData = makeMockKeysResponse("key-001", 0xaa);
      const refreshedData = makeMockKeysResponse("key-002", 0xbb);

      fetchMock
        .mockResolvedValueOnce(mockOkResponse(initialData))
        .mockResolvedValueOnce(mockOkResponse(refreshedData));

      const cacheTTL = 5000;
      const client = new CredentialAPIClient(
        "https://auth.example.com",
        cacheTTL,
      );

      const keys1 = await client.getIssuerPublicKeys();
      expect(keys1[0].id).toBe("key-001");
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Advance time past TTL.
      vi.advanceTimersByTime(cacheTTL + 1);

      const keys2 = await client.getIssuerPublicKeys();
      expect(keys2[0].id).toBe("key-002");
      expect(fetchMock).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });

    it("should serve cached data when just before TTL expiry", async () => {
      vi.useFakeTimers();

      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue(mockOkResponse(mockData));

      const cacheTTL = 10000;
      const client = new CredentialAPIClient(
        "https://auth.example.com",
        cacheTTL,
      );

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Advance to just before TTL.
      vi.advanceTimersByTime(cacheTTL - 1);

      await client.getIssuerPublicKeys();
      // Should still use cache.
      expect(fetchMock).toHaveBeenCalledTimes(1);

      vi.useRealTimers();
    });
  });

  describe("network error handling", () => {
    it("should throw on network failure", async () => {
      fetchMock.mockRejectedValue(new Error("Network error"));

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Network error",
      );
    });

    it("should throw on HTTP 500 error", async () => {
      fetchMock.mockResolvedValue(
        mockErrorResponse(500, "Internal Server Error"),
      );

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Failed to fetch issuer public keys: 500 Internal Server Error",
      );
    });

    it("should throw on HTTP 404 error", async () => {
      fetchMock.mockResolvedValue(mockErrorResponse(404, "Not Found"));

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Failed to fetch issuer public keys: 404 Not Found",
      );
    });

    it("should retry fetch after previous failure on next call", async () => {
      fetchMock
        .mockRejectedValueOnce(new Error("Network error"))
        .mockResolvedValueOnce(mockOkResponse(makeMockKeysResponse()));

      const client = new CredentialAPIClient("https://auth.example.com");

      // First call fails.
      await expect(client.getIssuerPublicKeys()).rejects.toThrow();

      // Second call should try again and succeed.
      const keys = await client.getIssuerPublicKeys();
      expect(keys).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe("cache invalidation", () => {
    it("should force re-fetch after invalidateCache()", async () => {
      const initialData = makeMockKeysResponse("key-001", 0xaa);
      const refreshedData = makeMockKeysResponse("key-002", 0xbb);

      fetchMock
        .mockResolvedValueOnce(mockOkResponse(initialData))
        .mockResolvedValueOnce(mockOkResponse(refreshedData));

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      const keys1 = await client.getIssuerPublicKeys();
      expect(keys1[0].id).toBe("key-001");
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Invalidate cache.
      client.invalidateCache();

      // Next call should re-fetch.
      const keys2 = await client.getIssuerPublicKeys();
      expect(keys2[0].id).toBe("key-002");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("should re-cache after invalidation", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue(mockOkResponse(mockData));

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      client.invalidateCache();
      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(2);

      // After re-fetch, cache should be active again.
      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("should be safe to call invalidateCache() when no cache exists", () => {
      const client = new CredentialAPIClient("https://auth.example.com");

      // Should not throw.
      expect(() => client.invalidateCache()).not.toThrow();
    });

    it("should be safe to call invalidateCache() multiple times", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue(mockOkResponse(mockData));

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      client.invalidateCache();
      client.invalidateCache();
      client.invalidateCache();

      await client.getIssuerPublicKeys();
      // Should only fetch once more after invalidation, not three times.
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });
});
