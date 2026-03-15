/**
 * Tests for CredentialAPIClient module.
 *
 * Tests cover:
 * - Successful fetch and parsing of issuer public keys
 * - Caching behavior (cache hit, cache miss, cache expiry)
 * - Error handling for failed fetches
 * - Cache invalidation
 * - Response validation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CredentialAPIClient } from "../credential-api.js";

/** Create a mock API response for issuer public keys. */
function makeMockKeysResponse() {
  return [
    {
      id: "key-001",
      publicKey: btoa(String.fromCharCode(...new Uint8Array(48).fill(0xaa))),
      algorithm: "BBS+",
      createdAt: "2025-01-15T00:00:00Z",
    },
    {
      id: "key-002",
      publicKey: btoa(String.fromCharCode(...new Uint8Array(48).fill(0xbb))),
      algorithm: "BBS+",
      createdAt: "2025-02-01T00:00:00Z",
    },
  ];
}

describe("CredentialAPIClient", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("getIssuerPublicKeys", () => {
    it("should fetch and parse issuer public keys", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const client = new CredentialAPIClient("https://auth.example.com");
      const keys = await client.getIssuerPublicKeys();

      expect(keys).toHaveLength(2);
      expect(keys[0].id).toBe("key-001");
      expect(keys[0].algorithm).toBe("BBS+");
      expect(keys[0].createdAt).toBe("2025-01-15T00:00:00Z");
      expect(keys[0].publicKey).toBeInstanceOf(Uint8Array);
      expect(keys[0].publicKey.length).toBe(48);
      // Verify the decoded bytes match the original
      for (let i = 0; i < 48; i++) {
        expect(keys[0].publicKey[i]).toBe(0xaa);
      }

      expect(keys[1].id).toBe("key-002");
      expect(keys[1].publicKey[0]).toBe(0xbb);

      expect(fetchMock).toHaveBeenCalledWith(
        "https://auth.example.com/api/v1/credentials/public-key",
      );
    });

    it("should throw on non-OK response", async () => {
      fetchMock.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Failed to fetch issuer public keys: 500 Internal Server Error",
      );
    });

    it("should throw on 404 response", async () => {
      fetchMock.mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Failed to fetch issuer public keys: 404 Not Found",
      );
    });

    it("should throw on non-array response", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ error: "not an array" }),
      });

      const client = new CredentialAPIClient("https://auth.example.com");

      await expect(client.getIssuerPublicKeys()).rejects.toThrow(
        "Expected array of issuer public keys from API",
      );
    });
  });

  describe("caching", () => {
    it("should cache results and not fetch again within TTL", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      const keys1 = await client.getIssuerPublicKeys();
      const keys2 = await client.getIssuerPublicKeys();

      expect(keys1).toEqual(keys2);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("should refetch after cache TTL expires", async () => {
      vi.useFakeTimers();

      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const cacheTTL = 5000;
      const client = new CredentialAPIClient(
        "https://auth.example.com",
        cacheTTL,
      );

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // Advance time past TTL
      vi.advanceTimersByTime(cacheTTL + 1);

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });

    it("should serve cached data before TTL even if new data is available", async () => {
      const originalData = makeMockKeysResponse();
      const updatedData = [
        {
          id: "key-003",
          publicKey: btoa(
            String.fromCharCode(...new Uint8Array(48).fill(0xcc)),
          ),
          algorithm: "BBS+",
          createdAt: "2025-03-01T00:00:00Z",
        },
      ];

      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(originalData),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(updatedData),
        });

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      const keys1 = await client.getIssuerPublicKeys();
      expect(keys1).toHaveLength(2);
      expect(keys1[0].id).toBe("key-001");

      // Second call should use cache
      const keys2 = await client.getIssuerPublicKeys();
      expect(keys2).toHaveLength(2);
      expect(keys2[0].id).toBe("key-001");

      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("invalidateCache", () => {
    it("should force a fresh fetch after cache invalidation", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const client = new CredentialAPIClient("https://auth.example.com", 60000);

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(1);

      client.invalidateCache();

      await client.getIssuerPublicKeys();
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe("base URL handling", () => {
    it("should construct the correct endpoint URL", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const client = new CredentialAPIClient("https://auth.custom-domain.com");
      await client.getIssuerPublicKeys();

      expect(fetchMock).toHaveBeenCalledWith(
        "https://auth.custom-domain.com/api/v1/credentials/public-key",
      );
    });

    it("should handle base URL with trailing slash", async () => {
      const mockData = makeMockKeysResponse();
      fetchMock.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      // Note: baseUrl with trailing slash would produce double slash, but that is
      // the caller's responsibility. This test documents current behavior.
      const client = new CredentialAPIClient("https://auth.example.com/");
      await client.getIssuerPublicKeys();

      expect(fetchMock).toHaveBeenCalledWith(
        "https://auth.example.com//api/v1/credentials/public-key",
      );
    });
  });
});
