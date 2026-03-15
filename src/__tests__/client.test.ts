/**
 * Tests for SignerClient
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SignerClient } from "../client.js";
import { SessionClient } from "../session-client.js";
import { NetworkError, TimeoutError } from "../errors.js";
import {
  createFetchMock,
  mockFetchResponse,
  mockKey,
  mockUuid,
  toBase64,
  toHex,
} from "./mocks.js";

describe("SignerClient", () => {
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

  describe("constructor", () => {
    it("should create client with base URL", () => {
      const client = new SignerClient("http://localhost:8080");
      expect(client).toBeDefined();
    });

    it("should strip trailing slash from base URL", async () => {
      const client = new SignerClient("http://localhost:8080/");
      // We can verify this by making a request and checking the URL
      mockFetchResponse(fetchMock, 202, {
        id: "123",
        status: "pending",
        expiresAt: new Date().toISOString(),
      });

      await client.createSigningRequest({
        id: mockUuid(),
        pairingId: mockUuid(),
        ephemeralPublic: mockKey(),
        encryptedPayload: new Uint8Array([1, 2, 3]),
        payloadNonce: new Uint8Array(12),
        expiresIn: 300,
        timestamp: Date.now(),
      });

      // openapi-fetch passes a Request object as the single argument
      const request = fetchMock.mock.calls[0][0] as Request;
      expect(request.url).toMatch(
        /^http:\/\/localhost:8080\/api\/v1\/requests$/,
      );
    });
  });

  describe("createSigningRequest", () => {
    it("should create a signing request", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();
      const pairingId = mockUuid();

      mockFetchResponse(fetchMock, 202, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.createSigningRequest({
        id: requestId,
        pairingId,
        ephemeralPublic: mockKey(),
        encryptedPayload: new Uint8Array([1, 2, 3]),
        payloadNonce: new Uint8Array(12),
        expiresIn: 300,
        timestamp: Date.now(),
      });

      expect(result.id).toBe(requestId);
      expect(result.status).toBe("pending");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("should throw NetworkError on HTTP error", async () => {
      const client = new SignerClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 500, { error: "Internal server error" });

      await expect(
        client.createSigningRequest({
          id: mockUuid(),
          pairingId: mockUuid(),
          ephemeralPublic: mockKey(),
          encryptedPayload: new Uint8Array([1, 2, 3]),
          payloadNonce: new Uint8Array(12),
          expiresIn: 300,
          timestamp: Date.now(),
        }),
      ).rejects.toThrow(NetworkError);
    });

    it("should include optional fields", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();

      mockFetchResponse(fetchMock, 202, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      await client.createSigningRequest({
        id: requestId,
        pairingId: mockUuid(),
        keyId: "key-123",
        signingPublicKeyHex: "aabbcc112233",
        ephemeralPublic: mockKey(),
        encryptedPayload: new Uint8Array([1, 2, 3]),
        payloadNonce: new Uint8Array(12),
        expiresIn: 300,
        timestamp: Date.now(),
      });

      // openapi-fetch passes a Request object as the single argument
      const request = fetchMock.mock.calls[0][0] as Request;
      const body = await request.json();
      expect(body.signingPublicKeyHex).toBe("aabbcc112233");
      // display_metadata is no longer sent - it's inside the encrypted payload
      expect(body.display_metadata).toBeUndefined();
    });
  });

  describe("getRequestStatus", () => {
    it("should return request status", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();

      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.getRequestStatus(requestId);
      expect(result.status).toBe("pending");
    });

    it("should return responded status with response data", async () => {
      // Privacy: backend only returns 'responded' - decision is determined by decrypting payload
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();
      const ephemeralPublic = mockKey();
      const encryptedResponse = new Uint8Array([1, 2, 3, 4, 5]);
      const responseNonce = new Uint8Array(12);

      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "responded",
        approverEphemeralKeyHex: toHex(ephemeralPublic),
        encryptedResponse: toBase64(encryptedResponse),
        responseNonce: toBase64(responseNonce),
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.getRequestStatus(requestId);

      expect(result.status).toBe("responded");
      expect(result.approverEphemeralKey).toBeDefined();
      expect(result.encryptedResponse).toBeDefined();
    });

    it("should throw on 404", async () => {
      const client = new SignerClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 404, { error: "Not found" });

      await expect(client.getRequestStatus("nonexistent")).rejects.toThrow(
        NetworkError,
      );
    });
  });

  describe("pollSigningResponse", () => {
    it("should poll until responded", async () => {
      // Privacy: backend only returns 'responded' - decision is determined by decrypting payload
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();

      // First poll: pending
      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      // Second poll: responded (actual decision encrypted in response)
      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "responded",
        approverEphemeralKeyHex: toHex(mockKey()),
        encryptedResponse: toBase64(new Uint8Array([1, 2, 3])),
        responseNonce: toBase64(new Uint8Array(12)),
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.pollSigningResponse(requestId, 5000, {
        initialInterval: 10,
      });

      expect(result.status).toBe("responded");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("should throw TimeoutError when timeout exceeded", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();

      // Always return pending
      for (let i = 0; i < 10; i++) {
        mockFetchResponse(fetchMock, 200, {
          id: requestId,
          status: "pending",
          expiresAt: new Date(Date.now() + 300000).toISOString(),
        });
      }

      await expect(
        client.pollSigningResponse(requestId, 50, {
          initialInterval: 10,
          maxInterval: 10,
        }),
      ).rejects.toThrow(TimeoutError);
    });
  });

  describe("createRequesterSession", () => {
    it("should create a requester session (public, no auth)", async () => {
      const client = new SessionClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 200, {
        sessionId: "session-123",
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        tokenClaimSecret: "secret-123",
      });

      const result = await client.createRequesterSession({
        requesterName: "Test App",
        requesterPublicKey: mockKey(),
      });

      expect(result.sessionId).toBe("session-123");
      expect(result.status).toBe("pending");
      expect(result.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe("getRequesterSessionStatus", () => {
    it("should return session status (public, no auth)", async () => {
      const client = new SessionClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 200, {
        status: "verified",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.getRequesterSessionStatus("session-123");

      expect(result.status).toBe("verified");
      expect(result.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe("getRequesterSessionTokens", () => {
    it("should return tokens after verification", async () => {
      const client = new SessionClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 200, {
        accessToken: "access-token-123",
        refreshToken: "refresh-token-123",
        expiresIn: 3600,
        tokenType: "Bearer",
        userId: "user-123",
      });

      const result = await client.getRequesterSessionTokens("session-123");

      expect(result.accessToken).toBe("access-token-123");
      expect(result.refreshToken).toBe("refresh-token-123");
      expect(result.expiresIn).toBe(3600);
      expect(result.userId).toBe("user-123");
    });

    it("should throw if session not verified", async () => {
      const client = new SessionClient("http://localhost:8080");

      mockFetchResponse(fetchMock, 400, { error: "Session not verified" });

      await expect(
        client.getRequesterSessionTokens("session-123"),
      ).rejects.toThrow(NetworkError);
    });
  });

  describe("network errors", () => {
    it("should throw NetworkError on fetch failure", async () => {
      const client = new SignerClient("http://localhost:8080");

      // Mock fetch to throw an error
      fetchMock.mockRejectedValueOnce(new Error("Connection refused"));

      await expect(client.getRequestStatus("request-123")).rejects.toThrow(
        NetworkError,
      );
    });
  });
});
