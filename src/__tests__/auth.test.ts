/**
 * Tests for authentication module (QR code login flow)
 * Web SDK is the requester that creates requester sessions
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  RequesterSession,
  createRequesterSession,
  login,
  isAccountValid,
  generateQRCodeUrl,
  needsTokenRefresh,
  refreshTokens,
  updateAccountTokens,
} from "../auth.js";
import { NetworkError } from "../errors.js";
import { SessionClient } from "../session-client.js";
import {
  createFetchMock,
  mockFetchResponse,
  mockKeyPair,
  mockStoredAccount,
} from "./mocks.js";

describe("auth", () => {
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

  describe("generateQRCodeUrl", () => {
    it("should generate proper QR code URL", () => {
      const sessionId = "session-123";
      const publicKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const url = generateQRCodeUrl(
        "https://login.ackagent.com",
        sessionId,
        publicKey,
      );

      expect(url).toContain("https://login.ackagent.com/link/login");
      expect(url).toContain("sid=session-123");
      expect(url).toContain("pk=");
    });
  });

  describe("RequesterSession", () => {
    it("should store session data", async () => {
      const client = new SessionClient("http://localhost:8080");
      const keyPair = await mockKeyPair();
      const expiresAt = new Date(Date.now() + 300000);

      const requesterSession = new RequesterSession(
        client,
        "http://localhost:8080",
        "https://login.ackagent.com",
        "session-123",
        expiresAt,
        keyPair,
      );

      expect(requesterSession.sessionId).toBe("session-123");
      expect(requesterSession.expiresAt).toEqual(expiresAt);
      expect(requesterSession.qrCodeUrl).toContain(
        "https://login.ackagent.com/link/login",
      );
    });

    it("should wait for verification and return account", async () => {
      const client = new SessionClient("http://localhost:8080");
      const keyPair = await mockKeyPair();
      const expiresAt = new Date(Date.now() + 300000);

      const requesterSession = new RequesterSession(
        client,
        "http://localhost:8080",
        "https://login.ackagent.com",
        "session-123",
        expiresAt,
        keyPair,
      );

      // Mock verified status response
      mockFetchResponse(fetchMock, 200, {
        status: "verified",
        expiresAt: expiresAt.toISOString(),
      });

      // Mock tokens response
      mockFetchResponse(fetchMock, 200, {
        accessToken: "access-token-123",
        refreshToken: "refresh-token-123",
        expiresIn: 3600,
        tokenType: "Bearer",
        userId: "user-123",
      });

      const account = await requesterSession.waitForVerification(5000);

      expect(account.userId).toBe("user-123");
      expect(account.accessToken).toBe("access-token-123");
      expect(account.sasVerified).toBe(true);
      expect(account.identityPrivateKey).toBeInstanceOf(CryptoKey);
      expect(account.identityPublicKey).toEqual(keyPair.publicKey);
    });

    it("should throw on rejection", async () => {
      const client = new SessionClient("http://localhost:8080");
      const keyPair = await mockKeyPair();
      const expiresAt = new Date(Date.now() + 300000);

      const requesterSession = new RequesterSession(
        client,
        "http://localhost:8080",
        "https://login.ackagent.com",
        "session-123",
        expiresAt,
        keyPair,
      );

      mockFetchResponse(fetchMock, 200, {
        status: "rejected",
        expiresAt: expiresAt.toISOString(),
      });

      await expect(requesterSession.waitForVerification(5000)).rejects.toThrow(
        NetworkError,
      );
    });
  });

  describe("createRequesterSession", () => {
    it("should create QR code requester session", async () => {
      mockFetchResponse(fetchMock, 200, {
        sessionId: "session-123",
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        tokenClaimSecret: "secret-123",
      });

      const session = await createRequesterSession({
        relayUrl: "http://localhost:8080",
        loginUrl: "https://login.ackagent.com",
        name: "Test App",
      });

      expect(session.sessionId).toBe("session-123");
      expect(session.qrCodeUrl).toContain(
        "https://login.ackagent.com/link/login",
      );
      expect(session.qrCodeUrl).toContain("sid=session-123");
    });
  });

  describe("login", () => {
    it("should perform complete login flow", async () => {
      // Mock create session
      mockFetchResponse(fetchMock, 200, {
        sessionId: "session-123",
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        tokenClaimSecret: "secret-123",
      });

      // Mock verification polling
      mockFetchResponse(fetchMock, 200, {
        status: "verified",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      // Mock tokens
      mockFetchResponse(fetchMock, 200, {
        accessToken: "access-token-123",
        refreshToken: "refresh-token-123",
        expiresIn: 3600,
        tokenType: "Bearer",
        userId: "user-123",
      });

      const onQRCode = vi.fn().mockReturnValue(true);

      const result = await login(
        {
          relayUrl: "http://localhost:8080",
          loginUrl: "https://login.ackagent.com",
          name: "Test App",
        },
        onQRCode,
        5000,
      );

      expect(onQRCode).toHaveBeenCalledTimes(1);
      expect(result.account.userId).toBe("user-123");
      expect(result.account.sasVerified).toBe(true);
    });

    it("should throw if user cancels", async () => {
      mockFetchResponse(fetchMock, 200, {
        sessionId: "session-123",
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        tokenClaimSecret: "secret-123",
      });

      const onQRCode = vi.fn().mockReturnValue(false); // User cancels

      await expect(
        login(
          {
            relayUrl: "http://localhost:8080",
            loginUrl: "https://login.ackagent.com",
            name: "Test App",
          },
          onQRCode,
        ),
      ).rejects.toThrow("Login cancelled by user");
    });
  });

  describe("isAccountValid", () => {
    it("should return true for valid account", async () => {
      const account = await mockStoredAccount({
        sasVerified: true,
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
      });

      expect(isAccountValid(account)).toBe(true);
    });

    it("should return false for expired account", async () => {
      const account = await mockStoredAccount({
        sasVerified: true,
        expiresAt: new Date(Date.now() - 1000), // 1 second ago
      });

      expect(isAccountValid(account)).toBe(false);
    });

    it("should return false for unverified account", async () => {
      const account = await mockStoredAccount({
        sasVerified: false,
        expiresAt: new Date(Date.now() + 3600000),
      });

      expect(isAccountValid(account)).toBe(false);
    });
  });

  describe("needsTokenRefresh", () => {
    it("should return true for token expiring within 7 days", async () => {
      const account = await mockStoredAccount({
        expiresAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000), // 5 days from now
      });

      expect(needsTokenRefresh(account)).toBe(true);
    });

    it("should return true for token expiring today", async () => {
      const account = await mockStoredAccount({
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
      });

      expect(needsTokenRefresh(account)).toBe(true);
    });

    it("should return true for expired token", async () => {
      const account = await mockStoredAccount({
        expiresAt: new Date(Date.now() - 1000), // 1 second ago
      });

      expect(needsTokenRefresh(account)).toBe(true);
    });

    it("should return false for token valid longer than 7 days", async () => {
      const account = await mockStoredAccount({
        expiresAt: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000), // 10 days from now
      });

      expect(needsTokenRefresh(account)).toBe(false);
    });

    it("should return false for token expiring exactly at 7 days", async () => {
      const account = await mockStoredAccount({
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000 + 1000), // 7 days + 1 second
      });

      expect(needsTokenRefresh(account)).toBe(false);
    });
  });

  describe("refreshTokens", () => {
    it("should successfully refresh tokens", async () => {
      mockFetchResponse(fetchMock, 200, {
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        expires_in: 7200, // 2 hours
      });

      const result = await refreshTokens(
        "http://auth.example.com",
        "old-refresh-token",
        "my-client-id",
      );

      expect(result.accessToken).toBe("new-access-token");
      expect(result.refreshToken).toBe("new-refresh-token");
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());

      // Verify the fetch call
      expect(fetchMock).toHaveBeenCalledWith("http://auth.example.com/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: expect.any(URLSearchParams),
      });
    });

    it("should handle refresh without new refresh token", async () => {
      mockFetchResponse(fetchMock, 200, {
        access_token: "new-access-token",
        expires_in: 3600,
        // No refresh_token in response
      });

      const result = await refreshTokens(
        "http://auth.example.com",
        "refresh-token",
        "client-id",
      );

      expect(result.accessToken).toBe("new-access-token");
      expect(result.refreshToken).toBeUndefined();
    });

    it("should default to 1 hour expiry if not provided", async () => {
      mockFetchResponse(fetchMock, 200, {
        access_token: "new-access-token",
        // No expires_in
      });

      const before = Date.now();
      const result = await refreshTokens(
        "http://auth.example.com",
        "refresh-token",
        "client-id",
      );

      // Should be approximately 1 hour from now
      const expectedExpiry = before + 3600 * 1000;
      expect(result.expiresAt.getTime()).toBeGreaterThanOrEqual(
        expectedExpiry - 1000,
      );
      expect(result.expiresAt.getTime()).toBeLessThanOrEqual(
        expectedExpiry + 1000,
      );
    });

    it("should throw on 401 unauthorized", async () => {
      mockFetchResponse(fetchMock, 401, {
        error: "invalid_grant",
        error_description: "Refresh token expired",
      });

      await expect(
        refreshTokens("http://auth.example.com", "invalid-token", "client-id"),
      ).rejects.toThrow(NetworkError);
    });

    it("should throw on 400 bad request", async () => {
      mockFetchResponse(fetchMock, 400, {
        error: "invalid_request",
      });

      await expect(
        refreshTokens("http://auth.example.com", "token", "client-id"),
      ).rejects.toThrow(NetworkError);
    });

    it("should throw on 500 server error", async () => {
      mockFetchResponse(fetchMock, 500, {
        error: "server_error",
      });

      await expect(
        refreshTokens("http://auth.example.com", "token", "client-id"),
      ).rejects.toThrow("Token refresh failed: 500");
    });
  });

  describe("updateAccountTokens", () => {
    it("should update account with new tokens", async () => {
      const originalAccount = await mockStoredAccount({
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: new Date(Date.now() - 1000), // Expired
      });

      const newExpiry = new Date(Date.now() + 3600000);
      const updated = updateAccountTokens(originalAccount, {
        accessToken: "new-access-token",
        refreshToken: "new-refresh-token",
        expiresAt: newExpiry,
      });

      expect(updated.accessToken).toBe("new-access-token");
      expect(updated.refreshToken).toBe("new-refresh-token");
      expect(updated.expiresAt).toEqual(newExpiry);

      // Other fields should be preserved
      expect(updated.userId).toBe(originalAccount.userId);
      expect(updated.sasVerified).toBe(originalAccount.sasVerified);
      expect(updated.identityPrivateKey).toBe(
        originalAccount.identityPrivateKey,
      );
      expect(updated.identityPublicKey).toBe(originalAccount.identityPublicKey);
    });

    it("should keep old refresh token if not provided in update", async () => {
      const originalAccount = await mockStoredAccount({
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
      });

      const updated = updateAccountTokens(originalAccount, {
        accessToken: "new-access-token",
        // No refreshToken
        expiresAt: new Date(Date.now() + 3600000),
      });

      expect(updated.accessToken).toBe("new-access-token");
      expect(updated.refreshToken).toBe("old-refresh-token"); // Preserved
    });

    it("should not mutate original account", async () => {
      const originalAccount = await mockStoredAccount({
        accessToken: "old-access-token",
      });

      const originalAccessToken = originalAccount.accessToken;

      updateAccountTokens(originalAccount, {
        accessToken: "new-access-token",
        expiresAt: new Date(),
      });

      expect(originalAccount.accessToken).toBe(originalAccessToken);
    });
  });
});
