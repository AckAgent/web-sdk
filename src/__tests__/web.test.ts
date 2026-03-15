import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SigningErrorCode } from "../types.js";
import {
  SigningRejectedError,
  SigningExpiredError,
  SigningError,
} from "../errors.js";
import {
  generateKeyPair,
  deriveResponseKey,
  encrypt,
  decrypt,
  requestIdToBytes,
} from "../crypto.js";
import type {
  TransportRequest,
  TransportResponse,
} from "../transport/types.js";
import { SignerClient } from "../client.js";
import {
  createFetchMock,
  mockFetchResponse,
  mockUuid,
  toBase64,
  toHex,
  mockStoredAccount,
  mockUserDevice,
  createSigningFlowMock,
} from "./mocks.js";

vi.mock("../browser.js", () => ({
  isBrowser: () => true,
  collectBrowserMetadata: () => ({
    url: "https://example.com/checkout",
    origin: "https://example.com",
    pageTitle: "Checkout - Example Store",
    userAgent: "Mozilla/5.0 (Test)",
    referrer: "https://example.com/cart",
    timestamp: "2024-01-01T00:00:00.000Z",
  }),
}));

import {
  requestWebApproval,
  requestWebApprovalWithTransport,
  approveWeb,
} from "../web.js";

function createExpiredTransport() {
  let capturedRequest: TransportRequest | undefined;
  const transport = {
    async send(request: TransportRequest): Promise<TransportResponse> {
      capturedRequest = request;
      return {
        id: request.id,
        status: "expired",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      };
    },
  };
  return { transport, getCapturedRequest: () => capturedRequest };
}

describe("signing-related client methods", () => {
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

  describe("createSigningRequest", () => {
    it("should create request with all required fields", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();
      const pairingId = mockUuid();
      const ephemeralKeyPair = await generateKeyPair();
      const ephemeralPublic = ephemeralKeyPair.publicKey;
      const encryptedPayload = new Uint8Array([1, 2, 3, 4, 5]);
      const payloadNonce = new Uint8Array(12);

      mockFetchResponse(fetchMock, 202, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.createSigningRequest({
        id: requestId,
        pairingId,
        ephemeralPublic,
        encryptedPayload,
        payloadNonce,
        expiresIn: 300,
        timestamp: Date.now(),
      });

      expect(result.id).toBe(requestId);
      expect(result.status).toBe("pending");

      const request = fetchMock.mock.calls[0][0] as Request;
      const body = await request.json();
      expect(body.id).toBe(requestId);
      expect(body.requesterId).toBe(pairingId);
    });

    it("should not include display metadata (it is in encrypted payload now)", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();
      const ephemeralKeyPair = await generateKeyPair();

      mockFetchResponse(fetchMock, 202, {
        id: requestId,
        status: "pending",
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      await client.createSigningRequest({
        id: requestId,
        pairingId: mockUuid(),
        ephemeralPublic: ephemeralKeyPair.publicKey,
        encryptedPayload: new Uint8Array([1, 2, 3]),
        payloadNonce: new Uint8Array(12),
        expiresIn: 300,
        timestamp: Date.now(),
      });

      const request = fetchMock.mock.calls[0][0] as Request;
      const body = await request.json();
      expect(body.display_metadata).toBeUndefined();
    });
  });

  describe("pollSigningResponse", () => {
    it("should return responded status with response data", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();
      const ephemeralKeyPair = await generateKeyPair();
      const ephemeralPublic = ephemeralKeyPair.publicKey;

      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "responded",
        approverEphemeralKeyHex: toHex(ephemeralPublic),
        encryptedResponse: toBase64(new Uint8Array([1, 2, 3])),
        responseNonce: toBase64(new Uint8Array(12)),
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });

      const result = await client.pollSigningResponse(requestId, 5000, {
        initialInterval: 10,
      });

      expect(result.status).toBe("responded");
      expect(result.approverEphemeralKey).toBeDefined();
      expect(result.encryptedResponse).toBeDefined();
      expect(result.responseNonce).toBeDefined();
    });

    it("should throw SigningExpiredError when expired", async () => {
      const client = new SignerClient("http://localhost:8080");
      const requestId = mockUuid();

      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "expired",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      });

      await expect(
        client.pollSigningResponse(requestId, 5000, { initialInterval: 10 }),
      ).rejects.toThrow(SigningExpiredError);
    });
  });
});

describe("response decryption", () => {
  it("should decrypt response with correct keys", async () => {
    const requesterKeyPair = await generateKeyPair();
    const requestId = mockUuid();
    const requestIdBytes = requestIdToBytes(requestId);

    const signerResponseKeyPair = await generateKeyPair();

    const signerResponseKey = await deriveResponseKey(
      signerResponseKeyPair.privateKey,
      requesterKeyPair.publicKey,
      requestIdBytes,
    );

    const signature = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const plaintextHash = "sha256:abc123";
    const responsePayload = JSON.stringify({
      signature: toBase64(signature),
      plaintextHash: plaintextHash,
    });
    const { ciphertext, nonce } = encrypt(
      signerResponseKey,
      new TextEncoder().encode(responsePayload),
      requestIdBytes,
    );

    const requesterResponseKey = await deriveResponseKey(
      requesterKeyPair.privateKey,
      signerResponseKeyPair.publicKey,
      requestIdBytes,
    );

    expect(requesterResponseKey).toEqual(signerResponseKey);

    const decrypted = decrypt(
      requesterResponseKey,
      nonce,
      ciphertext,
      requestIdBytes,
    );
    const decryptedPayload = JSON.parse(new TextDecoder().decode(decrypted));

    expect(decryptedPayload.signature).toBe(toBase64(signature));
    expect(decryptedPayload.plaintextHash).toBe(plaintextHash);
  });
});

describe("SigningErrorCode", () => {
  it.each([
    ["Rejected", 1],
    ["Expired", 2],
    ["UnsupportedAlgorithm", 3],
    ["InvalidPairing", 4],
    ["KeyNotFound", 5],
    ["InternalError", 6],
  ] as const)("%s should be %i", (name, expected) => {
    expect(SigningErrorCode[name]).toBe(expected);
  });
});

describe("Error classes", () => {
  it.each([
    {
      name: "SigningRejectedError with custom message",
      error: new SigningRejectedError("Custom message"),
      code: SigningErrorCode.Rejected,
      message: "Custom message",
      errorName: "SigningRejectedError",
    },
    {
      name: "SigningRejectedError with default message",
      error: new SigningRejectedError(),
      code: SigningErrorCode.Rejected,
      message: "Signing request rejected",
      errorName: "SigningRejectedError",
    },
    {
      name: "SigningExpiredError",
      error: new SigningExpiredError(),
      code: SigningErrorCode.Expired,
      message: "Signing request expired",
      errorName: "SigningExpiredError",
    },
    {
      name: "SigningError with custom code",
      error: new SigningError(SigningErrorCode.KeyNotFound, "Key not found"),
      code: SigningErrorCode.KeyNotFound,
      message: "Key not found",
      errorName: "SigningError",
    },
  ])("$name should have correct properties", ({
    error,
    code,
    message,
    errorName,
  }) => {
    expect(error.code).toBe(code);
    expect(error.message).toBe(message);
    expect(error.name).toBe(errorName);
  });
});

describe("web approval flows with fetch", () => {
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

  it.each([
    { fn: "requestWebApproval", caller: requestWebApproval },
    { fn: "approveWeb", caller: approveWeb },
  ])("$fn should throw SigningExpiredError when request expires", async ({
    caller,
  }) => {
    const account = await mockStoredAccount();
    const flowMock = createSigningFlowMock(fetchMock);

    flowMock.mockPendingResponse();
    flowMock.mockExpiredResponse();

    await expect(
      caller(
        account,
        {
          title: "Confirm Payment",
          description: "$50.00 to Merchant",
          plaintext: "Payment details...",
        },
        undefined,
        5000,
      ),
    ).rejects.toThrow(SigningExpiredError);
  });

  it("requestWebApproval should make request to correct endpoint", async () => {
    const account = await mockStoredAccount();
    const flowMock = createSigningFlowMock(fetchMock);

    flowMock.mockPendingResponse();
    flowMock.mockExpiredResponse();

    await expect(
      requestWebApproval(
        account,
        {
          title: "Confirm Payment",
          description: "$50.00 to Merchant",
          plaintext: "Payment details...",
        },
        undefined,
        5000,
      ),
    ).rejects.toThrow(SigningExpiredError);

    expect(fetchMock).toHaveBeenCalled();
    const request = fetchMock.mock.calls[0][0] as Request;
    expect(request.url).toContain("/api/v1/requests");
  });

  it("requestWebApproval should include browser metadata in the encrypted payload", async () => {
    const account = await mockStoredAccount();
    const flowMock = createSigningFlowMock(fetchMock);

    flowMock.mockPendingResponse();
    flowMock.mockExpiredResponse();

    await expect(
      requestWebApproval(
        account,
        { title: "Test Action", plaintext: "Test content" },
        undefined,
        5000,
      ),
    ).rejects.toThrow(SigningExpiredError);

    const { body } = flowMock.capturedRequest;
    expect(body).toBeDefined();
    if (!body) throw new Error("Expected request body to be defined");
    expect(body.encryptedPayload).toBeDefined();
    expect(body.payloadNonce).toBeDefined();
  });

  it("requestWebApproval should send wrappedKeys to the relay API", async () => {
    const account = await mockStoredAccount();
    const flowMock = createSigningFlowMock(fetchMock);

    flowMock.mockPendingResponse();
    flowMock.mockExpiredResponse();

    await expect(
      requestWebApproval(
        account,
        { title: "Test Action", plaintext: "Test content" },
        undefined,
        5000,
      ),
    ).rejects.toThrow(SigningExpiredError);

    const { body } = flowMock.capturedRequest;
    expect(body).toBeDefined();
    if (!body) throw new Error("Expected request body to be defined");
    expect(body.wrappedKeys).toBeDefined();
    expect(Array.isArray(body.wrappedKeys)).toBe(true);
    const wrappedKeys = body.wrappedKeys as Array<Record<string, string>>;
    expect(wrappedKeys.length).toBe(1);
    expect(wrappedKeys[0].encryptionPublicKeyHex).toBeDefined();
    expect(wrappedKeys[0].wrappedKey).toBeDefined();
    expect(wrappedKeys[0].wrappedKeyNonce).toBeDefined();
    expect(wrappedKeys[0].requesterEphemeralKeyHex).toBeDefined();
  });

  it("requestWebApproval should return KeyNotFound for empty devices", async () => {
    const account = await mockStoredAccount({ devices: [] });

    const result = await requestWebApproval(account, {
      title: "Test",
      plaintext: "Content",
    });

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(SigningErrorCode.KeyNotFound);
    expect(result.errorMessage).toBe("No devices available in account");
  });
});

describe("requestWebApprovalWithTransport", () => {
  it("should send via transport and decrypt response", async () => {
    const account = await mockStoredAccount();
    const signature = new Uint8Array([9, 8, 7, 6]);
    const plaintextHash = "sha256:deadbeef";

    const transport = {
      async send(request: TransportRequest): Promise<TransportResponse> {
        const signerResponseKeyPair = await generateKeyPair();
        const requestIdBytes = requestIdToBytes(request.id);
        const responseKey = await deriveResponseKey(
          signerResponseKeyPair.privateKey,
          request.ephemeralPublic,
          requestIdBytes,
        );

        const responsePayload = JSON.stringify({
          signature: toBase64(signature),
          plaintextHash,
        });
        const { ciphertext, nonce } = encrypt(
          responseKey,
          new TextEncoder().encode(responsePayload),
          requestIdBytes,
        );

        return {
          id: request.id,
          status: "responded",
          ephemeralPublic: signerResponseKeyPair.publicKey,
          encryptedResponse: ciphertext,
          responseNonce: nonce,
          respondedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 300000).toISOString(),
        };
      },
    };

    const result = await requestWebApprovalWithTransport(
      account,
      {
        title: "Confirm Action",
        description: "Transport test",
        plaintext: "Hello from transport test",
      },
      transport,
    );

    expect(result.success).toBe(true);
    expect(result.signature).toEqual(signature);
    expect(result.plaintextHash).toBe(plaintextHash);
  });

  it("should include wrappedKeys in the transport request", async () => {
    const account = await mockStoredAccount();
    const { transport, getCapturedRequest } = createExpiredTransport();

    await requestWebApprovalWithTransport(
      account,
      { title: "Multi-device test", plaintext: "Content for multi-device" },
      transport,
    );

    const capturedRequest = getCapturedRequest();
    expect(capturedRequest).toBeDefined();
    if (!capturedRequest) throw new Error("Expected captured request");
    expect(capturedRequest.wrappedKeys).toBeDefined();
    if (!capturedRequest.wrappedKeys) throw new Error("Expected wrapped keys");
    expect(capturedRequest.wrappedKeys).toHaveLength(1);
    const wrappedKey = capturedRequest.wrappedKeys[0];
    expect(wrappedKey.encryptionPublicKeyHex).toBeDefined();
    expect(wrappedKey.wrappedKey).toBeDefined();
    expect(wrappedKey.wrappedKeyNonce).toBeDefined();
    expect(wrappedKey.requesterEphemeralKeyHex).toBeDefined();
  });

  it("should encrypt for multiple devices when account has multiple devices", async () => {
    const device1 = await mockUserDevice({ isPrimary: true });
    const device2 = await mockUserDevice({ isPrimary: false });
    const account = await mockStoredAccount({ devices: [device1, device2] });
    const { transport, getCapturedRequest } = createExpiredTransport();

    await requestWebApprovalWithTransport(
      account,
      { title: "Multi-device test", plaintext: "Content for all devices" },
      transport,
    );

    const capturedRequest = getCapturedRequest();
    expect(capturedRequest).toBeDefined();
    if (!capturedRequest) throw new Error("Expected captured request");
    expect(capturedRequest.wrappedKeys).toBeDefined();
    if (!capturedRequest.wrappedKeys) throw new Error("Expected wrapped keys");
    expect(capturedRequest.wrappedKeys).toHaveLength(2);

    const ephemeralKeys = capturedRequest.wrappedKeys.map(
      (wk) => wk.requesterEphemeralKeyHex,
    );
    expect(new Set(ephemeralKeys).size).toBe(2);
  });
});
