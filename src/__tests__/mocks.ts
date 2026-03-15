/**
 * Mock utilities for Web SDK tests
 */

import { vi } from "vitest";
import type {
  BackendRequestStatus,
  BackendRequesterSession,
  UserDevice,
  StoredAccount,
} from "../types.js";
import {
  generateKeyPair,
  deriveResponseKey,
  encrypt,
  requestIdToBytes,
  type KeyPair,
} from "../crypto.js";

// Type for fetch mock
export type FetchMock = ReturnType<typeof vi.fn>;

/**
 * Create a mock fetch function
 */
export function createFetchMock(): FetchMock {
  return vi.fn();
}

/**
 * Create a mock Response object that satisfies openapi-fetch's requirements.
 * openapi-fetch reads response.headers for content-type and calls response.json()/text().
 */
function createMockResponse(
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): Response {
  const headers = new Headers({
    "content-type": "application/json",
    ...extraHeaders,
  });
  const bodyStr = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? "OK" : "Error",
    headers,
    json: async () => body,
    text: async () => bodyStr,
    clone: () => createMockResponse(status, body, extraHeaders),
    body: null,
    bodyUsed: false,
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob(),
    formData: async () => new FormData(),
    redirected: false,
    type: "basic" as ResponseType,
    url: "",
    bytes: async () => new Uint8Array(),
  } as Response;
}

/**
 * Set up mock response for fetch
 */
export function mockFetchResponse(
  fetchMock: FetchMock,
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): void {
  fetchMock.mockResolvedValueOnce(
    createMockResponse(status, body, extraHeaders),
  );
}

/**
 * Set up mock network error for fetch
 */
export function mockFetchError(fetchMock: FetchMock, message: string): void {
  fetchMock.mockRejectedValueOnce(new Error(message));
}

/**
 * Generate a mock 32-byte symmetric key (Uint8Array)
 */
export function mockKey(): Uint8Array {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Generate a mock P-256 public key (33 bytes compressed SEC1)
 * Uses actual key generation to ensure valid format
 */
export async function mockPublicKey(): Promise<Uint8Array> {
  const keyPair = await generateKeyPair();
  return keyPair.publicKey;
}

/**
 * Generate a mock P-256 ECDH key pair using Web Crypto
 * Returns a KeyPair with non-extractable CryptoKey privateKey
 */
export async function mockKeyPair(): Promise<KeyPair> {
  return generateKeyPair();
}

/**
 * Generate a mock UUID
 */
export function mockUuid(): string {
  return crypto.randomUUID();
}

/**
 * Create a mock UserDevice
 * Note: This is async because it generates a P-256 public key
 */
export async function mockUserDevice(
  overrides?: Partial<UserDevice>,
): Promise<UserDevice> {
  const publicKey = await mockPublicKey();
  return {
    deviceId: mockUuid(),
    deviceName: "Test Device",
    publicKey,
    isPrimary: true,
    ...overrides,
  };
}

/**
 * Create a mock StoredAccount
 * Note: This is async because it generates a CryptoKey
 */
export async function mockStoredAccount(
  overrides?: Partial<
    Omit<StoredAccount, "identityPrivateKey"> & {
      identityPrivateKey?: CryptoKey;
    }
  >,
): Promise<StoredAccount> {
  const keyPair = await mockKeyPair();
  const device = await mockUserDevice();
  return {
    userId: mockUuid(),
    accessToken: "test-access-token",
    expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
    loggedInAt: new Date(),
    sasVerified: true,
    devices: [device],
    identityPrivateKey: keyPair.privateKey,
    identityPublicKey: keyPair.publicKey,
    relayUrl: "http://localhost:8080",
    ...overrides,
  };
}

/**
 * Create a mock BackendRequesterSession
 * Note: This is async because it generates a P-256 public key
 */
export async function mockBackendRequesterSession(
  overrides?: Partial<BackendRequesterSession>,
): Promise<BackendRequesterSession> {
  const device = await mockUserDevice();
  return {
    id: mockUuid(),
    status: "pending",
    userId: mockUuid(),
    devices: [device],
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    ...overrides,
  };
}

/**
 * Create a mock BackendRequestStatus
 */
export function mockBackendRequestStatus(
  overrides?: Partial<BackendRequestStatus>,
): BackendRequestStatus {
  return {
    id: mockUuid(),
    status: "pending",
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    ...overrides,
  };
}

/**
 * Encode Uint8Array to base64
 */
export function toBase64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

/**
 * Decode base64 to Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  return new Uint8Array(
    atob(base64)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );
}

/**
 * Encode Uint8Array to lowercase hex string
 */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decode hex string to Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Create an encrypted signer response (simulates iOS device response).
 *
 * @param requesterEphemeralPublic - The requester's ephemeral public key (from the signing request)
 * @param requestId - The request ID string
 * @param outcome - Whether the request was approved, rejected, or has a specific error
 * @param signature - Optional signature bytes (for approved outcome)
 * @returns Encrypted response data for mock fetch response
 */
export async function createMockSignerResponse(
  requesterEphemeralPublic: Uint8Array,
  requestId: string,
  outcome:
    | "approved"
    | "rejected"
    | "expired"
    | { errorCode: number; errorMessage: string },
  signature?: Uint8Array,
): Promise<{
  approverEphemeralKeyHex: string;
  encryptedResponse: string;
  responseNonce: string;
}> {
  // Generate signer's response ephemeral key pair
  const signerResponseKeyPair = await generateKeyPair();
  const requestIdBytes = requestIdToBytes(requestId);

  // Derive response key (same as what requester will compute)
  const responseKey = await deriveResponseKey(
    signerResponseKeyPair.privateKey,
    requesterEphemeralPublic,
    requestIdBytes,
  );

  // Build response payload based on outcome
  let responsePayload: object;
  if (outcome === "approved") {
    const sig = signature ?? new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    responsePayload = { signature: toBase64(sig) };
  } else if (outcome === "rejected") {
    responsePayload = { errorCode: 1, errorMessage: "User rejected" };
  } else if (outcome === "expired") {
    responsePayload = { errorCode: 2, errorMessage: "Request expired" };
  } else {
    responsePayload = {
      errorCode: outcome.errorCode,
      errorMessage: outcome.errorMessage,
    };
  }

  // Encrypt the response
  const payloadBytes = new TextEncoder().encode(
    JSON.stringify(responsePayload),
  );
  const { ciphertext, nonce } = encrypt(responseKey, payloadBytes);

  return {
    approverEphemeralKeyHex: toHex(signerResponseKeyPair.publicKey),
    encryptedResponse: toBase64(ciphertext),
    responseNonce: toBase64(nonce),
  };
}

/**
 * Setup fetch mocks for a complete signing flow.
 * Returns helpers to capture the request and provide responses.
 */
export function createSigningFlowMock(fetchMock: FetchMock): {
  capturedRequest: {
    id?: string;
    ephemeralPublic?: Uint8Array;
    body?: Record<string, unknown>;
  };
  mockPendingResponse: () => void;
  mockRespondedResponse: (
    requestId: string,
    requesterEphemeralPublic: Uint8Array,
    outcome:
      | "approved"
      | "rejected"
      | { errorCode: number; errorMessage: string },
    signature?: Uint8Array,
  ) => Promise<void>;
  mockExpiredResponse: (requestId?: string) => void;
} {
  const capturedRequest: {
    id?: string;
    ephemeralPublic?: Uint8Array;
    body?: Record<string, unknown>;
  } = {};

  return {
    capturedRequest,

    mockPendingResponse: () => {
      fetchMock.mockImplementationOnce(
        async (input: Request | string, init?: RequestInit) => {
          // openapi-fetch passes a Request object as the single argument
          let body: Record<string, unknown>;
          if (input instanceof Request) {
            body = await input.json();
          } else {
            body = JSON.parse(init?.body as string);
          }
          capturedRequest.id = body.id as string;
          capturedRequest.ephemeralPublic = fromHex(
            body.requesterEphemeralKeyHex as string,
          );
          capturedRequest.body = body;

          return createMockResponse(202, {
            id: body.id,
            status: "pending",
            expiresAt: new Date(Date.now() + 300000).toISOString(),
          });
        },
      );
    },

    mockRespondedResponse: async (
      requestId: string,
      requesterEphemeralPublic: Uint8Array,
      outcome:
        | "approved"
        | "rejected"
        | { errorCode: number; errorMessage: string },
      signature?: Uint8Array,
    ) => {
      const encryptedResponse = await createMockSignerResponse(
        requesterEphemeralPublic,
        requestId,
        outcome,
        signature,
      );

      mockFetchResponse(fetchMock, 200, {
        id: requestId,
        status: "responded",
        ...encryptedResponse,
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });
    },

    mockExpiredResponse: (requestId?: string) => {
      mockFetchResponse(fetchMock, 200, {
        id: requestId ?? capturedRequest.id ?? mockUuid(),
        status: "expired",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      });
    },
  };
}
