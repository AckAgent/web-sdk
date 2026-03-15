import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  BlobClient,
  BlobNotFoundError,
  BlobVersionConflictError,
  NoWrappedKeyError,
  encryptKeyMetadata,
  decryptKeyMetadata,
  decryptHistoryVersion,
  type BlobRequest,
  type BlobResponse,
  type KeyMetadataBlob,
  type DeviceEncryptionInfo,
  type HistoryDetailResponse,
} from "../blob.js";
import { NetworkError, CryptoError } from "../errors.js";
import { base64Encode, hexEncode } from "../encoding.js";
import { generateKeyPair, PUBLIC_KEY_SIZE } from "../crypto.js";
import { createFetchMock, mockFetchResponse, mockFetchError } from "./mocks.js";

function makeWrappedKey(keyHex = "aabb01") {
  return {
    encryptionPublicKeyHex: keyHex,
    ephemeralPublicHex: hexEncode(new Uint8Array(33)),
    wrappedKey: base64Encode(new Uint8Array(48)),
    wrappedKeyNonce: base64Encode(new Uint8Array(12)),
  };
}

function makeResponseBody(version = 1) {
  return {
    encryptedBlob: base64Encode(new Uint8Array([1, 2, 3, 4])),
    blobNonce: base64Encode(new Uint8Array(12)),
    wrappedKeys: [makeWrappedKey()],
    version,
    updatedAt: "2024-01-15T12:00:00Z",
  };
}

function makeRequest(): BlobRequest {
  return {
    encryptedBlob: new Uint8Array([1, 2, 3, 4]),
    blobNonce: new Uint8Array(12),
    wrappedKeys: [
      {
        encryptionPublicKeyHex: "aabb01",
        ephemeralPublic: new Uint8Array(33),
        wrappedKey: new Uint8Array(48),
        wrappedKeyNonce: new Uint8Array(12),
      },
    ],
  };
}

function makeMetadata(): KeyMetadataBlob {
  return {
    keys: [
      {
        publicKeyHex: "aabbcc112233",
        purpose: "ssh",
        label: "My SSH Key",
        storageType: "secure_enclave",
        deviceName: "iPhone 15 Pro",
        approverId: "approver-uuid-1",
        publicKey: "ssh-ed25519 AAAAC3...",
        createdAt: "2024-01-15T12:00:00Z",
      },
    ],
    updatedAt: new Date("2024-01-15T12:00:00Z"),
  };
}

async function deviceInfo(
  keyHex: string,
): Promise<{ info: DeviceEncryptionInfo; privateKey: CryptoKey }> {
  const kp = await generateKeyPair();
  return {
    info: { encryptionPublicKeyHex: keyHex, publicKey: kp.publicKey },
    privateKey: kp.privateKey,
  };
}

async function encryptAndWrap(
  metadata: KeyMetadataBlob,
  devices: DeviceEncryptionInfo[],
  version = 1,
  date = "2024-01-15T12:00:00Z",
): Promise<BlobResponse> {
  const enc = await encryptKeyMetadata(metadata, devices);
  return {
    encryptedBlob: enc.encryptedBlob,
    blobNonce: enc.blobNonce,
    wrappedKeys: enc.wrappedKeys,
    version,
    updatedAt: new Date(date),
  };
}

describe("blob", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let originalFetch: typeof globalThis.fetch;
  let client: BlobClient;
  const BASE = "http://localhost:8081";
  const ORG = "org-123";
  const TOKEN = "test-access-token";

  beforeEach(() => {
    fetchMock = createFetchMock();
    originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock;
    client = new BlobClient({ baseUrl: BASE, orgId: ORG });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  const ops: Record<string, () => () => Promise<unknown>> = {
    getBlob: () => () => client.getBlob(TOKEN),
    createBlob: () => () => client.createBlob(TOKEN, makeRequest()),
    updateBlob: () => () => client.updateBlob(TOKEN, "v5", makeRequest()),
    deleteBlob: () => () =>
      client.deleteBlob(TOKEN, "aabb01aabb01", "YXNzZXJ0aW9u"),
    getBlobHistory: () => () => client.getBlobHistory(TOKEN),
    getBlobHistoryVersion: () => () => client.getBlobHistoryVersion(TOKEN, 3),
    restoreFromHistory: () => () =>
      client.restoreFromHistory(TOKEN, 3, "aabb01aabb01", "YXNzZXJ0aW9u"),
  };

  describe.each(Object.keys(ops))("%s HTTP errors", (op) => {
    it.each([
      [
        "401",
        () => mockFetchResponse(fetchMock, 401, null),
        "Authentication required",
      ],
      [
        "500",
        () => mockFetchResponse(fetchMock, 500, { error: "server error" }),
        NetworkError,
      ],
      [
        "timeout",
        () =>
          fetchMock.mockRejectedValueOnce(
            Object.assign(new Error("Timeout"), { name: "TimeoutError" }),
          ),
        "Request timed out",
      ],
    ] as const)("throws on %s", async (_l, mock, expected) => {
      mock();
      if (typeof expected === "string")
        await expect(ops[op]()()).rejects.toThrow(expected);
      else await expect(ops[op]()()).rejects.toThrow(expected);
    });
  });

  describe.each(["getBlob", "deleteBlob"])("%s network failure", (op) => {
    it("throws NetworkError", async () => {
      mockFetchError(fetchMock, "Connection refused");
      await expect(ops[op]()()).rejects.toThrow(NetworkError);
    });
  });

  describe("getBlob", () => {
    it("returns blob data and etag", async () => {
      mockFetchResponse(fetchMock, 200, makeResponseBody(5), { ETag: '"v5"' });
      const r = await client.getBlob(TOKEN);
      expect(r.response.version).toBe(5);
      expect(r.etag).toBe("v5");
      expect(r.response.encryptedBlob).toBeInstanceOf(Uint8Array);
      expect(r.response.blobNonce).toBeInstanceOf(Uint8Array);
      expect(r.response.wrappedKeys).toHaveLength(1);
      expect(r.response.wrappedKeys[0].encryptionPublicKeyHex).toBe("aabb01");
      expect(r.response.updatedAt).toBeInstanceOf(Date);
    });

    it.each([
      ["unquoted", "v1", "v1"],
      ["quoted", '"v1"', "v1"],
      ["missing", undefined, ""],
    ])("handles ETag %s", async (_l, header, expected) => {
      if (header)
        mockFetchResponse(fetchMock, 200, makeResponseBody(), { ETag: header });
      else mockFetchResponse(fetchMock, 200, makeResponseBody());
      expect((await client.getBlob(TOKEN)).etag).toBe(expected);
    });

    it("throws BlobNotFoundError on 404", async () => {
      mockFetchResponse(fetchMock, 404, null);
      const e = await client.getBlob(TOKEN).catch((e: unknown) => e);
      expect(e).toBeInstanceOf(BlobNotFoundError);
      expect((e as Error).message).toBe("Blob not found");
    });

    it("throws on abort", async () => {
      fetchMock.mockRejectedValueOnce(
        Object.assign(new Error("Aborted"), { name: "AbortError" }),
      );
      await expect(client.getBlob(TOKEN)).rejects.toThrow("Request timed out");
    });

    it("parses multiple wrapped keys", async () => {
      const body = {
        ...makeResponseBody(),
        wrappedKeys: [makeWrappedKey("aabb01"), makeWrappedKey("ccdd02")],
      };
      mockFetchResponse(fetchMock, 200, body, { ETag: '"v1"' });
      const r = await client.getBlob(TOKEN);
      expect(r.response.wrappedKeys).toHaveLength(2);
      expect(r.response.wrappedKeys[0].encryptionPublicKeyHex).toBe("aabb01");
      expect(r.response.wrappedKeys[1].encryptionPublicKeyHex).toBe("ccdd02");
    });
  });

  describe("createBlob", () => {
    it("creates and returns with etag", async () => {
      mockFetchResponse(fetchMock, 201, makeResponseBody(), { ETag: '"v1"' });
      const r = await client.createBlob(TOKEN, makeRequest());
      expect(r.response.version).toBe(1);
      expect(r.etag).toBe("v1");
      expect(r.response.encryptedBlob).toBeInstanceOf(Uint8Array);
    });

    it("throws on 409 conflict", async () => {
      mockFetchResponse(fetchMock, 409, null);
      const e = await client
        .createBlob(TOKEN, makeRequest())
        .catch((e: unknown) => e);
      expect(e).toBeInstanceOf(NetworkError);
      expect((e as Error).message).toBe(
        "Blob already exists - use updateBlob instead",
      );
    });

    it("serializes base64 fields", async () => {
      mockFetchResponse(fetchMock, 201, makeResponseBody(), { ETag: '"v1"' });
      await client.createBlob(TOKEN, makeRequest());
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("updateBlob", () => {
    it("updates with etag", async () => {
      mockFetchResponse(fetchMock, 200, makeResponseBody(6), { ETag: '"v6"' });
      const r = await client.updateBlob(TOKEN, "v5", makeRequest());
      expect(r.response.version).toBe(6);
      expect(r.etag).toBe("v6");
    });

    it("throws BlobVersionConflictError on 412", async () => {
      mockFetchResponse(fetchMock, 412, null);
      const e = await client
        .updateBlob(TOKEN, "v5", makeRequest())
        .catch((e: unknown) => e);
      expect(e).toBeInstanceOf(BlobVersionConflictError);
      expect((e as Error).message).toBe(
        "Version conflict - please refetch and retry",
      );
    });

    it("throws BlobNotFoundError on 404", async () => {
      mockFetchResponse(fetchMock, 404, null);
      await expect(
        client.updateBlob(TOKEN, "v5", makeRequest()),
      ).rejects.toThrow(BlobNotFoundError);
    });

    it("throws if etag empty", async () => {
      await expect(client.updateBlob(TOKEN, "", makeRequest())).rejects.toThrow(
        "etag is required for updates",
      );
    });
  });

  describe("deleteBlob", () => {
    it("succeeds on 204", async () => {
      mockFetchResponse(fetchMock, 204, null);
      await expect(
        client.deleteBlob(TOKEN, "aabb01aabb01", "YXNzZXJ0aW9u"),
      ).resolves.toBeUndefined();
    });
  });

  describe("getBlobHistory", () => {
    it("returns entries", async () => {
      mockFetchResponse(fetchMock, 200, {
        history: [
          { version: 5, createdAt: "2024-01-15T12:00:00Z" },
          { version: 4, createdAt: "2024-01-14T18:30:00Z" },
          { version: 3, createdAt: "2024-01-13T09:15:00Z" },
        ],
      });
      const r = await client.getBlobHistory(TOKEN);
      expect(r.history).toHaveLength(3);
      expect(r.history[0].version).toBe(5);
      expect(r.history[0].createdAt).toBeInstanceOf(Date);
      expect(r.history[2].version).toBe(3);
    });

    it.each([
      ["empty", { history: [] }],
      ["missing", {}],
    ])("handles %s history", async (_l, body) => {
      mockFetchResponse(fetchMock, 200, body);
      expect((await client.getBlobHistory(TOKEN)).history).toHaveLength(0);
    });

    it("passes limit", async () => {
      mockFetchResponse(fetchMock, 200, {
        history: [{ version: 5, createdAt: "2024-01-15T12:00:00Z" }],
      });
      const r = await client.getBlobHistory(TOKEN, 1);
      expect(r.history).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("getBlobHistoryVersion", () => {
    it("returns version", async () => {
      mockFetchResponse(fetchMock, 200, {
        ...makeResponseBody(3),
        encryptedBlob: base64Encode(new Uint8Array([10, 20, 30])),
        createdAt: "2024-01-13T09:15:00Z",
      });
      const r = await client.getBlobHistoryVersion(TOKEN, 3);
      expect(r.version).toBe(3);
      expect(r.encryptedBlob).toBeInstanceOf(Uint8Array);
      expect(r.blobNonce).toBeInstanceOf(Uint8Array);
      expect(r.wrappedKeys).toHaveLength(1);
      expect(r.createdAt).toBeInstanceOf(Date);
      expect(r.createdAt.toISOString()).toBe("2024-01-13T09:15:00.000Z");
    });

    it("throws BlobNotFoundError on 404", async () => {
      mockFetchResponse(fetchMock, 404, null);
      await expect(client.getBlobHistoryVersion(TOKEN, 99)).rejects.toThrow(
        BlobNotFoundError,
      );
    });
  });

  describe("restoreFromHistory", () => {
    it("restores with etag", async () => {
      mockFetchResponse(fetchMock, 200, makeResponseBody(7), { ETag: '"v7"' });
      const r = await client.restoreFromHistory(
        TOKEN,
        3,
        "aabb01aabb01",
        "YXNzZXJ0aW9u",
      );
      expect(r.response.version).toBe(7);
      expect(r.etag).toBe("v7");
    });

    it("throws BlobNotFoundError on 404", async () => {
      mockFetchResponse(fetchMock, 404, null);
      await expect(
        client.restoreFromHistory(TOKEN, 99, "aabb01aabb01", "YXNzZXJ0aW9u"),
      ).rejects.toThrow(BlobNotFoundError);
    });
  });

  describe("configuration", () => {
    it("strips trailing slash", async () => {
      const c = new BlobClient({
        baseUrl: "http://localhost:8081/",
        orgId: "org-1",
      });
      mockFetchResponse(fetchMock, 200, makeResponseBody(), { ETag: '"v1"' });
      expect((await c.getBlob(TOKEN)).etag).toBe("v1");
    });

    it.each([
      ["default", undefined],
      ["custom", 5000],
    ])("supports %s timeout", async (_l, timeout) => {
      const c = new BlobClient({
        baseUrl: BASE,
        orgId: ORG,
        ...(timeout ? { timeout } : {}),
      });
      mockFetchResponse(fetchMock, 200, makeResponseBody(), { ETag: '"v1"' });
      await c.getBlob(TOKEN);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("encryptKeyMetadata", () => {
    it("encrypts for single device", async () => {
      const d = await deviceInfo("aabb01");
      const r = await encryptKeyMetadata(makeMetadata(), [d.info]);
      expect(r.encryptedBlob).toBeInstanceOf(Uint8Array);
      expect(r.encryptedBlob.length).toBeGreaterThan(0);
      expect(r.blobNonce).toBeInstanceOf(Uint8Array);
      expect(r.blobNonce.length).toBe(12);
      expect(r.wrappedKeys).toHaveLength(1);
      expect(r.wrappedKeys[0].encryptionPublicKeyHex).toBe("aabb01");
      expect(r.wrappedKeys[0].ephemeralPublic).toBeInstanceOf(Uint8Array);
      expect(r.wrappedKeys[0].ephemeralPublic.length).toBe(PUBLIC_KEY_SIZE);
      expect(r.wrappedKeys[0].wrappedKey).toBeInstanceOf(Uint8Array);
      expect(r.wrappedKeys[0].wrappedKeyNonce).toBeInstanceOf(Uint8Array);
    });

    it("encrypts for multiple devices", async () => {
      const [d1, d2] = await Promise.all([
        deviceInfo("aabb01"),
        deviceInfo("ccdd02"),
      ]);
      const r = await encryptKeyMetadata(makeMetadata(), [d1.info, d2.info]);
      expect(r.wrappedKeys).toHaveLength(2);
      expect(r.wrappedKeys[0].encryptionPublicKeyHex).toBe("aabb01");
      expect(r.wrappedKeys[1].encryptionPublicKeyHex).toBe("ccdd02");
    });

    it("throws CryptoError for empty devices", async () => {
      await expect(encryptKeyMetadata(makeMetadata(), [])).rejects.toThrow(
        CryptoError,
      );
      await expect(encryptKeyMetadata(makeMetadata(), [])).rejects.toThrow(
        "No devices to encrypt for",
      );
    });

    it("skips invalid key sizes", async () => {
      const valid = await deviceInfo("aabb01");
      const devices: DeviceEncryptionInfo[] = [
        { encryptionPublicKeyHex: "eeff03", publicKey: new Uint8Array(32) },
        valid.info,
      ];
      const r = await encryptKeyMetadata(makeMetadata(), devices);
      expect(r.wrappedKeys).toHaveLength(1);
      expect(r.wrappedKeys[0].encryptionPublicKeyHex).toBe("aabb01");
    });

    it("throws if all keys invalid", async () => {
      const devices: DeviceEncryptionInfo[] = [
        { encryptionPublicKeyHex: "bad100", publicKey: new Uint8Array(32) },
        { encryptionPublicKeyHex: "bad200", publicKey: new Uint8Array(10) },
      ];
      await expect(encryptKeyMetadata(makeMetadata(), devices)).rejects.toThrow(
        "No devices with valid encryption keys found",
      );
    });

    it("produces different ciphertexts (random nonces)", async () => {
      const d = await deviceInfo("aabb01");
      const r1 = await encryptKeyMetadata(makeMetadata(), [d.info]);
      const r2 = await encryptKeyMetadata(makeMetadata(), [d.info]);
      expect(r1.blobNonce).not.toEqual(r2.blobNonce);
      expect(r1.encryptedBlob).not.toEqual(r2.encryptedBlob);
    });
  });

  describe("decryptKeyMetadata", () => {
    it("decrypts for this device", async () => {
      const d = await deviceInfo("aabb01");
      const resp = await encryptAndWrap(makeMetadata(), [d.info]);
      const dec = await decryptKeyMetadata(resp, "aabb01", d.privateKey);
      expect(dec.keys).toHaveLength(1);
      expect(dec.keys[0].publicKeyHex).toBe("aabbcc112233");
      expect(dec.keys[0].purpose).toBe("ssh");
      expect(dec.keys[0].label).toBe("My SSH Key");
      expect(dec.keys[0].storageType).toBe("secure_enclave");
      expect(dec.keys[0].deviceName).toBe("iPhone 15 Pro");
      expect(dec.updatedAt).toBeInstanceOf(Date);
    });

    it("decrypts correct device among multiple", async () => {
      const [d1, d2] = await Promise.all([
        deviceInfo("aabb01"),
        deviceInfo("ccdd02"),
      ]);
      const resp = await encryptAndWrap(makeMetadata(), [d1.info, d2.info]);
      const dec = await decryptKeyMetadata(resp, "ccdd02", d2.privateKey);
      expect(dec.keys).toHaveLength(1);
      expect(dec.keys[0].publicKeyHex).toBe("aabbcc112233");
    });

    it("throws NoWrappedKeyError for unknown key", async () => {
      const d = await deviceInfo("aabb01");
      const resp = await encryptAndWrap(makeMetadata(), [d.info]);
      const e = await decryptKeyMetadata(resp, "ffee99", d.privateKey).catch(
        (e: unknown) => e,
      );
      expect(e).toBeInstanceOf(NoWrappedKeyError);
      expect((e as Error).message).toBe("No wrapped key found for this device");
    });

    it("throws NoWrappedKeyError for empty wrappedKeys", async () => {
      const d = await deviceInfo("aabb01");
      const resp: BlobResponse = {
        encryptedBlob: new Uint8Array([1, 2, 3]),
        blobNonce: new Uint8Array(12),
        wrappedKeys: [],
        version: 1,
        updatedAt: new Date(),
      };
      await expect(
        decryptKeyMetadata(resp, "aabb01", d.privateKey),
      ).rejects.toThrow(NoWrappedKeyError);
    });

    it("handles empty keys array", async () => {
      const meta: KeyMetadataBlob = {
        keys: [],
        updatedAt: new Date("2024-01-15T12:00:00Z"),
      };
      const d = await deviceInfo("aabb01");
      const resp = await encryptAndWrap(meta, [d.info]);
      expect(
        (await decryptKeyMetadata(resp, "aabb01", d.privateKey)).keys,
      ).toHaveLength(0);
    });

    it("handles multiple keys", async () => {
      const meta: KeyMetadataBlob = {
        keys: [
          {
            publicKeyHex: "aabb01",
            purpose: "ssh",
            label: "SSH Key",
            storageType: "secure_enclave",
            deviceName: "iPhone",
            createdAt: "2024-01-01T00:00:00Z",
          },
          {
            publicKeyHex: "ccdd02",
            purpose: "gpg",
            label: "GPG Key",
            storageType: "software",
            deviceName: "MacBook",
            createdAt: "2024-01-02T00:00:00Z",
            orgId: "org-123",
          },
          {
            publicKeyHex: "eeff03",
            purpose: "age",
            label: "Age Key",
            storageType: "secure_enclave",
            deviceName: "iPhone",
            createdAt: "2024-01-03T00:00:00Z",
          },
        ],
        updatedAt: new Date("2024-01-15T12:00:00Z"),
      };
      const d = await deviceInfo("aabb01");
      const resp = await encryptAndWrap(meta, [d.info]);
      const dec = await decryptKeyMetadata(resp, "aabb01", d.privateKey);
      expect(dec.keys).toHaveLength(3);
      expect(dec.keys[0].purpose).toBe("ssh");
      expect(dec.keys[1].purpose).toBe("gpg");
      expect(dec.keys[1].orgId).toBe("org-123");
      expect(dec.keys[2].purpose).toBe("age");
    });
  });

  describe("decryptHistoryVersion", () => {
    it("decrypts history entry", async () => {
      const d = await deviceInfo("aabb01");
      const enc = await encryptKeyMetadata(makeMetadata(), [d.info]);
      const hist: HistoryDetailResponse = {
        ...enc,
        version: 3,
        createdAt: new Date("2024-01-13T09:15:00Z"),
      };
      const dec = await decryptHistoryVersion(hist, "aabb01", d.privateKey);
      expect(dec.keys).toHaveLength(1);
      expect(dec.keys[0].publicKeyHex).toBe("aabbcc112233");
      expect(dec.keys[0].purpose).toBe("ssh");
      expect(dec.updatedAt).toBeInstanceOf(Date);
    });

    it("throws NoWrappedKeyError for missing device", async () => {
      const [d, other] = await Promise.all([
        deviceInfo("aabb01"),
        deviceInfo("ffee99"),
      ]);
      const enc = await encryptKeyMetadata(makeMetadata(), [d.info]);
      const hist: HistoryDetailResponse = {
        ...enc,
        version: 3,
        createdAt: new Date("2024-01-13T09:15:00Z"),
      };
      await expect(
        decryptHistoryVersion(hist, "ffee99", other.privateKey),
      ).rejects.toThrow(NoWrappedKeyError);
    });
  });

  describe.each([
    ["BlobNotFoundError", BlobNotFoundError, NetworkError, "Blob not found"],
    [
      "BlobVersionConflictError",
      BlobVersionConflictError,
      NetworkError,
      "Version conflict - please refetch and retry",
    ],
    [
      "NoWrappedKeyError",
      NoWrappedKeyError,
      CryptoError,
      "No wrapped key found for this device",
    ],
  ] as const)("Error class: %s", (name, Cls, Parent, msg) => {
    it("instance chain", () => {
      const e = new Cls();
      expect(e).toBeInstanceOf(Cls);
      expect(e).toBeInstanceOf(Parent);
      expect(e).toBeInstanceOf(Error);
    });
    it("name and message", () => {
      const e = new Cls();
      expect(e.name).toBe(name);
      expect(e.message).toBe(msg);
    });
  });

  describe("roundtrip", () => {
    it("roundtrips key metadata", async () => {
      const meta: KeyMetadataBlob = {
        keys: [
          {
            publicKeyHex: "aabbccddeeff",
            purpose: "gpg",
            label: "GPG Signing Key",
            storageType: "software",
            deviceName: "Test Device",
            publicKey: "mQENBGR...",
            createdAt: "2024-06-15T10:30:00Z",
            orgId: "org-456",
          },
        ],
        updatedAt: new Date("2024-06-15T10:30:00Z"),
      };
      const d = await deviceInfo("aabb01");
      const resp = await encryptAndWrap(
        meta,
        [d.info],
        1,
        "2024-06-15T10:30:00Z",
      );
      const dec = await decryptKeyMetadata(resp, "aabb01", d.privateKey);
      expect(dec.keys).toHaveLength(1);
      expect(dec.keys[0].publicKeyHex).toBe("aabbccddeeff");
      expect(dec.keys[0].purpose).toBe("gpg");
      expect(dec.keys[0].label).toBe("GPG Signing Key");
      expect(dec.keys[0].storageType).toBe("software");
      expect(dec.keys[0].deviceName).toBe("Test Device");
      expect(dec.keys[0].publicKey).toBe("mQENBGR...");
      expect(dec.keys[0].orgId).toBe("org-456");
      expect(dec.keys[0].createdAt).toBe("2024-06-15T10:30:00Z");
      expect(dec.updatedAt.toISOString()).toBe("2024-06-15T10:30:00.000Z");
    });

    it("roundtrips with multiple devices", async () => {
      const [d1, d2, d3] = await Promise.all([
        deviceInfo("aabb01"),
        deviceInfo("ccdd02"),
        deviceInfo("eeff03"),
      ]);
      const resp = await encryptAndWrap(makeMetadata(), [
        d1.info,
        d2.info,
        d3.info,
      ]);
      for (const [hex, d] of [
        ["aabb01", d1],
        ["ccdd02", d2],
        ["eeff03", d3],
      ] as const) {
        const dec = await decryptKeyMetadata(resp, hex, d.privateKey);
        expect(dec.keys).toHaveLength(1);
        expect(dec.keys[0].publicKeyHex).toBe("aabbcc112233");
      }
    });
  });
});
