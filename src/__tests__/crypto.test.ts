import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateKeyPair,
  sharedSecret,
  deriveRequestKey,
  deriveResponseKey,
  encrypt,
  decrypt,
  generateRandomBytes,
  requestIdToBytes,
  checkWebCryptoSupport,
  compressPublicKey,
  decompressPublicKey,
  encryptForMultipleDevices,
  decryptFromMultiDevice,
  deriveWrappingKey,
  KEY_SIZE,
  PUBLIC_KEY_SIZE,
  UNCOMPRESSED_PUBLIC_KEY_SIZE,
  NONCE_SIZE,
  type DeviceKey,
} from "../crypto.js";
import { CryptoError } from "../errors.js";

type EncryptionVectors = {
  request_id_bytes_hex: string;
  requester_ephemeral_private_hex: string;
  requester_ephemeral_public_hex: string;
  signer_identity_public_hex: string;
  signer_ephemeral_private_hex: string;
  request_key_hex: string;
  response_key_hex: string;
  plaintext_hex: string;
  nonce_hex: string;
  aad_hex: string;
  ciphertext_hex: string;
};

function loadVectors(): EncryptionVectors {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, "..", "..");
  const data = fs.readFileSync(
    path.join(root, "test-fixtures", "crypto_test_vectors.json"),
    "utf8",
  );
  return (JSON.parse(data) as { encryption_vectors: EncryptionVectors })
    .encryption_vectors;
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

describe("Web Crypto Support", () => {
  it("detects P-256 ECDH support", async () => {
    expect(await checkWebCryptoSupport()).toBe(true);
  });
});

describe("Key Generation", () => {
  it("generates valid key pairs", async () => {
    const keyPair = await generateKeyPair();
    expect(keyPair.privateKey).toBeInstanceOf(CryptoKey);
    expect(keyPair.privateKey.extractable).toBe(false);
    expect(keyPair.privateKey.algorithm.name).toBe("ECDH");
    expect(keyPair.privateKey.usages).toContain("deriveBits");
    expect(keyPair.publicKey.length).toBe(PUBLIC_KEY_SIZE);
    expect(PUBLIC_KEY_SIZE).toBe(33);
    expect([0x02, 0x03]).toContain(keyPair.publicKey[0]);
    expect(keyPair.publicKey.some((b) => b !== 0)).toBe(true);
  });

  it("generates different key pairs each time", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    expect(toHex(kp1.publicKey)).not.toBe(toHex(kp2.publicKey));
  });
});

describe("Public Key Compression", () => {
  it("compress/decompress round-trip produces original key", async () => {
    const kpInternal = (await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const uncompressed = new Uint8Array(
      await crypto.subtle.exportKey("raw", kpInternal.publicKey),
    );
    expect(uncompressed.length).toBe(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    expect(uncompressed[0]).toBe(0x04);

    const compressed = compressPublicKey(uncompressed);
    expect(compressed.length).toBe(PUBLIC_KEY_SIZE);
    expect([0x02, 0x03]).toContain(compressed[0]);
    expect(toHex(compressed.slice(1))).toBe(toHex(uncompressed.slice(1, 33)));

    const decompressed = decompressPublicKey(compressed);
    expect(decompressed.length).toBe(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    expect(toHex(decompressed)).toBe(toHex(uncompressed));
  });

  it("compresses with correct parity prefix", async () => {
    const parities = new Set<number>();
    for (let i = 0; i < 20 && parities.size < 2; i++) {
      const kp = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      )) as CryptoKeyPair;
      const raw = new Uint8Array(
        await crypto.subtle.exportKey("raw", kp.publicKey),
      );
      const compressed = compressPublicKey(raw);
      parities.add(compressed[0]);
      const expectedPrefix = raw[64] & 1 ? 0x03 : 0x02;
      expect(compressed[0]).toBe(expectedPrefix);
    }
    expect(parities.size).toBe(2);
  });

  it.each([
    [
      "compressPublicKey with 33 bytes",
      () => compressPublicKey(new Uint8Array(33)),
    ],
    [
      "compressPublicKey with 64 bytes",
      () => compressPublicKey(new Uint8Array(64)),
    ],
    [
      "compressPublicKey with wrong prefix",
      () => {
        const b = new Uint8Array(65);
        b[0] = 0x02;
        return compressPublicKey(b);
      },
    ],
    [
      "decompressPublicKey with 65 bytes",
      () => decompressPublicKey(new Uint8Array(65)),
    ],
    [
      "decompressPublicKey with 32 bytes",
      () => decompressPublicKey(new Uint8Array(32)),
    ],
    [
      "decompressPublicKey with wrong prefix",
      () => {
        const b = new Uint8Array(33);
        b[0] = 0x04;
        return decompressPublicKey(b);
      },
    ],
  ])("rejects invalid input: %s", (_label, fn) => {
    expect(fn).toThrow(CryptoError);
  });

  it("generateKeyPair returns compressed keys that work with ECDH", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    expect(kp1.publicKey.length).toBe(33);
    expect(kp2.publicKey.length).toBe(33);
    const s1 = await sharedSecret(kp1.privateKey, kp2.publicKey);
    const s2 = await sharedSecret(kp2.privateKey, kp1.publicKey);
    expect(toHex(s1)).toBe(toHex(s2));
  });

  it("decompresses a known test vector", () => {
    const compressedG = new Uint8Array([
      0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
      0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
      0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    ]);
    const decompressed = decompressPublicKey(compressedG);
    expect(decompressed[0]).toBe(0x04);
    expect(toHex(decompressed.slice(1, 33))).toBe(
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    );
    expect(toHex(decompressed.slice(33))).toBe(
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
  });
});

describe("Shared Secret", () => {
  it("computes symmetric shared secret", async () => {
    const web = await generateKeyPair();
    const ios = await generateKeyPair();
    const webShared = await sharedSecret(web.privateKey, ios.publicKey);
    const iosShared = await sharedSecret(ios.privateKey, web.publicKey);
    expect(webShared.length).toBe(KEY_SIZE);
    expect(toHex(webShared)).toBe(toHex(iosShared));
  });

  it("rejects invalid public key sizes", async () => {
    const kp = await generateKeyPair();
    await expect(
      sharedSecret(kp.privateKey, new Uint8Array(16).fill(0x42)),
    ).rejects.toThrow(CryptoError);
  });
});

describe("Key Derivation (Forward Secrecy)", () => {
  it.each([
    ["request", deriveRequestKey],
    ["response", deriveResponseKey],
  ] as const)("derives matching %s keys on both sides", async (_label, deriveFn) => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const requestId = generateRandomBytes(16);
    const key1 = await deriveFn(kp1.privateKey, kp2.publicKey, requestId);
    const key2 = await deriveFn(kp2.privateKey, kp1.publicKey, requestId);
    expect(key1.length).toBe(KEY_SIZE);
    expect(toHex(key1)).toBe(toHex(key2));
  });
});

describe("Encryption/Decryption", () => {
  it("encrypts and decrypts round-trip", () => {
    const key = generateRandomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode("Hello, World!");
    const { ciphertext, nonce } = encrypt(key, plaintext);
    expect(ciphertext.length).toBe(plaintext.length + 16);
    expect(nonce.length).toBe(NONCE_SIZE);
    expect(new TextDecoder().decode(decrypt(key, nonce, ciphertext))).toBe(
      "Hello, World!",
    );
  });

  it("encrypts and decrypts with AAD", () => {
    const key = generateRandomBytes(KEY_SIZE);
    const plaintext = new TextEncoder().encode("Secret message");
    const aad = new TextEncoder().encode("request-id-123");
    const { ciphertext, nonce } = encrypt(key, plaintext, aad);
    expect(new TextDecoder().decode(decrypt(key, nonce, ciphertext, aad))).toBe(
      "Secret message",
    );
  });

  it.each([
    [
      "wrong key",
      () => {
        const key1 = generateRandomBytes(KEY_SIZE);
        const { ciphertext, nonce } = encrypt(
          key1,
          new TextEncoder().encode("Secret message"),
        );
        return () => decrypt(generateRandomBytes(KEY_SIZE), nonce, ciphertext);
      },
    ],
    [
      "wrong AAD",
      () => {
        const key = generateRandomBytes(KEY_SIZE);
        const { ciphertext, nonce } = encrypt(
          key,
          new TextEncoder().encode("Secret message"),
          new TextEncoder().encode("aad1"),
        );
        return () =>
          decrypt(key, nonce, ciphertext, new TextEncoder().encode("aad2"));
      },
    ],
    [
      "tampered ciphertext",
      () => {
        const key = generateRandomBytes(KEY_SIZE);
        const { ciphertext, nonce } = encrypt(
          key,
          new TextEncoder().encode("Secret message"),
        );
        const tampered = new Uint8Array(ciphertext);
        tampered[0] ^= 0xff;
        return () => decrypt(key, nonce, tampered);
      },
    ],
  ])("fails to decrypt with %s", (_label, setup) => {
    expect(setup()).toThrow(CryptoError);
  });

  it("encrypts empty data", () => {
    const key = generateRandomBytes(KEY_SIZE);
    const { ciphertext, nonce } = encrypt(key, new Uint8Array(0));
    expect(decrypt(key, nonce, ciphertext).length).toBe(0);
  });
});

describe("End-to-End Flow", () => {
  it("simulates forward secrecy flow", async () => {
    const iosIdentity = await generateKeyPair();
    const webEphemeral = await generateKeyPair();
    const requestId = generateRandomBytes(16);

    const webRequestKey = await deriveRequestKey(
      webEphemeral.privateKey,
      iosIdentity.publicKey,
      requestId,
    );
    const request = new TextEncoder().encode('{"challenge":"abc123"}');
    const { ciphertext: reqCt, nonce: reqNonce } = encrypt(
      webRequestKey,
      request,
    );

    const iosRequestKey = await deriveRequestKey(
      iosIdentity.privateKey,
      webEphemeral.publicKey,
      requestId,
    );
    expect(toHex(webRequestKey)).toBe(toHex(iosRequestKey));
    expect(
      new TextDecoder().decode(decrypt(iosRequestKey, reqNonce, reqCt)),
    ).toBe('{"challenge":"abc123"}');

    const iosEphemeral = await generateKeyPair();
    const iosResponseKey = await deriveResponseKey(
      iosEphemeral.privateKey,
      webEphemeral.publicKey,
      requestId,
    );
    const response = new TextEncoder().encode('{"signature":"sig123"}');
    const { ciphertext: respCt, nonce: respNonce } = encrypt(
      iosResponseKey,
      response,
    );

    const webResponseKey = await deriveResponseKey(
      webEphemeral.privateKey,
      iosEphemeral.publicKey,
      requestId,
    );
    expect(toHex(iosResponseKey)).toBe(toHex(webResponseKey));
    expect(
      new TextDecoder().decode(decrypt(webResponseKey, respNonce, respCt)),
    ).toBe('{"signature":"sig123"}');
  });
});

describe("Utility Functions", () => {
  it.each([16, 32])("generates random bytes of length %d", (len) => {
    expect(generateRandomBytes(len).length).toBe(len);
  });

  it("generates different random bytes each time", () => {
    expect(toHex(generateRandomBytes(32))).not.toBe(
      toHex(generateRandomBytes(32)),
    );
  });

  it("converts request ID to bytes", () => {
    const bytes = requestIdToBytes("550e8400-e29b-41d4-a716-446655440000");
    expect(bytes.length).toBe(16);
    expect(bytes[0]).toBe(0x55);
  });
});

describe("Cross-Language Vectors", () => {
  it.each([
    ["decrypts ciphertext using known key"],
    ["produces matching ciphertext when encrypting with same key and nonce"],
  ])("%s", () => {
    const v = loadVectors();
    const requestKey = fromHex(v.request_key_hex);
    const nonce = fromHex(v.nonce_hex);
    const ciphertext = fromHex(v.ciphertext_hex);
    const aad = fromHex(v.aad_hex);
    const plaintext = decrypt(requestKey, nonce, ciphertext, aad);
    expect(toHex(plaintext)).toBe(v.plaintext_hex);
  });
});

describe("Multi-Device Encryption", () => {
  let deviceKPs: Awaited<ReturnType<typeof generateKeyPair>>[];
  const deviceNames = ["iphone", "ipad", "watch"];

  beforeAll(async () => {
    deviceKPs = await Promise.all(
      Array.from({ length: 4 }, () => generateKeyPair()),
    );
  });

  it("encrypts and decrypts for a single device", async () => {
    const devices: DeviceKey[] = [
      { deviceId: "device-1", publicKey: deviceKPs[0].publicKey },
    ];
    const requestId = generateRandomBytes(16);
    const plaintext = new TextEncoder().encode("Hello, device!");
    const payload = await encryptForMultipleDevices(
      plaintext,
      devices,
      requestId,
    );
    expect(payload.encrypted_payload.length).toBeGreaterThan(0);
    expect(payload.payload_nonce.length).toBe(NONCE_SIZE);
    expect(payload.wrapped_keys.length).toBe(1);
    expect(payload.wrapped_keys[0].device_id).toBe("device-1");
    expect(payload.wrapped_keys[0].ephemeral_public.length).toBe(
      PUBLIC_KEY_SIZE,
    );
    const decrypted = await decryptFromMultiDevice(
      payload,
      "device-1",
      deviceKPs[0].privateKey,
      requestId,
    );
    expect(new TextDecoder().decode(decrypted)).toBe("Hello, device!");
  });

  it("encrypts and decrypts for multiple devices", async () => {
    const devices: DeviceKey[] = deviceNames.map((name, i) => ({
      deviceId: name,
      publicKey: deviceKPs[i].publicKey,
    }));
    const requestId = generateRandomBytes(16);
    const plaintext = new TextEncoder().encode("Multi-device message");
    const payload = await encryptForMultipleDevices(
      plaintext,
      devices,
      requestId,
    );
    expect(payload.wrapped_keys.length).toBe(3);

    for (let i = 0; i < 3; i++) {
      const decrypted = await decryptFromMultiDevice(
        payload,
        deviceNames[i],
        deviceKPs[i].privateKey,
        requestId,
      );
      expect(new TextDecoder().decode(decrypted)).toBe("Multi-device message");
    }
  });

  it("throws error for empty device list", async () => {
    await expect(
      encryptForMultipleDevices(
        new TextEncoder().encode("Test"),
        [],
        generateRandomBytes(16),
      ),
    ).rejects.toThrow("No devices to encrypt for");
  });

  it("skips devices with invalid key sizes", async () => {
    const devices: DeviceKey[] = [
      { deviceId: "invalid", publicKey: new Uint8Array(16) },
      { deviceId: "valid", publicKey: deviceKPs[0].publicKey },
    ];
    const requestId = generateRandomBytes(16);
    const payload = await encryptForMultipleDevices(
      new TextEncoder().encode("Test"),
      devices,
      requestId,
    );
    expect(payload.wrapped_keys.length).toBe(1);
    expect(payload.wrapped_keys[0].device_id).toBe("valid");
    const decrypted = await decryptFromMultiDevice(
      payload,
      "valid",
      deviceKPs[0].privateKey,
      requestId,
    );
    expect(new TextDecoder().decode(decrypted)).toBe("Test");
  });

  it.each([
    [
      "unknown device",
      async (kps: typeof deviceKPs) => {
        const devices: DeviceKey[] = [
          { deviceId: "device-1", publicKey: kps[0].publicKey },
        ];
        const requestId = generateRandomBytes(16);
        const payload = await encryptForMultipleDevices(
          new TextEncoder().encode("Test"),
          devices,
          requestId,
        );
        return decryptFromMultiDevice(
          payload,
          "unknown-device",
          kps[0].privateKey,
          requestId,
        );
      },
      "No wrapped key found for this device",
    ],
    [
      "wrong private key",
      async (kps: typeof deviceKPs) => {
        const devices: DeviceKey[] = [
          { deviceId: "device-1", publicKey: kps[0].publicKey },
        ];
        const requestId = generateRandomBytes(16);
        const payload = await encryptForMultipleDevices(
          new TextEncoder().encode("Test"),
          devices,
          requestId,
        );
        return decryptFromMultiDevice(
          payload,
          "device-1",
          kps[1].privateKey,
          requestId,
        );
      },
      CryptoError,
    ],
    [
      "wrong request ID",
      async (kps: typeof deviceKPs) => {
        const devices: DeviceKey[] = [
          { deviceId: "device-1", publicKey: kps[0].publicKey },
        ];
        const payload = await encryptForMultipleDevices(
          new TextEncoder().encode("Test"),
          devices,
          generateRandomBytes(16),
        );
        return decryptFromMultiDevice(
          payload,
          "device-1",
          kps[0].privateKey,
          generateRandomBytes(16),
        );
      },
      CryptoError,
    ],
  ])("fails to decrypt with %s", async (_label, setup, expectedError) => {
    await expect(setup(deviceKPs)).rejects.toThrow(expectedError);
  });

  it.each([
    ["empty payload", new Uint8Array(0), 0],
    ["large payload (64KB)", generateRandomBytes(64 * 1024), 64 * 1024],
  ])("encrypts and decrypts %s", async (_label, plaintext, expectedLen) => {
    const devices: DeviceKey[] = [
      { deviceId: "device-1", publicKey: deviceKPs[0].publicKey },
    ];
    const requestId = generateRandomBytes(16);
    const payload = await encryptForMultipleDevices(
      plaintext,
      devices,
      requestId,
    );
    if (expectedLen === 0) expect(payload.encrypted_payload.length).toBe(16);
    const decrypted = await decryptFromMultiDevice(
      payload,
      "device-1",
      deviceKPs[0].privateKey,
      requestId,
    );
    expect(decrypted.length).toBe(expectedLen);
    if (expectedLen > 0) expect(toHex(decrypted)).toBe(toHex(plaintext));
  });

  it("generates unique ephemeral keys per device", async () => {
    const devices: DeviceKey[] = [
      { deviceId: "device-1", publicKey: deviceKPs[0].publicKey },
      { deviceId: "device-2", publicKey: deviceKPs[1].publicKey },
    ];
    const payload = await encryptForMultipleDevices(
      new TextEncoder().encode("Test"),
      devices,
      generateRandomBytes(16),
    );
    const [wk0, wk1] = payload.wrapped_keys;
    expect(toHex(wk0.ephemeral_public)).not.toBe(toHex(wk1.ephemeral_public));
    expect(toHex(wk0.wrapped_key)).not.toBe(toHex(wk1.wrapped_key));
    expect(toHex(wk0.wrapped_key_nonce)).not.toBe(toHex(wk1.wrapped_key_nonce));
  });

  it("derives consistent wrapping keys", async () => {
    const requestId = generateRandomBytes(16);
    const k1 = await deriveWrappingKey(
      deviceKPs[0].privateKey,
      deviceKPs[1].publicKey,
      requestId,
    );
    const k2 = await deriveWrappingKey(
      deviceKPs[1].privateKey,
      deviceKPs[0].publicKey,
      requestId,
    );
    expect(toHex(k1)).toBe(toHex(k2));
  });
});
