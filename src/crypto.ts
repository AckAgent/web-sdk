/**
 * Cryptographic operations for E2E encryption
 * Uses Web Crypto P-256 ECDH key exchange, HKDF-SHA256 key derivation, and ChaCha20-Poly1305 encryption
 *
 * Browser requirements: Modern browsers with Web Crypto ECDH P-256 support
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { CryptoError } from "./errors.js";
import { uuidToBytes } from "./encoding.js";

/** Size of symmetric keys in bytes (ChaCha20-Poly1305) */
export const KEY_SIZE = 32;

/** Size of P-256 public keys in bytes (compressed SEC1: 0x02/0x03 || X) */
export const PUBLIC_KEY_SIZE = 33;

/** Size of P-256 uncompressed public keys in bytes (0x04 || X || Y) */
export const UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;

/** Size of ChaCha20-Poly1305 nonce in bytes */
export const NONCE_SIZE = 12;

/** HKDF info strings matching the Go/Swift implementations */
const HKDF_REQUEST_INFO = "signer-request-v1";
const HKDF_RESPONSE_INFO = "signer-response-v1";
const HKDF_WRAPPING_INFO = "signer-wrap-v1";

/** P-256 ECDH key pair with non-extractable private key */
export interface KeyPair {
  privateKey: CryptoKey; // Non-extractable
  publicKey: Uint8Array; // Raw bytes for transmission (33 bytes compressed SEC1)
}

/**
 * Check if the browser supports Web Crypto P-256 ECDH.
 * @returns true if P-256 ECDH is supported, false otherwise
 */
export async function checkWebCryptoSupport(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Error thrown when the browser doesn't support required Web Crypto features
 */
export class UnsupportedBrowserError extends Error {
  constructor() {
    super(
      "This browser does not support Web Crypto P-256 ECDH. " +
        "Please use a modern browser with Web Crypto API support.",
    );
    this.name = "UnsupportedBrowserError";
  }
}

// P-256 curve parameters for point compression/decompression
/** P-256 prime field modulus */
const P256_P =
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
/** P-256 curve parameter b (y^2 = x^3 - 3x + b mod p) */
const P256_B =
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

/**
 * Modular exponentiation: base^exp mod m using BigInt.
 * Uses square-and-multiply for efficiency.
 */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % m;
    }
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/**
 * Convert a 32-byte Uint8Array to a BigInt (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert a BigInt to a 32-byte Uint8Array (big-endian, zero-padded).
 */
function bigIntToBytes(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Compress an uncompressed P-256 public key (65 bytes) to compressed SEC1 format (33 bytes).
 *
 * Input format:  0x04 || X (32 bytes) || Y (32 bytes)
 * Output format: prefix || X (32 bytes), where prefix is 0x02 (Y even) or 0x03 (Y odd)
 *
 * @param uncompressed - 65-byte uncompressed P-256 public key
 * @returns 33-byte compressed P-256 public key
 */
export function compressPublicKey(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== UNCOMPRESSED_PUBLIC_KEY_SIZE) {
    throw new CryptoError(
      `Expected ${UNCOMPRESSED_PUBLIC_KEY_SIZE}-byte uncompressed key, got ${uncompressed.length}`,
    );
  }
  if (uncompressed[0] !== 0x04) {
    throw new CryptoError("Invalid uncompressed key prefix (expected 0x04)");
  }

  const compressed = new Uint8Array(PUBLIC_KEY_SIZE);
  // Y parity: check least significant bit of the last byte of Y
  compressed[0] = uncompressed[64] & 1 ? 0x03 : 0x02;
  compressed.set(uncompressed.slice(1, 33), 1);
  return compressed;
}

/**
 * Decompress a compressed P-256 public key (33 bytes) to uncompressed format (65 bytes).
 *
 * Uses the P-256 curve equation y^2 = x^3 - 3x + b (mod p) and the fact that
 * p ≡ 3 (mod 4), so the modular square root is y = rhs^((p+1)/4) mod p.
 *
 * Security note: The BigInt arithmetic here is variable-time, which is acceptable
 * because this function only operates on public keys (not secret material). Public
 * keys are transmitted in the clear and are not sensitive to timing side-channels.
 *
 * @param compressed - 33-byte compressed P-256 public key (0x02 or 0x03 prefix)
 * @returns 65-byte uncompressed P-256 public key
 */
export function decompressPublicKey(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== PUBLIC_KEY_SIZE) {
    throw new CryptoError(
      `Expected ${PUBLIC_KEY_SIZE}-byte compressed key, got ${compressed.length}`,
    );
  }

  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new CryptoError(
      "Invalid compressed key prefix (expected 0x02 or 0x03)",
    );
  }

  const x = bytesToBigInt(compressed.slice(1, 33));

  // Compute right-hand side: x^3 - 3x + b mod p
  const x3 = modPow(x, 3n, P256_P);
  const threeX = (3n * x) % P256_P;
  const rhs = (((x3 - threeX + P256_B) % P256_P) + P256_P) % P256_P;

  // Since p ≡ 3 (mod 4), sqrt is rhs^((p+1)/4) mod p
  const y = modPow(rhs, (P256_P + 1n) / 4n, P256_P);

  // Verify y^2 ≡ rhs (mod p) to ensure the point is on the curve
  if ((y * y) % P256_P !== rhs) {
    throw new CryptoError("Point is not on the P-256 curve");
  }

  // Select correct Y based on parity (prefix 0x02 = even, 0x03 = odd)
  const isOdd = (y & 1n) === 1n;
  const wantOdd = prefix === 0x03;
  const finalY = isOdd !== wantOdd ? P256_P - y : y;

  const uncompressed = new Uint8Array(UNCOMPRESSED_PUBLIC_KEY_SIZE);
  uncompressed[0] = 0x04;
  uncompressed.set(bigIntToBytes(x), 1);
  uncompressed.set(bigIntToBytes(finalY), 33);
  return uncompressed;
}

/**
 * Generate a new P-256 ECDH key pair with non-extractable private key.
 * The private key is stored in the Web Crypto subsystem and cannot be read by JavaScript.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  try {
    const keyPair = (await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false, // Non-extractable
      ["deriveBits"],
    )) as CryptoKeyPair;

    // Export public key as raw bytes (65 bytes uncompressed from Web Crypto)
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "raw",
      keyPair.publicKey,
    );
    const uncompressedPublicKey = new Uint8Array(publicKeyBuffer);

    // Compress to 33-byte SEC1 format for transmission
    return {
      privateKey: keyPair.privateKey,
      publicKey: compressPublicKey(uncompressedPublicKey),
    };
  } catch (error) {
    if (error instanceof Error && error.name === "NotSupportedError") {
      throw new UnsupportedBrowserError();
    }
    throw error;
  }
}

/**
 * Compute P-256 ECDH shared secret from our private key and their public key.
 * Accepts compressed (33-byte) public keys and decompresses before ECDH.
 * Returns the raw shared secret bytes (32 bytes) for use in HKDF.
 */
export async function sharedSecret(
  ourPrivateKey: CryptoKey,
  theirPublicKey: Uint8Array,
): Promise<Uint8Array> {
  if (theirPublicKey.length !== PUBLIC_KEY_SIZE) {
    throw new CryptoError("Invalid public key size");
  }

  // Decompress to uncompressed format for Web Crypto importKey
  const uncompressedKey = decompressPublicKey(theirPublicKey);

  // Import their public key (Web Crypto requires uncompressed format)
  const keyBuffer = new ArrayBuffer(uncompressedKey.length);
  new Uint8Array(keyBuffer).set(uncompressedKey);

  const importedPublicKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  // Derive shared bits using P-256 ECDH
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: importedPublicKey },
    ourPrivateKey,
    256, // 32 bytes = 256 bits
  );

  return new Uint8Array(sharedBits);
}

/**
 * Internal helper: derive key from ECDH shared secret with custom info string
 */
async function deriveKeyWithInfo(
  ourPrivateKey: CryptoKey,
  theirPublicKey: Uint8Array,
  requestId: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const secret = await sharedSecret(ourPrivateKey, theirPublicKey);
  const encoder = new TextEncoder();
  return hkdf(sha256, secret, requestId, encoder.encode(info), KEY_SIZE);
}

/**
 * Derive a per-request encryption key for forward secrecy.
 * Requester uses: deriveRequestKey(ephemeralPrivate, signerIdentityPublic, requestId)
 */
export async function deriveRequestKey(
  ourPrivateKey: CryptoKey,
  theirPublicKey: Uint8Array,
  requestId: Uint8Array,
): Promise<Uint8Array> {
  return deriveKeyWithInfo(
    ourPrivateKey,
    theirPublicKey,
    requestId,
    HKDF_REQUEST_INFO,
  );
}

/**
 * Derive a per-response decryption key for forward secrecy.
 * Requester uses: deriveResponseKey(ephemeralPrivate, signerEphemeralPublic, requestId)
 */
export async function deriveResponseKey(
  ourPrivateKey: CryptoKey,
  theirPublicKey: Uint8Array,
  requestId: Uint8Array,
): Promise<Uint8Array> {
  return deriveKeyWithInfo(
    ourPrivateKey,
    theirPublicKey,
    requestId,
    HKDF_RESPONSE_INFO,
  );
}

/**
 * Encrypt plaintext using ChaCha20-Poly1305
 * @param key - 32-byte encryption key
 * @param plaintext - Data to encrypt
 * @param additionalData - Optional additional authenticated data (AAD)
 * @returns Object with `ciphertext` and `nonce` fields
 */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  if (key.length !== KEY_SIZE) {
    throw new CryptoError("Invalid key size");
  }

  const nonce = randomBytes(NONCE_SIZE);
  const cipher = chacha20poly1305(key, nonce, additionalData);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

/**
 * Decrypt ciphertext using ChaCha20-Poly1305
 * @param key - 32-byte decryption key
 * @param nonce - 12-byte nonce
 * @param ciphertext - Data to decrypt (includes authentication tag)
 * @param additionalData - Optional additional authenticated data (AAD)
 * @returns Decrypted plaintext
 */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  additionalData?: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_SIZE) {
    throw new CryptoError("Invalid key size");
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new CryptoError("Invalid nonce size");
  }

  try {
    const cipher = chacha20poly1305(key, nonce, additionalData);
    return cipher.decrypt(ciphertext);
  } catch {
    throw new CryptoError(
      "Decryption failed - message may be corrupted or tampered",
    );
  }
}

/**
 * Generate random bytes
 */
export function generateRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Convert a request ID string (UUID) to bytes for HKDF salt
 */
export function requestIdToBytes(requestId: string): Uint8Array {
  return uuidToBytes(requestId);
}

// Multi-Device Encryption (Per-Device Key Wrapping)

/** Device key for multi-device encryption */
export interface DeviceKey {
  deviceId: string;
  publicKey: Uint8Array; // P-256 33 bytes (compressed SEC1)
}

/** Wrapped symmetric key for a specific device */
export interface WrappedKey {
  device_id: string;
  wrapped_key: Uint8Array;
  wrapped_key_nonce: Uint8Array;
  ephemeral_public: Uint8Array;
}

/** Multi-device encrypted payload */
export interface MultiDevicePayload {
  encrypted_payload: Uint8Array;
  payload_nonce: Uint8Array;
  wrapped_keys: WrappedKey[];
}

/**
 * Derive a key wrapping key from an ECDH shared secret
 */
export async function deriveWrappingKey(
  ourPrivateKey: CryptoKey,
  theirPublicKey: Uint8Array,
  requestId: Uint8Array,
): Promise<Uint8Array> {
  return deriveKeyWithInfo(
    ourPrivateKey,
    theirPublicKey,
    requestId,
    HKDF_WRAPPING_INFO,
  );
}

/**
 * Encrypt a payload for multiple devices using per-device key wrapping.
 *
 * Algorithm:
 * 1. Generate a random symmetric key (32 bytes)
 * 2. Encrypt the payload with the symmetric key (ChaCha20-Poly1305)
 * 3. For each device:
 *    - Generate ephemeral P-256 ECDH key pair
 *    - Derive wrapping key: HKDF(ECDH(ephemeral, device_pub), requestId)
 *    - Wrap symmetric key with ChaCha20-Poly1305
 * 4. Return encrypted payload + wrapped keys
 */
export async function encryptForMultipleDevices(
  payload: Uint8Array,
  devices: DeviceKey[],
  requestId: Uint8Array,
): Promise<MultiDevicePayload> {
  if (devices.length === 0) {
    throw new CryptoError("No devices to encrypt for");
  }

  // Generate random symmetric key (32 bytes)
  const symmetricKey = randomBytes(KEY_SIZE);

  // Encrypt payload with symmetric key (request ID as AAD binds ciphertext to this request)
  const { ciphertext: encryptedPayload, nonce: payloadNonce } = encrypt(
    symmetricKey,
    payload,
    requestId,
  );

  // Wrap the symmetric key for each device
  const wrappedKeys: WrappedKey[] = [];
  for (const device of devices) {
    if (device.publicKey.length !== PUBLIC_KEY_SIZE) {
      continue; // Skip invalid keys
    }

    // Generate ephemeral key pair for this device
    const ephemeralKP = await generateKeyPair();

    // Derive wrapping key
    const wrappingKey = await deriveWrappingKey(
      ephemeralKP.privateKey,
      device.publicKey,
      requestId,
    );

    // Wrap the symmetric key (request ID as AAD binds wrapped key to this request)
    const { ciphertext: wrappedSymKey, nonce: wrappedKeyNonce } = encrypt(
      wrappingKey,
      symmetricKey,
      requestId,
    );

    wrappedKeys.push({
      device_id: device.deviceId,
      wrapped_key: wrappedSymKey,
      wrapped_key_nonce: wrappedKeyNonce,
      ephemeral_public: ephemeralKP.publicKey,
    });
  }

  return {
    encrypted_payload: encryptedPayload,
    payload_nonce: payloadNonce,
    wrapped_keys: wrappedKeys,
  };
}

/**
 * Decrypt a multi-device payload using the wrapped key for our device
 */
export async function decryptFromMultiDevice(
  payload: MultiDevicePayload,
  deviceId: string,
  devicePrivateKey: CryptoKey,
  requestId: Uint8Array,
): Promise<Uint8Array> {
  // Find our device's wrapped key
  const ourWrappedKey = payload.wrapped_keys.find(
    (wk) => wk.device_id === deviceId,
  );
  if (!ourWrappedKey) {
    throw new CryptoError("No wrapped key found for this device");
  }

  // Derive wrapping key
  const wrappingKey = await deriveWrappingKey(
    devicePrivateKey,
    ourWrappedKey.ephemeral_public,
    requestId,
  );

  // Unwrap symmetric key (request ID as AAD verifies key belongs to this request)
  const symmetricKey = decrypt(
    wrappingKey,
    ourWrappedKey.wrapped_key_nonce,
    ourWrappedKey.wrapped_key,
    requestId,
  );

  // Decrypt payload (request ID as AAD verifies payload belongs to this request)
  return decrypt(
    symmetricKey,
    payload.payload_nonce,
    payload.encrypted_payload,
    requestId,
  );
}
