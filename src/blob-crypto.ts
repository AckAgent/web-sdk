/**
 * Blob encryption/decryption helpers
 */

import { CryptoError } from "./errors.js";
import {
  generateKeyPair,
  deriveWrappingKey,
  encrypt,
  decrypt,
  generateRandomBytes,
  KEY_SIZE,
  PUBLIC_KEY_SIZE,
} from "./crypto.js";
import type {
  BlobWrappedKey,
  BlobResponse,
  BlobRequest,
  HistoryDetailResponse,
  DeviceEncryptionInfo,
  KeyMetadataBlob,
} from "./blob-types.js";
import { NoWrappedKeyError } from "./blob-types.js";

// ============================================================================
// Encryption/Decryption Helpers
// ============================================================================

/**
 * Encrypt key metadata for multiple devices
 *
 * Algorithm:
 * 1. Generate a random symmetric key (32 bytes)
 * 2. Encrypt the metadata JSON with the symmetric key (ChaCha20-Poly1305)
 * 3. For each device:
 *    - Generate ephemeral P-256 ECDH key pair
 *    - Derive wrapping key: HKDF(ECDH(ephemeral, device_pub), empty_salt)
 *    - Wrap symmetric key with ChaCha20-Poly1305
 * 4. Return encrypted payload + wrapped keys
 */
export async function encryptKeyMetadata(
  metadata: KeyMetadataBlob,
  devices: DeviceEncryptionInfo[],
): Promise<BlobRequest> {
  if (devices.length === 0) {
    throw new CryptoError("No devices to encrypt for");
  }

  // Serialize metadata to JSON
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      keys: metadata.keys,
      updatedAt: metadata.updatedAt.toISOString(),
    }),
  );

  // Generate random symmetric key (32 bytes)
  const symmetricKey = generateRandomBytes(KEY_SIZE);

  // Encrypt payload with symmetric key
  const { ciphertext: encryptedBlob, nonce: blobNonce } = encrypt(
    symmetricKey,
    plaintext,
  );

  // Wrap the symmetric key for each device
  const wrappedKeys: BlobWrappedKey[] = [];
  const emptySalt = new Uint8Array(0); // No request ID for blob wrapping

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
      emptySalt,
    );

    // Wrap the symmetric key
    const { ciphertext: wrappedSymKey, nonce: wrappedKeyNonce } = encrypt(
      wrappingKey,
      symmetricKey,
    );

    wrappedKeys.push({
      encryptionPublicKeyHex: device.encryptionPublicKeyHex,
      ephemeralPublic: ephemeralKP.publicKey,
      wrappedKey: wrappedSymKey,
      wrappedKeyNonce: wrappedKeyNonce,
    });
  }

  if (wrappedKeys.length === 0) {
    throw new CryptoError("No devices with valid encryption keys found");
  }

  return {
    encryptedBlob: encryptedBlob,
    blobNonce: blobNonce,
    wrappedKeys: wrappedKeys,
  };
}

/**
 * Decrypt key metadata using this device's private key
 *
 * @param blobResponse - The encrypted blob response from the server
 * @param encryptionPublicKeyHex - Lowercase hex-encoded P-256 ECDH encryption public key of this device
 * @param devicePrivateKey - The device's private key for ECDH key derivation
 */
export async function decryptKeyMetadata(
  blobResponse: BlobResponse,
  encryptionPublicKeyHex: string,
  devicePrivateKey: CryptoKey,
): Promise<KeyMetadataBlob> {
  // Find our device's wrapped key
  const ourWrappedKey = blobResponse.wrappedKeys.find(
    (wk) => wk.encryptionPublicKeyHex === encryptionPublicKeyHex,
  );

  if (!ourWrappedKey) {
    throw new NoWrappedKeyError();
  }

  const emptySalt = new Uint8Array(0); // No request ID for blob wrapping

  // Derive wrapping key
  const wrappingKey = await deriveWrappingKey(
    devicePrivateKey,
    ourWrappedKey.ephemeralPublic,
    emptySalt,
  );

  // Unwrap symmetric key
  const symmetricKey = decrypt(
    wrappingKey,
    ourWrappedKey.wrappedKeyNonce,
    ourWrappedKey.wrappedKey,
  );

  // Decrypt blob
  const plaintext = decrypt(
    symmetricKey,
    blobResponse.blobNonce,
    blobResponse.encryptedBlob,
  );

  // Parse JSON
  const jsonStr = new TextDecoder().decode(plaintext);
  const data = JSON.parse(jsonStr);

  return {
    keys: data.keys || [],
    updatedAt: new Date(data.updatedAt ?? data.updated_at),
  };
}

/**
 * Decrypt from history detail response
 *
 * @param historyResponse - The history version response from the server
 * @param encryptionPublicKeyHex - Lowercase hex-encoded P-256 ECDH encryption public key of this device
 * @param devicePrivateKey - The device's private key for ECDH key derivation
 */
export async function decryptHistoryVersion(
  historyResponse: HistoryDetailResponse,
  encryptionPublicKeyHex: string,
  devicePrivateKey: CryptoKey,
): Promise<KeyMetadataBlob> {
  // Convert to BlobResponse format for decryption
  const blobResponse: BlobResponse = {
    encryptedBlob: historyResponse.encryptedBlob,
    blobNonce: historyResponse.blobNonce,
    wrappedKeys: historyResponse.wrappedKeys,
    version: historyResponse.version,
    updatedAt: historyResponse.createdAt,
  };

  return decryptKeyMetadata(
    blobResponse,
    encryptionPublicKeyHex,
    devicePrivateKey,
  );
}
