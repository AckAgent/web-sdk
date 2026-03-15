/**
 * Blob service response parsing and request serialization helpers.
 *
 * These are standalone functions extracted from BlobClient to keep the
 * client class focused on HTTP communication.
 */

import { NetworkError } from "./errors.js";
import {
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode,
} from "./encoding.js";
import type {
  BlobWrappedKey,
  BlobResponse,
  BlobRequest,
  SerializedBlobRequest,
  HistoryListResponse,
  HistoryDetailResponse,
} from "./blob-types.js";

/**
 * Strip surrounding quotes from an ETag header value.
 */
export function parseETag(etag: string | null): string {
  if (!etag) return "";
  if (etag.length >= 2 && etag[0] === '"' && etag[etag.length - 1] === '"') {
    return etag.slice(1, -1);
  }
  return etag;
}

/**
 * Parse a blob response payload and validate required fields at runtime.
 */
export function parseBlobResponse(data: unknown): BlobResponse {
  const blobData = requireObject(data, "blob response");
  const encryptedBlob = requireString(
    blobData,
    "encryptedBlob",
    "blob response",
  );
  const blobNonce = requireString(blobData, "blobNonce", "blob response");
  const version = requireNumber(blobData, "version", "blob response");
  const updatedAt = requireDate(blobData, "updatedAt", "blob response");

  return {
    encryptedBlob: base64Decode(encryptedBlob),
    blobNonce: base64Decode(blobNonce),
    wrappedKeys: parseWrappedKeys(blobData.wrappedKeys),
    version,
    updatedAt,
  };
}

/**
 * Parse wrapped key array from API payload.
 */
export function parseWrappedKeys(keys: unknown): BlobWrappedKey[] {
  if (!Array.isArray(keys)) return [];

  return keys.map((wrappedKey, index) => {
    const wrappedKeyData = requireObject(
      wrappedKey,
      `wrapped key entry at index ${index}`,
    );

    return {
      encryptionPublicKeyHex: requireString(
        wrappedKeyData,
        "encryptionPublicKeyHex",
        `wrapped key entry at index ${index}`,
      ),
      ephemeralPublic: hexDecode(
        requireString(
          wrappedKeyData,
          "ephemeralPublicHex",
          `wrapped key entry at index ${index}`,
        ),
      ),
      wrappedKey: base64Decode(
        requireString(
          wrappedKeyData,
          "wrappedKey",
          `wrapped key entry at index ${index}`,
        ),
      ),
      wrappedKeyNonce: base64Decode(
        requireString(
          wrappedKeyData,
          "wrappedKeyNonce",
          `wrapped key entry at index ${index}`,
        ),
      ),
    };
  });
}

/**
 * Serialize in-memory blob request bytes to the API wire format.
 */
export function serializeBlobRequest(
  request: BlobRequest,
): SerializedBlobRequest {
  return {
    encryptedBlob: base64Encode(request.encryptedBlob),
    blobNonce: base64Encode(request.blobNonce),
    wrappedKeys: request.wrappedKeys.map((wk) => ({
      encryptionPublicKeyHex: wk.encryptionPublicKeyHex,
      ephemeralPublicHex: hexEncode(wk.ephemeralPublic),
      wrappedKey: base64Encode(wk.wrappedKey),
      wrappedKeyNonce: base64Encode(wk.wrappedKeyNonce),
    })),
  };
}

/**
 * Parse history list response from API payload.
 */
export function parseHistoryListResponse(data: unknown): HistoryListResponse {
  const historyListData = requireObject(data, "blob history response");
  const historyEntries = historyListData.history;
  if (!Array.isArray(historyEntries)) {
    return { history: [] };
  }

  return {
    history: historyEntries.map((entry, index) => {
      const historyEntryData = requireObject(
        entry,
        `blob history entry at index ${index}`,
      );

      return {
        version: requireNumber(
          historyEntryData,
          "version",
          `blob history entry at index ${index}`,
        ),
        createdAt: requireDate(
          historyEntryData,
          "createdAt",
          `blob history entry at index ${index}`,
        ),
      };
    }),
  };
}

/**
 * Parse a history detail response from API payload.
 */
export function parseHistoryDetailResponse(
  data: unknown,
): HistoryDetailResponse {
  const historyDetailData = requireObject(data, "blob history detail response");

  return {
    encryptedBlob: base64Decode(
      requireString(
        historyDetailData,
        "encryptedBlob",
        "blob history detail response",
      ),
    ),
    blobNonce: base64Decode(
      requireString(
        historyDetailData,
        "blobNonce",
        "blob history detail response",
      ),
    ),
    wrappedKeys: parseWrappedKeys(historyDetailData.wrappedKeys),
    version: requireNumber(
      historyDetailData,
      "version",
      "blob history detail response",
    ),
    createdAt: requireDate(
      historyDetailData,
      "createdAt",
      "blob history detail response",
    ),
  };
}

// =============================================================================
// Runtime validation helpers
// =============================================================================

/**
 * Ensure an unknown value is a non-null object.
 */
function requireObject(
  value: unknown,
  context: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object") {
    throw new NetworkError(`Invalid ${context}: expected object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Read a required string field from an object payload.
 */
function requireString(
  data: Record<string, unknown>,
  fieldName: string,
  context: string,
): string {
  const value = data[fieldName];
  if (typeof value !== "string") {
    throw new NetworkError(`Invalid ${context}: missing ${fieldName}`);
  }
  return value;
}

/**
 * Read a required numeric field from an object payload.
 */
function requireNumber(
  data: Record<string, unknown>,
  fieldName: string,
  context: string,
): number {
  const value = data[fieldName];
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new NetworkError(`Invalid ${context}: missing ${fieldName}`);
  }
  return value;
}

/**
 * Parse a required ISO-8601 date-time field from an object payload.
 */
function requireDate(
  data: Record<string, unknown>,
  fieldName: string,
  context: string,
): Date {
  const value = requireString(data, fieldName, context);
  const parsedDate = new Date(value);
  if (Number.isNaN(parsedDate.getTime())) {
    throw new NetworkError(`Invalid ${context}: malformed ${fieldName}`);
  }
  return parsedDate;
}
