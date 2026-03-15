/**
 * Base64url encoding utilities
 */

/**
 * Maximum chunk size for String.fromCharCode to avoid call stack overflow.
 * 32KB (0x8000 bytes) is safe for all major browsers.
 */
const CHUNK_SIZE = 0x8000;

/**
 * Convert Uint8Array to binary string safely (handles large arrays)
 */
function bytesToBinaryString(data: Uint8Array): string {
  if (data.length <= CHUNK_SIZE) {
    return String.fromCharCode.apply(null, Array.from(data));
  }

  // Process in chunks for large arrays to avoid stack overflow
  let result = "";
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const chunk = data.subarray(i, Math.min(i + CHUNK_SIZE, data.length));
    result += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return result;
}

/**
 * Encode bytes to base64url (no padding)
 */
export function base64urlEncode(data: Uint8Array): string {
  const base64 = btoa(bytesToBinaryString(data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode base64url to bytes
 */
export function base64urlDecode(str: string): Uint8Array {
  // Add padding if needed
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");

  const remainder = base64.length % 4;
  if (remainder > 0) {
    base64 += "=".repeat(4 - remainder);
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode bytes to standard base64
 */
export function base64Encode(data: Uint8Array): string {
  return btoa(bytesToBinaryString(data));
}

/**
 * Decode standard base64 to bytes
 */
export function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode bytes to lowercase hex string
 */
export function hexEncode(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decode hex string to bytes
 */
export function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a UUID string to bytes (16 bytes)
 */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to UUID string
 */
export function bytesToUuid(bytes: Uint8Array): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Generate a random UUID v4
 */
export function generateUuid(): string {
  return crypto.randomUUID();
}
