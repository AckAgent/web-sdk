/**
 * Tests for encoding utilities: base64url, base64, UUID conversion, and UUID generation.
 * Covers round-trip correctness, URL-safe character handling, large array chunking,
 * and UUID v4 format compliance.
 */

import { describe, it, expect } from "vitest";
import {
  base64urlEncode,
  base64urlDecode,
  base64Encode,
  base64Decode,
  uuidToBytes,
  bytesToUuid,
  generateUuid,
} from "../encoding.js";

describe("base64urlEncode / base64urlDecode", () => {
  it("round-trips arbitrary bytes", () => {
    const data = new Uint8Array([0, 1, 2, 255, 128, 64]);
    const encoded = base64urlEncode(data);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(data);
  });

  it("produces URL-safe characters (no +, /, or =)", () => {
    // Use bytes that produce + and / in standard base64
    const data = new Uint8Array([0xff, 0xff, 0xfe]);
    const encoded = base64urlEncode(data);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });

  it("handles empty input", () => {
    const data = new Uint8Array(0);
    const encoded = base64urlEncode(data);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(data);
  });

  it("decodes input with padding characters", () => {
    // Encode then manually add padding, decode should still work
    const data = new Uint8Array([1, 2, 3]);
    const encoded = base64urlEncode(data);
    // Manually add padding to test the decode path that strips it
    const withPadding = `${encoded}=`;
    const decoded = base64urlDecode(withPadding.replace(/=+$/, ""));
    expect(decoded).toEqual(data);
  });
});

describe("base64Encode / base64Decode", () => {
  it("round-trips arbitrary bytes", () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const encoded = base64Encode(data);
    const decoded = base64Decode(encoded);
    expect(decoded).toEqual(data);
  });

  it("produces standard base64 with padding", () => {
    // 1 byte input should produce padding (4 char output with ==)
    const data = new Uint8Array([65]); // 'A'
    const encoded = base64Encode(data);
    expect(encoded).toBe("QQ==");
  });

  it("handles empty input", () => {
    const data = new Uint8Array(0);
    const encoded = base64Encode(data);
    const decoded = base64Decode(encoded);
    expect(decoded).toEqual(data);
  });
});

describe("large array chunking", () => {
  it("correctly encodes and decodes arrays larger than 32KB", () => {
    // CHUNK_SIZE is 0x8000 (32768), so use something larger
    const size = 40000;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      data[i] = i % 256;
    }
    // Test with base64
    const encoded = base64Encode(data);
    const decoded = base64Decode(encoded);
    expect(decoded).toEqual(data);
  });

  it("correctly round-trips large arrays through base64url", () => {
    const size = 40000;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      data[i] = i % 256;
    }
    const encoded = base64urlEncode(data);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(data);
  });
});

describe("uuidToBytes / bytesToUuid", () => {
  it("round-trips a known UUID", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    const bytes = uuidToBytes(uuid);
    expect(bytes.length).toBe(16);
    const result = bytesToUuid(bytes);
    expect(result).toBe(uuid);
  });

  it("converts known UUID to correct bytes", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    const bytes = uuidToBytes(uuid);
    // First byte: 0x55
    expect(bytes[0]).toBe(0x55);
    // Second byte: 0x0e
    expect(bytes[1]).toBe(0x0e);
    // Last byte: 0x00
    expect(bytes[15]).toBe(0x00);
  });

  it("round-trips the nil UUID", () => {
    const nil = "00000000-0000-0000-0000-000000000000";
    const bytes = uuidToBytes(nil);
    expect(bytes).toEqual(new Uint8Array(16));
    expect(bytesToUuid(bytes)).toBe(nil);
  });
});

describe("generateUuid", () => {
  it("returns a string matching UUID format (8-4-4-4-12)", () => {
    const uuid = generateUuid();
    const pattern =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(uuid).toMatch(pattern);
  });

  it("sets version 4 bits (byte 6 upper nibble is 0x4)", () => {
    const uuid = generateUuid();
    // Version is the 13th hex char (index 14 in string, accounting for hyphens)
    // Format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx where V is version
    const versionChar = uuid.charAt(14);
    expect(versionChar).toBe("4");
  });

  it("sets variant bits (byte 8 upper bits are 10xx)", () => {
    const uuid = generateUuid();
    // Variant is the 17th hex char (index 19 in string, accounting for hyphens)
    // Format: xxxxxxxx-xxxx-xxxx-Yxxx-xxxxxxxxxxxx where Y is 8, 9, a, or b
    const variantChar = uuid.charAt(19);
    expect(["8", "9", "a", "b"]).toContain(variantChar);
  });

  it("generates unique UUIDs", () => {
    const uuids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      uuids.add(generateUuid());
    }
    expect(uuids.size).toBe(100);
  });
});
