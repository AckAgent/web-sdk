import { describe, it, expect } from "vitest";
import { computeSAS, type SASApproverKey } from "./sas";
import testVectors from "../test-fixtures/crypto_test_vectors.json";

// Type for the test vectors JSON structure
interface SASVectorApproverKey {
  device_id: string;
  public_key_hex: string; // Used as encryptionPublicKeyHex for sorting
}

interface SASVector {
  description: string;
  requester_public_key_hex: string;
  device_keys: SASVectorApproverKey[]; // Legacy name in test vectors
  expected_words: string[];
  expected_emojis: string[];
  expected_word_string: string;
  expected_emoji_string: string;
}

interface TestVectors {
  sas_vectors: SASVector[];
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

describe("SAS (Short Authentication String)", () => {
  const vectors = testVectors as TestVectors;

  describe("computeSAS against shared test vectors", () => {
    vectors.sas_vectors.forEach((vector) => {
      it(vector.description, () => {
        // Convert hex to Uint8Array
        const requesterPubKey = hexToBytes(vector.requester_public_key_hex);

        // Build approver keys array
        const approverKeys: SASApproverKey[] = vector.device_keys.map((dk) => ({
          encryptionPublicKeyHex: dk.public_key_hex,
          publicKey: hexToBytes(dk.public_key_hex),
        }));

        // Compute SAS
        const result = computeSAS(requesterPubKey, approverKeys);

        // Verify all fields
        expect(result.words).toEqual(vector.expected_words);
        expect(result.emojis).toEqual(vector.expected_emojis);
        expect(result.wordString).toBe(vector.expected_word_string);
        expect(result.emojiString).toBe(vector.expected_emoji_string);
      });
    });
  });

  describe("approver key sorting", () => {
    it("produces same result regardless of approver key input order", () => {
      // Find the two-approver vector
      const twoApproverVector = vectors.sas_vectors.find(
        (v) => v.device_keys.length === 2,
      );
      expect(twoApproverVector).toBeDefined();

      const requesterPubKey = hexToBytes(
        twoApproverVector?.requester_public_key_hex,
      );

      // Build approver keys in original order
      const approverKeys: SASApproverKey[] = twoApproverVector?.device_keys.map(
        (dk) => ({
          encryptionPublicKeyHex: dk.public_key_hex,
          publicKey: hexToBytes(dk.public_key_hex),
        }),
      );

      // Compute SAS with original order
      const result1 = computeSAS(requesterPubKey, approverKeys);
      expect(result1.words).toEqual(twoApproverVector?.expected_words);

      // Reverse the approver keys
      const reversedKeys = [...approverKeys].reverse();
      const result2 = computeSAS(requesterPubKey, reversedKeys);

      // Should produce identical results
      expect(result2.words).toEqual(result1.words);
      expect(result2.emojis).toEqual(result1.emojis);
      expect(result2.wordString).toBe(result1.wordString);
      expect(result2.emojiString).toBe(result1.emojiString);
    });
  });

  describe("sorting regression", () => {
    it("sorts by encryptionPublicKeyHex, not device ID", () => {
      // Find the sorting-divergence vector where UUID sort differs from key hex sort
      const divergenceVector = vectors.sas_vectors.find((v) =>
        v.description.includes("Sorting divergence"),
      );
      expect(divergenceVector).toBeDefined();

      const requesterPubKey = hexToBytes(
        divergenceVector?.requester_public_key_hex,
      );

      const approverKeys: SASApproverKey[] = divergenceVector?.device_keys.map(
        (dk) => ({
          encryptionPublicKeyHex: dk.public_key_hex,
          publicKey: hexToBytes(dk.public_key_hex),
        }),
      );

      const result = computeSAS(requesterPubKey, approverKeys);

      // Must match expected (computed with key-hex sort, not UUID sort)
      expect(result.words).toEqual(divergenceVector?.expected_words);
      expect(result.wordString).toBe(divergenceVector?.expected_word_string);
    });
  });

  describe("edge cases", () => {
    it("handles empty approver keys", () => {
      const requesterPubKey = new Uint8Array(32);
      const approverKeys: SASApproverKey[] = [];

      // Should not throw
      const result = computeSAS(requesterPubKey, approverKeys);

      // Should return 5 words/emojis (40 bits of entropy)
      expect(result.words).toHaveLength(5);
      expect(result.emojis).toHaveLength(5);
      expect(result.wordString).toMatch(/^\w+-\w+-\w+-\w+-\w+$/);
      expect(result.emojiString).toBeTruthy();
    });
  });

  describe("result formatting", () => {
    it("wordString is hyphen-separated", () => {
      const requesterPubKey = new Uint8Array(32);
      const result = computeSAS(requesterPubKey, []);

      // Word string should be hyphen-separated
      const parts = result.wordString.split("-");
      expect(parts).toHaveLength(5);
      expect(parts).toEqual(result.words);
    });

    it("emojiString is space-separated", () => {
      const requesterPubKey = new Uint8Array(32);
      const result = computeSAS(requesterPubKey, []);

      // Emoji string should be space-separated
      const parts = result.emojiString.split(" ");
      expect(parts).toHaveLength(5);
      expect(parts).toEqual(result.emojis);
    });
  });
});
