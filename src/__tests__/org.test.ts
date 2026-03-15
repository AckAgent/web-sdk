/**
 * Tests for organization emoji utilities
 */

import { describe, it, expect } from "vitest";
import { emojiFromIndex } from "../org.js";
import { SAS_WORDS, SAS_EMOJIS } from "../generated/sas-dictionary.js";
import type { UserOrganization } from "../types.js";

describe("emojiFromIndex", () => {
  // =========================================================================
  // 1-symbol range (0-255)
  // =========================================================================

  describe("1-symbol range (0-255)", () => {
    it("should return first dictionary entry for index 0", () => {
      const result = emojiFromIndex(0);
      expect(result.words).toEqual([SAS_WORDS[0]]);
      expect(result.emojis).toEqual([SAS_EMOJIS[0]]);
      expect(result.wordString).toBe("dog");
      expect(result.emojiString).toBe("🐶");
    });

    it("should return last 1-symbol entry for index 255", () => {
      const result = emojiFromIndex(255);
      expect(result.words).toEqual([SAS_WORDS[255]]);
      expect(result.emojis).toEqual([SAS_EMOJIS[255]]);
      expect(result.words).toHaveLength(1);
      expect(result.emojis).toHaveLength(1);
    });

    it("should return correct entry for mid-range index", () => {
      const result = emojiFromIndex(128);
      expect(result.words).toEqual([SAS_WORDS[128]]);
      expect(result.emojis).toEqual([SAS_EMOJIS[128]]);
      expect(result.wordString).toBe(SAS_WORDS[128]);
    });
  });

  // =========================================================================
  // 2-symbol range (256-65791)
  // =========================================================================

  describe("2-symbol range (256-65791)", () => {
    it("should return 2 symbols for index 256 (first in range)", () => {
      const result = emojiFromIndex(256);
      // adjusted = 0 -> indices [0, 0]
      expect(result.words).toEqual([SAS_WORDS[0], SAS_WORDS[0]]);
      expect(result.emojis).toEqual([SAS_EMOJIS[0], SAS_EMOJIS[0]]);
      expect(result.wordString).toBe("dog-dog");
      expect(result.emojiString).toBe("🐶 🐶");
    });

    it("should return 2 symbols for index 257", () => {
      const result = emojiFromIndex(257);
      // adjusted = 1 -> indices [0, 1]
      expect(result.words).toEqual([SAS_WORDS[0], SAS_WORDS[1]]);
      expect(result.wordString).toBe("dog-cat");
    });

    it("should return 2 symbols for index 512", () => {
      const result = emojiFromIndex(512);
      // adjusted = 256 -> indices [1, 0]
      expect(result.words).toEqual([SAS_WORDS[1], SAS_WORDS[0]]);
      expect(result.wordString).toBe("cat-dog");
    });

    it("should return last 2-symbol entry for index 65791", () => {
      const result = emojiFromIndex(65791);
      // adjusted = 65535 -> indices [255, 255]
      expect(result.words).toEqual([SAS_WORDS[255], SAS_WORDS[255]]);
      expect(result.emojis).toEqual([SAS_EMOJIS[255], SAS_EMOJIS[255]]);
      expect(result.words).toHaveLength(2);
    });
  });

  // =========================================================================
  // 3-symbol range (65792+)
  // =========================================================================

  describe("3-symbol range (65792+)", () => {
    it("should return 3 symbols for index 65792 (first in range)", () => {
      const result = emojiFromIndex(65792);
      // adjusted = 0 -> indices [0, 0, 0]
      expect(result.words).toEqual([SAS_WORDS[0], SAS_WORDS[0], SAS_WORDS[0]]);
      expect(result.emojis).toEqual([
        SAS_EMOJIS[0],
        SAS_EMOJIS[0],
        SAS_EMOJIS[0],
      ]);
      expect(result.wordString).toBe("dog-dog-dog");
      expect(result.emojiString).toBe("🐶 🐶 🐶");
    });

    it("should return 3 symbols for index 65793", () => {
      const result = emojiFromIndex(65793);
      // adjusted = 1 -> indices [0, 0, 1]
      expect(result.words).toEqual([SAS_WORDS[0], SAS_WORDS[0], SAS_WORDS[1]]);
      expect(result.wordString).toBe("dog-dog-cat");
    });

    it("should correctly decompose a larger 3-symbol index", () => {
      // adjusted = 256*256 + 256 + 1 = 65793 -> but that's index 65792+65793=131585
      // Let's pick index 65792 + (1*256*256 + 2*256 + 3) = 65792 + 66051 = 131843
      const result = emojiFromIndex(131843);
      // adjusted = 66051 -> [1, 2, 3]
      expect(result.words).toEqual([SAS_WORDS[1], SAS_WORDS[2], SAS_WORDS[3]]);
      expect(result.wordString).toBe("cat-mouse-hamster");
    });
  });

  // =========================================================================
  // String formatting
  // =========================================================================

  describe("string formatting", () => {
    it("should join words with hyphens", () => {
      const result = emojiFromIndex(257); // 2 symbols: [0, 1]
      expect(result.wordString).toBe("dog-cat");
    });

    it("should join emojis with spaces", () => {
      const result = emojiFromIndex(257);
      expect(result.emojiString).toBe("🐶 🐱");
    });

    it("should have matching length for words and emojis arrays", () => {
      for (const idx of [0, 128, 255, 256, 1000, 65791, 65792, 100000]) {
        const result = emojiFromIndex(idx);
        expect(result.words.length).toBe(result.emojis.length);
      }
    });
  });

  // =========================================================================
  // Error cases
  // =========================================================================

  describe("error cases", () => {
    it("should throw RangeError for negative index", () => {
      expect(() => emojiFromIndex(-1)).toThrow(RangeError);
    });

    it("should throw RangeError for non-integer index", () => {
      expect(() => emojiFromIndex(1.5)).toThrow(RangeError);
    });

    it("should throw RangeError for NaN", () => {
      expect(() => emojiFromIndex(Number.NaN)).toThrow(RangeError);
    });

    it("should throw RangeError for index exceeding 3-symbol maximum", () => {
      // Max 3-symbol: 65792 + 256^3 - 1 = 65792 + 16777215 = 16843007
      expect(() => emojiFromIndex(16843008)).toThrow(RangeError);
    });

    it("should not throw for maximum valid 3-symbol index", () => {
      // Max valid: 65792 + 256^3 - 1 = 16843007
      expect(() => emojiFromIndex(16843007)).not.toThrow();
      const result = emojiFromIndex(16843007);
      expect(result.words).toHaveLength(3);
      expect(result.words).toEqual([
        SAS_WORDS[255],
        SAS_WORDS[255],
        SAS_WORDS[255],
      ]);
    });
  });
});

describe("UserOrganization type", () => {
  it("should construct a valid UserOrganization", () => {
    const org: UserOrganization = {
      organizationId: "550e8400-e29b-41d4-a716-446655440000",
      orgEmojiIndex: 42,
      userEmojiIndex: 0,
      role: "owner",
      tier: "enterprise",
      memberCount: 5,
      localName: "My Org",
    };

    expect(org.organizationId).toBe("550e8400-e29b-41d4-a716-446655440000");
    expect(org.orgEmojiIndex).toBe(42);
    expect(org.role).toBe("owner");
    expect(org.tier).toBe("enterprise");
    expect(org.memberCount).toBe(5);
    expect(org.localName).toBe("My Org");
  });

  it("should allow localName to be optional", () => {
    const org: UserOrganization = {
      organizationId: "550e8400-e29b-41d4-a716-446655440000",
      orgEmojiIndex: 0,
      userEmojiIndex: 1,
      role: "member",
      tier: "free",
      memberCount: 2,
    };

    expect(org.localName).toBeUndefined();
  });

  it("should work with emojiFromIndex for org display", () => {
    const org: UserOrganization = {
      organizationId: "550e8400-e29b-41d4-a716-446655440000",
      orgEmojiIndex: 300,
      userEmojiIndex: 5,
      role: "member",
      tier: "free",
      memberCount: 10,
    };

    const orgEmoji = emojiFromIndex(org.orgEmojiIndex);
    expect(orgEmoji.words).toHaveLength(2); // 300 is in 2-symbol range
    expect(orgEmoji.emojis).toHaveLength(2);

    const userEmoji = emojiFromIndex(org.userEmojiIndex);
    expect(userEmoji.words).toHaveLength(1); // 5 is in 1-symbol range
  });
});
