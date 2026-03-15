/**
 * Organization emoji utilities
 *
 * Converts a numeric emoji index into human-readable words and emoji strings
 * using the SAS dictionary. The index encoding uses a variable-length scheme:
 *
 *   - Index 0-255: 1 symbol (256 values)
 *   - Index 256-65791: 2 symbols (256^2 = 65536 values)
 *   - Index 65792+: 3 symbols (256^3 = 16777216 values)
 *
 * This matches the server-side EmojiFromIndex() function used for
 * organization and user identification across all clients.
 */

import { SAS_WORDS, SAS_EMOJIS } from "./generated/sas-dictionary.js";

/** Resolved emoji representation for an organization or user index */
export interface OrgEmoji {
  /** Individual words (e.g., ["cat", "rocket"]) */
  words: string[];
  /** Individual emojis (e.g., ["🐱", "🚀"]) */
  emojis: string[];
  /** Hyphen-joined word string (e.g., "cat-rocket") */
  wordString: string;
  /** Space-joined emoji string (e.g., "🐱 🚀") */
  emojiString: string;
}

/** Boundary between 1-symbol and 2-symbol ranges */
const ONE_SYMBOL_MAX = 255;
/** Boundary between 2-symbol and 3-symbol ranges */
const TWO_SYMBOL_MAX = 65791;
/** Start of the 2-symbol range */
const TWO_SYMBOL_START = 256;
/** Start of the 3-symbol range */
const THREE_SYMBOL_START = 65792;
/** Number of entries in the SAS dictionary */
const DICT_SIZE = 256;

/**
 * Convert a numeric emoji index to words and emoji strings.
 *
 * Uses the same variable-length encoding as the server-side EmojiFromIndex():
 * - Index 0-255: 1 symbol (direct dictionary lookup)
 * - Index 256-65791: 2 symbols (base-256 decomposition)
 * - Index 65792+: 3 symbols (base-256 decomposition)
 *
 * @param index - Non-negative emoji index from the backend
 * @returns Resolved OrgEmoji with words, emojis, and formatted strings
 * @throws RangeError if index is negative or exceeds 3-symbol range
 */
export function emojiFromIndex(index: number): OrgEmoji {
  if (!Number.isInteger(index) || index < 0) {
    throw new RangeError(
      `Emoji index must be a non-negative integer, got ${index}`,
    );
  }

  let indices: number[];

  if (index <= ONE_SYMBOL_MAX) {
    // 1 symbol: direct lookup
    indices = [index];
  } else if (index <= TWO_SYMBOL_MAX) {
    // 2 symbols: subtract offset, decompose base-256
    const adjusted = index - TWO_SYMBOL_START;
    indices = [Math.floor(adjusted / DICT_SIZE), adjusted % DICT_SIZE];
  } else {
    // 3 symbols: subtract offset, decompose base-256
    const adjusted = index - THREE_SYMBOL_START;
    const maxThreeSymbol = DICT_SIZE * DICT_SIZE * DICT_SIZE - 1;
    if (adjusted > maxThreeSymbol) {
      throw new RangeError(
        `Emoji index ${index} exceeds maximum 3-symbol range`,
      );
    }
    indices = [
      Math.floor(adjusted / (DICT_SIZE * DICT_SIZE)),
      Math.floor((adjusted % (DICT_SIZE * DICT_SIZE)) / DICT_SIZE),
      adjusted % DICT_SIZE,
    ];
  }

  const words = indices.map((i) => SAS_WORDS[i]);
  const emojis = indices.map((i) => SAS_EMOJIS[i]);

  return {
    words,
    emojis,
    wordString: words.join("-"),
    emojiString: emojis.join(" "),
  };
}
