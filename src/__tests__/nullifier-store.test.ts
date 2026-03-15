/**
 * Tests for NullifierStore module.
 *
 * Tests cover:
 * - isSpent / markSpent round-trip
 * - TTL-based expiration
 * - Scope isolation (different scopes do not interfere)
 * - clear() behavior
 * - localStorage persistence (with mock localStorage)
 * - getSpentForScope
 * - Size tracking
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  NullifierStore,
  createAtomicNullifierStoreAdapter,
  createInMemoryNullifierStoreAdapter,
  createNullifierStore,
} from "../nullifier-store.js";

describe("NullifierStore", () => {
  let mockStorage: Record<string, string>;

  beforeEach(() => {
    mockStorage = {};
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => mockStorage[key] ?? null),
      setItem: vi.fn((key: string, value: string) => {
        mockStorage[key] = value;
      }),
      removeItem: vi.fn((key: string) => {
        delete mockStorage[key];
      }),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("createNullifierStore", () => {
    it("should create a NullifierStore instance", () => {
      const store = createNullifierStore();
      expect(store).toBeInstanceOf(NullifierStore);
    });

    it("should create with custom storage key", () => {
      const store = createNullifierStore("custom_key");
      store.markSpent("scope1", "nullifier1");
      expect(localStorage.setItem).toHaveBeenCalledWith(
        "custom_key",
        expect.any(String),
      );
    });
  });

  describe("checkAndMarkSpent (atomic semantics)", () => {
    it("should return false on first spend and true on replay", async () => {
      const store = new NullifierStore("atomic_test");

      const first = await store.checkAndMarkSpent("scope1", "nullifier1");
      const second = await store.checkAndMarkSpent("scope1", "nullifier1");

      expect(first).toBe(false);
      expect(second).toBe(true);
    });

    it("should support custom adapter callbacks (Redis/DB style)", async () => {
      const seen = new Set<string>();
      const adapter = createAtomicNullifierStoreAdapter((scope, nullifier) => {
        const key = `${scope}:${nullifier}`;
        if (seen.has(key)) {
          return true;
        }
        seen.add(key);
        return false;
      });
      const store = new NullifierStore({ adapter });

      expect(await store.checkAndMarkSpent("scope-a", "n1")).toBe(false);
      expect(await store.checkAndMarkSpent("scope-a", "n1")).toBe(true);
    });

    it("should support in-memory server adapter without localStorage", async () => {
      vi.stubGlobal("localStorage", undefined);
      const store = new NullifierStore({
        adapter: createInMemoryNullifierStoreAdapter(),
      });

      expect(await store.checkAndMarkSpent("scope1", "n1")).toBe(false);
      expect(await store.checkAndMarkSpent("scope1", "n1")).toBe(true);
    });
  });

  describe("isSpent / markSpent round-trip", () => {
    it("should report unspent nullifier as not spent", () => {
      const store = new NullifierStore("test_nullifiers");

      expect(store.isSpent("scope1", "nullifier1")).toBe(false);
    });

    it("should report spent nullifier as spent after markSpent", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope1", "nullifier1");

      expect(store.isSpent("scope1", "nullifier1")).toBe(true);
    });

    it("should handle multiple nullifiers in the same scope", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope1", "nullifier1");
      store.markSpent("scope1", "nullifier2");

      expect(store.isSpent("scope1", "nullifier1")).toBe(true);
      expect(store.isSpent("scope1", "nullifier2")).toBe(true);
      expect(store.isSpent("scope1", "nullifier3")).toBe(false);
    });
  });

  describe("TTL expiration", () => {
    it("should expire nullifiers after TTL", () => {
      vi.useFakeTimers();
      const ttlMs = 1000; // 1 second TTL
      const store = new NullifierStore("test_nullifiers", ttlMs);

      store.markSpent("scope1", "nullifier1");
      expect(store.isSpent("scope1", "nullifier1")).toBe(true);

      // Advance past TTL
      vi.advanceTimersByTime(ttlMs + 1);

      expect(store.isSpent("scope1", "nullifier1")).toBe(false);

      vi.useRealTimers();
    });

    it("should not expire nullifiers before TTL", () => {
      vi.useFakeTimers();
      const ttlMs = 5000;
      const store = new NullifierStore("test_nullifiers", ttlMs);

      store.markSpent("scope1", "nullifier1");

      // Advance but not past TTL
      vi.advanceTimersByTime(ttlMs - 1);

      expect(store.isSpent("scope1", "nullifier1")).toBe(true);

      vi.useRealTimers();
    });

    it("should support custom TTL per nullifier", () => {
      vi.useFakeTimers();
      const defaultTtl = 10000;
      const store = new NullifierStore("test_nullifiers", defaultTtl);

      // Mark with short custom TTL
      store.markSpent("scope1", "short_lived", 500);
      // Mark with default TTL
      store.markSpent("scope1", "long_lived");

      vi.advanceTimersByTime(600);

      expect(store.isSpent("scope1", "short_lived")).toBe(false);
      expect(store.isSpent("scope1", "long_lived")).toBe(true);

      vi.useRealTimers();
    });
  });

  describe("scope isolation", () => {
    it("should not interfere between different scopes", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope_a", "nullifier1");

      expect(store.isSpent("scope_a", "nullifier1")).toBe(true);
      expect(store.isSpent("scope_b", "nullifier1")).toBe(false);
    });

    it("should allow same nullifier in different scopes", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope_a", "shared_nullifier");
      store.markSpent("scope_b", "shared_nullifier");

      expect(store.isSpent("scope_a", "shared_nullifier")).toBe(true);
      expect(store.isSpent("scope_b", "shared_nullifier")).toBe(true);
    });

    it("should not mix scopes when checking spent status", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("example.com", "abc123");
      store.markSpent("other.com", "def456");

      expect(store.isSpent("example.com", "abc123")).toBe(true);
      expect(store.isSpent("example.com", "def456")).toBe(false);
      expect(store.isSpent("other.com", "abc123")).toBe(false);
      expect(store.isSpent("other.com", "def456")).toBe(true);
    });
  });

  describe("clear", () => {
    it("should remove all stored nullifiers", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope1", "n1");
      store.markSpent("scope2", "n2");
      store.markSpent("scope3", "n3");

      expect(store.size).toBe(3);

      store.clear();

      expect(store.size).toBe(0);
      expect(store.isSpent("scope1", "n1")).toBe(false);
      expect(store.isSpent("scope2", "n2")).toBe(false);
      expect(store.isSpent("scope3", "n3")).toBe(false);
    });

    it("should update localStorage after clear", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope1", "n1");
      store.clear();

      // Should have saved empty array to localStorage
      expect(localStorage.setItem).toHaveBeenLastCalledWith(
        "test_nullifiers",
        "[]",
      );
    });
  });

  describe("getSpentForScope", () => {
    it("should return all spent nullifiers for a scope", () => {
      const store = new NullifierStore("test_nullifiers");

      store.markSpent("scope1", "n1");
      store.markSpent("scope1", "n2");
      store.markSpent("scope2", "n3");

      const scope1Spent = store.getSpentForScope("scope1");
      expect(scope1Spent).toContain("n1");
      expect(scope1Spent).toContain("n2");
      expect(scope1Spent).not.toContain("n3");
      expect(scope1Spent.length).toBe(2);
    });

    it("should return empty array for scope with no spent nullifiers", () => {
      const store = new NullifierStore("test_nullifiers");

      const result = store.getSpentForScope("nonexistent_scope");
      expect(result).toEqual([]);
    });
  });

  describe("size", () => {
    it("should track the number of stored nullifiers", () => {
      const store = new NullifierStore("test_nullifiers");

      expect(store.size).toBe(0);

      store.markSpent("scope1", "n1");
      expect(store.size).toBe(1);

      store.markSpent("scope1", "n2");
      expect(store.size).toBe(2);

      store.markSpent("scope2", "n3");
      expect(store.size).toBe(3);
    });

    it("should exclude expired nullifiers from size", () => {
      vi.useFakeTimers();
      const store = new NullifierStore("test_nullifiers", 1000);

      store.markSpent("scope1", "n1");
      store.markSpent("scope1", "n2");
      expect(store.size).toBe(2);

      vi.advanceTimersByTime(1001);

      expect(store.size).toBe(0);

      vi.useRealTimers();
    });
  });

  describe("localStorage persistence", () => {
    it("should save to localStorage on markSpent", () => {
      const store = new NullifierStore("persist_test");

      store.markSpent("scope1", "n1");

      expect(localStorage.setItem).toHaveBeenCalledWith(
        "persist_test",
        expect.any(String),
      );

      const savedData = JSON.parse(mockStorage.persist_test);
      expect(savedData).toHaveLength(1);
      expect(savedData[0].nullifier).toBe("n1");
      expect(savedData[0].scope).toBe("scope1");
    });

    it("should load from localStorage on construction", () => {
      // Pre-populate localStorage with a valid entry
      const now = Date.now();
      const entries = [
        {
          nullifier: "stored_n",
          scope: "stored_scope",
          spentAt: now,
          expiresAt: now + 1000000,
        },
      ];
      mockStorage.load_test = JSON.stringify(entries);

      const store = new NullifierStore("load_test");

      expect(store.isSpent("stored_scope", "stored_n")).toBe(true);
      expect(store.size).toBe(1);
    });

    it("should skip expired entries when loading from localStorage", () => {
      const now = Date.now();
      const entries = [
        {
          nullifier: "expired_n",
          scope: "scope1",
          spentAt: now - 200000,
          expiresAt: now - 100000, // Already expired
        },
        {
          nullifier: "valid_n",
          scope: "scope1",
          spentAt: now,
          expiresAt: now + 1000000,
        },
      ];
      mockStorage.filter_test = JSON.stringify(entries);

      const store = new NullifierStore("filter_test");

      expect(store.isSpent("scope1", "expired_n")).toBe(false);
      expect(store.isSpent("scope1", "valid_n")).toBe(true);
      expect(store.size).toBe(1);
    });

    it("should handle corrupted localStorage data gracefully", () => {
      mockStorage.corrupt_test = "not valid json{{{";

      // Should not throw
      const store = new NullifierStore("corrupt_test");
      expect(store.size).toBe(0);
    });

    it("should handle missing localStorage gracefully", () => {
      vi.stubGlobal("localStorage", undefined);

      // Should not throw
      const store = new NullifierStore("no_ls");
      store.markSpent("scope1", "n1");
      expect(store.isSpent("scope1", "n1")).toBe(true);
    });
  });
});
