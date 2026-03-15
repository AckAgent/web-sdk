/**
 * Tests for IndexedDB storage module
 */

// Must import fake-indexeddb BEFORE storage module
import "fake-indexeddb/auto";

import { describe, it, expect, beforeEach } from "vitest";
import {
  openDatabase,
  storeAccount,
  loadAccount,
  deleteAccount,
  listAccounts,
  clearAllData,
  isIndexedDBAvailable,
} from "../storage.js";
import { mockStoredAccount, mockUserDevice } from "./mocks.js";

describe("storage", () => {
  beforeEach(async () => {
    // Clear all data before each test
    await clearAllData();
  });

  describe("openDatabase", () => {
    it("should open database successfully", async () => {
      const db = await openDatabase();
      expect(db).toBeDefined();
      expect(db.name).toBe("ackagent-keys");
    });

    it("should return same database on subsequent calls (singleton)", async () => {
      const db1 = await openDatabase();
      const db2 = await openDatabase();
      expect(db1).toBe(db2);
    });

    it("should create accounts object store", async () => {
      const db = await openDatabase();
      expect(db.objectStoreNames.contains("accounts")).toBe(true);
    });
  });

  describe("isIndexedDBAvailable", () => {
    it("should return true when IndexedDB is available", () => {
      expect(isIndexedDBAvailable()).toBe(true);
    });
  });

  describe("Account Storage", () => {
    describe("storeAccount", () => {
      it("should store account with all fields", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded).not.toBeNull();
        expect(loaded?.userId).toBe(account.userId);
        expect(loaded?.accessToken).toBe(account.accessToken);
        expect(loaded?.sasVerified).toBe(account.sasVerified);
        expect(loaded?.relayUrl).toBe(account.relayUrl);
      });

      it("should store account with optional refreshToken", async () => {
        const account = await mockStoredAccount({
          refreshToken: "test-refresh-token",
        });
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.refreshToken).toBe("test-refresh-token");
      });

      it("should store account without refreshToken", async () => {
        const account = await mockStoredAccount();
        delete (account as { refreshToken?: string }).refreshToken;
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.refreshToken).toBeUndefined();
      });

      it("should overwrite existing account with same userId", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const updatedAccount = {
          ...account,
          accessToken: "updated-token",
          sasVerified: false,
        };
        await storeAccount(updatedAccount);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.accessToken).toBe("updated-token");
        expect(loaded?.sasVerified).toBe(false);
      });

      it("should preserve CryptoKey via structured cloning", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.identityPrivateKey).toBeDefined();
        expect(loaded?.identityPrivateKey.type).toBe("private");
        // CryptoKey should be usable (non-extractable private key)
        expect(loaded?.identityPrivateKey.extractable).toBe(false);
      });

      it("should preserve Uint8Array publicKey", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.identityPublicKey).toBeInstanceOf(Uint8Array);
        expect(loaded?.identityPublicKey.length).toBe(33); // P-256 compressed
      });
    });

    describe("loadAccount", () => {
      it("should convert ISO strings back to Date objects", async () => {
        const account = await mockStoredAccount();
        const originalExpiresAt = account.expiresAt;
        const originalLoggedInAt = account.loggedInAt;
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.expiresAt).toBeInstanceOf(Date);
        expect(loaded?.loggedInAt).toBeInstanceOf(Date);
        expect(loaded?.expiresAt.getTime()).toBe(originalExpiresAt.getTime());
        expect(loaded?.loggedInAt.getTime()).toBe(originalLoggedInAt.getTime());
      });

      it("should return null for non-existent userId", async () => {
        const loaded = await loadAccount("non-existent-user");
        expect(loaded).toBeNull();
      });

      it("should preserve device array", async () => {
        const devices = [
          await mockUserDevice({ deviceName: "Device 1", isPrimary: true }),
          await mockUserDevice({ deviceName: "Device 2", isPrimary: false }),
        ];
        const account = await mockStoredAccount({ devices });
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.devices).toHaveLength(2);
        expect(loaded?.devices[0].deviceName).toBe("Device 1");
        expect(loaded?.devices[0].isPrimary).toBe(true);
        expect(loaded?.devices[1].deviceName).toBe("Device 2");
        expect(loaded?.devices[1].isPrimary).toBe(false);
      });

      it("should preserve device publicKey as Uint8Array", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const loaded = await loadAccount(account.userId);
        expect(loaded?.devices[0].publicKey).toBeInstanceOf(Uint8Array);
        expect(loaded?.devices[0].publicKey.length).toBe(33); // P-256 compressed
      });
    });

    describe("deleteAccount", () => {
      it("should remove account by userId", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        await deleteAccount(account.userId);

        const loaded = await loadAccount(account.userId);
        expect(loaded).toBeNull();
      });

      it("should succeed silently for non-existent userId", async () => {
        // Should not throw
        await expect(
          deleteAccount("non-existent-user"),
        ).resolves.toBeUndefined();
      });

      it("should not affect other accounts", async () => {
        const account1 = await mockStoredAccount();
        const account2 = await mockStoredAccount();
        await storeAccount(account1);
        await storeAccount(account2);

        await deleteAccount(account1.userId);

        const loaded1 = await loadAccount(account1.userId);
        const loaded2 = await loadAccount(account2.userId);
        expect(loaded1).toBeNull();
        expect(loaded2).not.toBeNull();
      });
    });

    describe("listAccounts", () => {
      it("should return empty array when no accounts", async () => {
        const accounts = await listAccounts();
        expect(accounts).toEqual([]);
      });

      it("should return all stored accounts", async () => {
        const account1 = await mockStoredAccount();
        const account2 = await mockStoredAccount();
        await storeAccount(account1);
        await storeAccount(account2);

        const accounts = await listAccounts();
        expect(accounts).toHaveLength(2);
        const userIds = accounts.map((a) => a.userId);
        expect(userIds).toContain(account1.userId);
        expect(userIds).toContain(account2.userId);
      });

      it("should convert all Date fields correctly", async () => {
        const account = await mockStoredAccount();
        await storeAccount(account);

        const accounts = await listAccounts();
        expect(accounts[0].expiresAt).toBeInstanceOf(Date);
        expect(accounts[0].loggedInAt).toBeInstanceOf(Date);
      });
    });
  });

  describe("clearAllData", () => {
    it("should remove all accounts", async () => {
      const account = await mockStoredAccount();
      await storeAccount(account);

      await clearAllData();

      const accounts = await listAccounts();
      expect(accounts).toEqual([]);
    });

    it("should succeed when data stores are already empty", async () => {
      await expect(clearAllData()).resolves.toBeUndefined();
    });

    it("should clear all accounts", async () => {
      // Store multiple accounts
      const account1 = await mockStoredAccount();
      const account2 = await mockStoredAccount();
      await storeAccount(account1);
      await storeAccount(account2);

      await clearAllData();

      // Verify all cleared
      expect(await listAccounts()).toHaveLength(0);
    });
  });

  describe("Organization Fields", () => {
    it("should store and load account with organizations", async () => {
      const account = await mockStoredAccount({
        organizations: [
          {
            organizationId: "550e8400-e29b-41d4-a716-446655440000",
            orgEmojiIndex: 42,
            userEmojiIndex: 0,
            role: "owner",
            tier: "enterprise",
            memberCount: 5,
            localName: "My Org",
          },
        ],
        defaultOrgId: "550e8400-e29b-41d4-a716-446655440000",
      });
      await storeAccount(account);

      const loaded = await loadAccount(account.userId);
      expect(loaded?.organizations).toHaveLength(1);
      expect(loaded?.organizations?.[0].organizationId).toBe(
        "550e8400-e29b-41d4-a716-446655440000",
      );
      expect(loaded?.organizations?.[0].orgEmojiIndex).toBe(42);
      expect(loaded?.organizations?.[0].role).toBe("owner");
      expect(loaded?.organizations?.[0].tier).toBe("enterprise");
      expect(loaded?.organizations?.[0].memberCount).toBe(5);
      expect(loaded?.organizations?.[0].localName).toBe("My Org");
      expect(loaded?.defaultOrgId).toBe("550e8400-e29b-41d4-a716-446655440000");
    });

    it("should store and load account with multiple organizations", async () => {
      const account = await mockStoredAccount({
        organizations: [
          {
            organizationId: "org-1",
            orgEmojiIndex: 10,
            userEmojiIndex: 0,
            role: "owner",
            tier: "enterprise",
            memberCount: 10,
          },
          {
            organizationId: "org-2",
            orgEmojiIndex: 300,
            userEmojiIndex: 1,
            role: "member",
            tier: "free",
            memberCount: 3,
          },
        ],
      });
      await storeAccount(account);

      const loaded = await loadAccount(account.userId);
      expect(loaded?.organizations).toHaveLength(2);
      expect(loaded?.defaultOrgId).toBeUndefined();
    });

    it("should handle account without organizations (v1 compatible)", async () => {
      const account = await mockStoredAccount();
      await storeAccount(account);

      const loaded = await loadAccount(account.userId);
      expect(loaded?.organizations).toBeUndefined();
      expect(loaded?.defaultOrgId).toBeUndefined();
    });
  });

  describe("Edge Cases", () => {
    it("should handle accounts with empty devices array", async () => {
      const account = await mockStoredAccount({ devices: [] });
      await storeAccount(account);

      const loaded = await loadAccount(account.userId);
      expect(loaded?.devices).toEqual([]);
    });

    it("should handle accounts with multiple devices", async () => {
      const devices = [
        await mockUserDevice({ deviceName: "iPhone", isPrimary: true }),
        await mockUserDevice({ deviceName: "iPad", isPrimary: false }),
        await mockUserDevice({ deviceName: "Mac", isPrimary: false }),
      ];
      const account = await mockStoredAccount({ devices });
      await storeAccount(account);

      const loaded = await loadAccount(account.userId);
      expect(loaded?.devices).toHaveLength(3);
    });

    it("should handle concurrent store operations", async () => {
      const account1 = await mockStoredAccount();
      const account2 = await mockStoredAccount();
      const account3 = await mockStoredAccount();
      const account4 = await mockStoredAccount();

      // Store all concurrently
      await Promise.all([
        storeAccount(account1),
        storeAccount(account2),
        storeAccount(account3),
        storeAccount(account4),
      ]);

      // Verify all stored
      expect(await loadAccount(account1.userId)).not.toBeNull();
      expect(await loadAccount(account2.userId)).not.toBeNull();
      expect(await loadAccount(account3.userId)).not.toBeNull();
      expect(await loadAccount(account4.userId)).not.toBeNull();
    });

    it("should handle concurrent read operations", async () => {
      const account1 = await mockStoredAccount();
      const account2 = await mockStoredAccount();
      await storeAccount(account1);
      await storeAccount(account2);

      // Read all concurrently
      const [loadedAccount1, loadedAccount2, accounts] = await Promise.all([
        loadAccount(account1.userId),
        loadAccount(account2.userId),
        listAccounts(),
      ]);

      expect(loadedAccount1).not.toBeNull();
      expect(loadedAccount2).not.toBeNull();
      expect(accounts).toHaveLength(2);
    });
  });
});
