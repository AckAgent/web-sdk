/**
 * IndexedDB storage for CryptoKey objects
 *
 * This module provides persistent storage for non-extractable CryptoKey objects
 * using IndexedDB's structured cloning capability.
 */

import type { StoredAccount, UserDevice, UserOrganization } from "./types.js";

const DB_NAME = "ackagent-keys";
const DB_VERSION = 2;

// Store names
const ACCOUNTS_STORE = "accounts";

/** Internal account structure for IndexedDB storage */
interface StoredAccountRecord {
  userId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: string; // ISO date string
  loggedInAt: string; // ISO date string
  sasVerified: boolean;
  devices: SerializedDevice[];
  identityPrivateKey: CryptoKey; // Non-extractable
  identityPublicKey: Uint8Array;
  relayUrl: string;
  organizations?: UserOrganization[];
  defaultOrgId?: string;
}

/** Serialized device (public keys stay as Uint8Array) */
interface SerializedDevice {
  deviceId: string;
  deviceName: string;
  publicKey: Uint8Array;
  isPrimary: boolean;
}

let dbPromise: Promise<IDBDatabase> | null = null;

// MARK: - Database Helpers

/**
 * Execute an IndexedDB transaction operation with standard error handling.
 * @param storeName - The object store name
 * @param mode - Transaction mode ('readonly' or 'readwrite')
 * @param operation - Function that receives the store and returns an IDBRequest
 * @param errorMessage - Error message prefix for failures
 * @param transform - Optional transform function for the result
 */
async function withTransaction<T>(
  storeName: string,
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest,
  errorMessage: string,
  transform?: (result: unknown) => T,
): Promise<T> {
  const db = await openDatabase();
  return new Promise<T>((resolve, reject) => {
    const transaction = db.transaction(storeName, mode);
    const store = transaction.objectStore(storeName);
    const request = operation(store);
    request.onerror = () =>
      reject(new Error(`${errorMessage}: ${request.error?.message}`));
    request.onsuccess = () => {
      const result = transform
        ? transform(request.result)
        : (request.result as T);
      resolve(result);
    };
  });
}

// MARK: - Record Transformations

/** Convert a stored account record to domain model */
function recordToAccount(record: StoredAccountRecord): StoredAccount {
  return {
    userId: record.userId,
    accessToken: record.accessToken,
    refreshToken: record.refreshToken,
    expiresAt: new Date(record.expiresAt),
    loggedInAt: new Date(record.loggedInAt),
    sasVerified: record.sasVerified,
    devices: record.devices.map(
      (d): UserDevice => ({
        deviceId: d.deviceId,
        deviceName: d.deviceName,
        publicKey: d.publicKey,
        isPrimary: d.isPrimary,
      }),
    ),
    identityPrivateKey: record.identityPrivateKey,
    identityPublicKey: record.identityPublicKey,
    relayUrl: record.relayUrl,
    organizations: record.organizations,
    defaultOrgId: record.defaultOrgId,
  };
}

/**
 * Open the IndexedDB database, creating stores if needed
 */
export async function openDatabase(): Promise<IDBDatabase> {
  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      dbPromise = null;
      reject(new Error(`Failed to open database: ${request.error?.message}`));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create accounts store with userId as key
      if (!db.objectStoreNames.contains(ACCOUNTS_STORE)) {
        db.createObjectStore(ACCOUNTS_STORE, { keyPath: "userId" });
      }

      // v1 -> v2: Added organizations and defaultOrgId fields to accounts.
      // No schema migration needed - new fields are optional and existing
      // records will return undefined for them via recordToAccount().
    };
  });

  return dbPromise;
}

/**
 * Store an account in IndexedDB
 */
export async function storeAccount(account: StoredAccount): Promise<void> {
  const record: StoredAccountRecord = {
    userId: account.userId,
    accessToken: account.accessToken,
    refreshToken: account.refreshToken,
    expiresAt: account.expiresAt.toISOString(),
    loggedInAt: account.loggedInAt.toISOString(),
    sasVerified: account.sasVerified,
    devices: account.devices.map((d) => ({
      deviceId: d.deviceId,
      deviceName: d.deviceName,
      publicKey: d.publicKey,
      isPrimary: d.isPrimary,
    })),
    identityPrivateKey: account.identityPrivateKey,
    identityPublicKey: account.identityPublicKey,
    relayUrl: account.relayUrl,
    organizations: account.organizations,
    defaultOrgId: account.defaultOrgId,
  };

  await withTransaction<void>(
    ACCOUNTS_STORE,
    "readwrite",
    (store) => store.put(record),
    "Failed to store account",
  );
}

/**
 * Load an account from IndexedDB
 */
export async function loadAccount(
  userId: string,
): Promise<StoredAccount | null> {
  return withTransaction<StoredAccount | null>(
    ACCOUNTS_STORE,
    "readonly",
    (store) => store.get(userId),
    "Failed to load account",
    (result) => {
      const record = result as StoredAccountRecord | undefined;
      return record ? recordToAccount(record) : null;
    },
  );
}

/**
 * Delete an account from IndexedDB
 */
export async function deleteAccount(userId: string): Promise<void> {
  await withTransaction<void>(
    ACCOUNTS_STORE,
    "readwrite",
    (store) => store.delete(userId),
    "Failed to delete account",
  );
}

/**
 * List all stored accounts
 */
export async function listAccounts(): Promise<StoredAccount[]> {
  return withTransaction<StoredAccount[]>(
    ACCOUNTS_STORE,
    "readonly",
    (store) => store.getAll(),
    "Failed to list accounts",
    (result) => (result as StoredAccountRecord[]).map(recordToAccount),
  );
}

/**
 * Clear all stored data (accounts)
 */
export async function clearAllData(): Promise<void> {
  const db = await openDatabase();

  return new Promise<void>((resolve, reject) => {
    const transaction = db.transaction([ACCOUNTS_STORE], "readwrite");

    transaction.onerror = () =>
      reject(new Error(`Failed to clear data: ${transaction.error?.message}`));
    transaction.oncomplete = () => resolve();

    transaction.objectStore(ACCOUNTS_STORE).clear();
  });
}

/**
 * Check if IndexedDB is available
 */
export function isIndexedDBAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}
