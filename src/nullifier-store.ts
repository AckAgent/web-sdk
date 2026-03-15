/**
 * Nullifier store for anonymous attestation replay prevention.
 *
 * Supports atomic `checkAndMarkSpent(scope, pseudonym, ttl)` semantics via
 * pluggable adapters so browser and server deployments can use appropriate
 * storage backends.
 */

/** Stored nullifier entry. */
interface NullifierEntry {
  nullifier: string;
  scope: string;
  spentAt: number;
  expiresAt: number;
}

/**
 * Adapter contract for nullifier persistence.
 *
 * `checkAndMarkSpent` must be atomic for production replay protection.
 * Return `true` when already spent, `false` when newly marked.
 */
export interface NullifierStoreAdapter {
  /**
   * Atomically check if the nullifier is already spent and mark it if not.
   *
   * @param scope - Replay scope (for example request ID)
   * @param nullifier - Nullifier value (for example pseudonym hex)
   * @param ttlMs - Time-to-live in milliseconds
   * @returns true if already spent, false if newly marked
   */
  checkAndMarkSpent(
    scope: string,
    nullifier: string,
    ttlMs: number,
  ): boolean | Promise<boolean>;

  /** Optional legacy lookup helper. */
  isSpent?(scope: string, nullifier: string): boolean;
  /** Optional legacy mark helper. */
  markSpent?(scope: string, nullifier: string, ttlMs: number): void;
  /** Optional listing helper. */
  getSpentForScope?(scope: string): string[];
  /** Optional clear helper. */
  clear?(): void;
  /** Optional size helper. */
  size?(): number;
}

/**
 * NullifierStore construction options.
 */
export interface NullifierStoreOptions {
  /** Optional custom adapter (Redis/DB/etc). */
  adapter?: NullifierStoreAdapter;
  /** localStorage key for browser persistence (default: ackagent_nullifiers). */
  storageKey?: string;
  /** Default nullifier TTL in milliseconds (default: 4 weeks). */
  defaultTTLMs?: number;
}

/**
 * In-memory adapter for Node.js/server and tests.
 *
 * Atomicity scope: single process.
 */
class InMemoryNullifierStoreAdapter implements NullifierStoreAdapter {
  protected store: Map<string, NullifierEntry> = new Map();

  checkAndMarkSpent(scope: string, nullifier: string, ttlMs: number): boolean {
    this.evictExpired();
    const key = this.makeKey(scope, nullifier);
    if (this.store.has(key)) {
      return true;
    }

    const now = Date.now();
    this.store.set(key, {
      nullifier,
      scope,
      spentAt: now,
      expiresAt: now + ttlMs,
    });

    this.onStoreChanged();
    return false;
  }

  isSpent(scope: string, nullifier: string): boolean {
    this.evictExpired();
    return this.store.has(this.makeKey(scope, nullifier));
  }

  markSpent(scope: string, nullifier: string, ttlMs: number): void {
    const now = Date.now();
    this.store.set(this.makeKey(scope, nullifier), {
      nullifier,
      scope,
      spentAt: now,
      expiresAt: now + ttlMs,
    });
    this.onStoreChanged();
  }

  getSpentForScope(scope: string): string[] {
    this.evictExpired();
    const result: string[] = [];
    for (const entry of this.store.values()) {
      if (entry.scope === scope) {
        result.push(entry.nullifier);
      }
    }
    return result;
  }

  clear(): void {
    this.store.clear();
    this.onStoreChanged();
  }

  size(): number {
    this.evictExpired();
    return this.store.size;
  }

  /** Hook for persistence adapters. */
  protected onStoreChanged(): void {}

  /** Build a stable key for scope/nullifier pair. */
  protected makeKey(scope: string, nullifier: string): string {
    return `${scope}:${nullifier}`;
  }

  /** Remove expired entries. */
  protected evictExpired(): void {
    const now = Date.now();
    let changed = false;

    for (const [key, entry] of this.store) {
      if (entry.expiresAt <= now) {
        this.store.delete(key);
        changed = true;
      }
    }

    if (changed) {
      this.onStoreChanged();
    }
  }
}

/**
 * localStorage-backed adapter for browser runtimes.
 *
 * Atomicity scope: best-effort per browser profile. Cross-tab races are still
 * possible because localStorage has no distributed compare-and-set primitive.
 */
class LocalStorageNullifierStoreAdapter extends InMemoryNullifierStoreAdapter {
  private readonly storageKey: string;

  constructor(storageKey: string) {
    super();
    this.storageKey = storageKey;
    this.loadFromStorage();
  }

  protected override onStoreChanged(): void {
    this.saveToStorage();
  }

  private loadFromStorage(): void {
    try {
      if (typeof localStorage === "undefined") {
        return;
      }

      const raw = localStorage.getItem(this.storageKey);
      if (!raw) {
        return;
      }

      const entries = JSON.parse(raw) as NullifierEntry[];
      const now = Date.now();
      for (const entry of entries) {
        if (entry.expiresAt > now) {
          this.store.set(this.makeKey(entry.scope, entry.nullifier), entry);
        }
      }
    } catch {
      // Ignore storage errors (SSR, private browsing, quota limits, etc.)
    }
  }

  private saveToStorage(): void {
    try {
      if (typeof localStorage === "undefined") {
        return;
      }
      localStorage.setItem(
        this.storageKey,
        JSON.stringify(Array.from(this.store.values())),
      );
    } catch {
      // Ignore storage errors
    }
  }
}

/**
 * Create an in-memory adapter suitable for Node.js and unit tests.
 *
 * @returns In-memory nullifier adapter
 */
export function createInMemoryNullifierStoreAdapter(): NullifierStoreAdapter {
  return new InMemoryNullifierStoreAdapter();
}

/**
 * Create a browser localStorage adapter.
 *
 * @param storageKey - localStorage key (default: ackagent_nullifiers)
 * @returns localStorage-backed adapter
 */
export function createLocalStorageNullifierStoreAdapter(
  storageKey = "ackagent_nullifiers",
): NullifierStoreAdapter {
  return new LocalStorageNullifierStoreAdapter(storageKey);
}

/**
 * Create a minimal adapter from an atomic callback.
 *
 * This is useful for Redis/DB-backed stores where the app provides
 * `checkAndMarkSpent` using backend-native compare-and-set semantics.
 *
 * @param checkAndMarkSpent - Atomic callback implementation
 * @returns Callback-backed adapter
 */
export function createAtomicNullifierStoreAdapter(
  checkAndMarkSpent: NullifierStoreAdapter["checkAndMarkSpent"],
): NullifierStoreAdapter {
  return {
    checkAndMarkSpent,
  };
}

/**
 * NullifierStore tracks spent nullifiers for replay detection.
 */
export class NullifierStore {
  private readonly adapter: NullifierStoreAdapter;
  private readonly defaultTTLMs: number;

  /**
   * Create a nullifier store.
   *
   * Backward compatible signatures:
   * - `new NullifierStore(storageKey?, defaultTTLMs?)`
   * - `new NullifierStore({ adapter, storageKey, defaultTTLMs })`
   *
   * @param configOrStorageKey - Options object or localStorage key
   * @param defaultTTLMs - Default TTL in milliseconds (legacy signature)
   */
  constructor(
    configOrStorageKey: NullifierStoreOptions | string = "ackagent_nullifiers",
    defaultTTLMs = 4 * 7 * 24 * 60 * 60 * 1000,
  ) {
    const options = normalizeOptions(configOrStorageKey, defaultTTLMs);

    this.defaultTTLMs = options.defaultTTLMs;

    if (options.adapter) {
      this.adapter = options.adapter;
      return;
    }

    if (typeof localStorage !== "undefined") {
      this.adapter = createLocalStorageNullifierStoreAdapter(
        options.storageKey,
      );
    } else {
      this.adapter = createInMemoryNullifierStoreAdapter();
    }
  }

  /**
   * Atomically check and mark a nullifier as spent.
   *
   * @param scope - Replay scope
   * @param nullifier - Nullifier value
   * @param ttlMs - Optional TTL override in milliseconds
   * @returns true if already spent, false if newly marked
   */
  async checkAndMarkSpent(
    scope: string,
    nullifier: string,
    ttlMs?: number,
  ): Promise<boolean> {
    return this.adapter.checkAndMarkSpent(
      scope,
      nullifier,
      ttlMs ?? this.defaultTTLMs,
    );
  }

  /**
   * Check if a nullifier has been spent for the given scope.
   *
   * Legacy convenience method for adapters that expose direct lookups.
   * For production replay protection, prefer `checkAndMarkSpent`.
   *
   * @param scope - Scope to check
   * @param nullifier - Nullifier value
   * @returns Whether the nullifier is already spent
   */
  isSpent(scope: string, nullifier: string): boolean {
    if (!this.adapter.isSpent) {
      throw new Error(
        "adapter does not support isSpent(); use checkAndMarkSpent()",
      );
    }
    return this.adapter.isSpent(scope, nullifier);
  }

  /**
   * Mark a nullifier as spent.
   *
   * Legacy convenience method for adapters that expose direct writes.
   * For production replay protection, prefer `checkAndMarkSpent`.
   *
   * @param scope - Scope for the nullifier
   * @param nullifier - Nullifier value
   * @param ttlMs - Optional TTL override in milliseconds
   */
  markSpent(scope: string, nullifier: string, ttlMs?: number): void {
    if (!this.adapter.markSpent) {
      throw new Error(
        "adapter does not support markSpent(); use checkAndMarkSpent()",
      );
    }
    this.adapter.markSpent(scope, nullifier, ttlMs ?? this.defaultTTLMs);
  }

  /**
   * Get all spent nullifiers for a scope.
   *
   * @param scope - Scope to query
   * @returns Spent nullifiers for the scope
   */
  getSpentForScope(scope: string): string[] {
    if (!this.adapter.getSpentForScope) {
      return [];
    }
    return this.adapter.getSpentForScope(scope);
  }

  /**
   * Clear all stored nullifiers.
   */
  clear(): void {
    this.adapter.clear?.();
  }

  /**
   * Number of stored nullifiers (when supported by the adapter).
   */
  get size(): number {
    return this.adapter.size ? this.adapter.size() : 0;
  }
}

/**
 * Create a nullifier store using default browser/server adapter selection.
 *
 * @param storageKey - Optional localStorage key for persistence
 * @returns NullifierStore instance
 */
export function createNullifierStore(storageKey?: string): NullifierStore {
  return new NullifierStore(storageKey);
}

/**
 * Normalize constructor input into a concrete options object.
 *
 * @param configOrStorageKey - Constructor input
 * @param defaultTTLMs - Legacy default TTL
 * @returns Normalized options
 */
function normalizeOptions(
  configOrStorageKey: NullifierStoreOptions | string,
  defaultTTLMs: number,
): Required<Pick<NullifierStoreOptions, "storageKey" | "defaultTTLMs">> &
  Pick<NullifierStoreOptions, "adapter"> {
  if (typeof configOrStorageKey === "string") {
    return {
      adapter: undefined,
      storageKey: configOrStorageKey,
      defaultTTLMs,
    };
  }

  return {
    adapter: configOrStorageKey.adapter,
    storageKey: configOrStorageKey.storageKey ?? "ackagent_nullifiers",
    defaultTTLMs: configOrStorageKey.defaultTTLMs ?? defaultTTLMs,
  };
}
