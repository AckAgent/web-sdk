/**
 * Transport manager for routing requests through multiple transports.
 * Tries transports in priority order with automatic fallback.
 */

import type { PollConfig } from "../client.js";
import type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "./types.js";
import { TransportError } from "./types.js";

/**
 * Error thrown when no transports are registered
 */
export class NoTransportsError extends Error {
  constructor() {
    super("No transports registered");
    this.name = "NoTransportsError";
  }
}

/**
 * Error thrown when all transports fail
 */
export class AllTransportsFailedError extends Error {
  constructor(public readonly lastError: Error) {
    super(`All transports failed: ${lastError.message}`);
    this.name = "AllTransportsFailedError";
  }
}

/**
 * Manager for multiple transports
 */
export class TransportManager {
  private transports: Transport[] = [];
  private sorted = false;

  /**
   * Register a transport with the manager.
   * Transports are tried in priority order (lower = higher priority).
   */
  register(transport: Transport): void {
    this.transports.push(transport);
    this.sorted = false;
  }

  /**
   * Get all registered transports in priority order
   */
  getTransports(): Transport[] {
    this.ensureSorted();
    return [...this.transports];
  }

  /**
   * Ensure transports are sorted by priority
   */
  private ensureSorted(): void {
    if (this.sorted) return;
    this.transports.sort((a, b) => a.priority - b.priority);
    this.sorted = true;
  }

  /**
   * Send a request using the first available transport.
   * Falls back to next transport on failure.
   */
  async send(
    request: TransportRequest,
    timeoutMs: number,
    pollConfig?: PollConfig,
  ): Promise<TransportResponse> {
    if (this.transports.length === 0) {
      throw new NoTransportsError();
    }

    this.ensureSorted();
    let lastError: Error | undefined;

    for (const transport of this.transports) {
      // Check availability
      try {
        const available = await transport.isAvailable();
        if (!available) {
          console.debug(`[Transport] ${transport.name} not available`);
          continue;
        }
      } catch (err) {
        console.debug(
          `[Transport] ${transport.name} availability check failed:`,
          err,
        );
        continue;
      }

      console.debug(
        `[Transport] Trying ${transport.name} (priority ${transport.priority})`,
      );

      try {
        const response = await transport.send(request, timeoutMs, pollConfig);
        console.debug(`[Transport] ${transport.name} succeeded`);
        return response;
      } catch (err) {
        lastError = new TransportError(transport.name, err as Error);
        console.debug(`[Transport] ${transport.name} failed:`, err);
      }
    }

    if (lastError) {
      throw new AllTransportsFailedError(lastError);
    }
    throw new NoTransportsError();
  }

  /**
   * Send with preference for a specific transport.
   * Falls back to standard priority order if preferred transport is unavailable.
   */
  async sendWithPreference(
    request: TransportRequest,
    timeoutMs: number,
    preferredName: string,
    pollConfig?: PollConfig,
  ): Promise<TransportResponse> {
    // Try preferred transport first
    const preferred = this.transports.find((t) => t.name === preferredName);
    if (preferred) {
      try {
        const available = await preferred.isAvailable();
        if (available) {
          console.debug(
            `[Transport] Using preferred transport ${preferredName}`,
          );
          const response = await preferred.send(request, timeoutMs, pollConfig);
          return response;
        }
      } catch {
        console.debug(
          `[Transport] Preferred transport ${preferredName} failed`,
        );
      }
    }

    // Fall back to standard priority order
    return this.send(request, timeoutMs, pollConfig);
  }

  /**
   * Check which transports are currently available
   */
  async checkAvailability(): Promise<Map<string, boolean>> {
    const result = new Map<string, boolean>();
    for (const transport of this.transports) {
      try {
        result.set(transport.name, await transport.isAvailable());
      } catch {
        result.set(transport.name, false);
      }
    }
    return result;
  }
}
