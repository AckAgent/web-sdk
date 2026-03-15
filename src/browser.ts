/**
 * Browser environment detection and metadata collection
 */

import type { BrowserMetadata } from "./generated/protocol.js";

/**
 * Check if running in a browser environment.
 * Returns false for Node.js, Deno, or other non-browser environments.
 */
export function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.document !== "undefined" &&
    typeof window.location !== "undefined"
  );
}

/**
 * Collect browser metadata from the current environment.
 * This metadata is automatically included in web approval requests.
 *
 * @returns Browser metadata object with URL, origin, title, user agent, etc.
 * @throws Error if not running in a browser environment
 *
 * @example
 * ```typescript
 * const metadata = collectBrowserMetadata();
 * console.log(metadata.origin); // "https://example.com"
 * console.log(metadata.pageTitle); // "My Web App"
 * ```
 */
export function collectBrowserMetadata(): BrowserMetadata {
  if (!isBrowser()) {
    throw new Error(
      "collectBrowserMetadata() can only be called in a browser environment",
    );
  }

  return {
    url: window.location.href,
    origin: window.location.origin,
    pageTitle: document.title || undefined,
    userAgent: navigator.userAgent || undefined,
    referrer: document.referrer || undefined,
    timestamp: new Date().toISOString(),
  };
}
