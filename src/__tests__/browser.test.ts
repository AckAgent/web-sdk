/**
 * Tests for browser environment detection and metadata collection
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// We can't easily mock browser globals in Node.js, so we'll test the module behavior
// In real browser environments, collectBrowserMetadata would work correctly

describe("browser module", () => {
  describe("isBrowser", () => {
    it("should return false in Node.js environment", async () => {
      // Reset module cache to get fresh import
      vi.resetModules();
      const { isBrowser } = await import("../browser.js");
      // In vitest (Node.js), there's no real window/document
      expect(isBrowser()).toBe(false);
    });
  });

  describe("collectBrowserMetadata", () => {
    it("should throw when not in browser environment", async () => {
      vi.resetModules();
      const { collectBrowserMetadata } = await import("../browser.js");
      expect(() => collectBrowserMetadata()).toThrow(
        "collectBrowserMetadata() can only be called in a browser environment",
      );
    });
  });

  describe("BrowserMetadata type", () => {
    it("should have the expected structure", async () => {
      // We can verify the exported types by importing and checking
      // This ensures the module exports what we expect
      const { isBrowser, collectBrowserMetadata } = await import(
        "../browser.js"
      );

      expect(typeof isBrowser).toBe("function");
      expect(typeof collectBrowserMetadata).toBe("function");
    });
  });
});

describe("browser module with mocked environment", () => {
  // Use vi.mock to properly mock the module for browser simulation
  // This tests that the functions work when browser APIs are available

  beforeEach(() => {
    // Mock window, document, and navigator at the global level
    vi.stubGlobal("window", {
      location: {
        href: "https://example.com/checkout?item=123",
        origin: "https://example.com",
      },
      document: {},
    });

    vi.stubGlobal("document", {
      title: "Checkout Page",
      referrer: "https://example.com/cart",
    });

    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Test Browser)",
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("should return true for isBrowser() when browser globals exist", async () => {
    // Need to re-import after mocking to pick up the mocked globals
    vi.resetModules();
    const { isBrowser } = await import("../browser.js");
    expect(isBrowser()).toBe(true);
  });

  it("should collect metadata from browser globals", async () => {
    vi.resetModules();
    const { collectBrowserMetadata } = await import("../browser.js");

    const metadata = collectBrowserMetadata();

    expect(metadata.url).toBe("https://example.com/checkout?item=123");
    expect(metadata.origin).toBe("https://example.com");
    expect(metadata.pageTitle).toBe("Checkout Page");
    expect(metadata.userAgent).toBe("Mozilla/5.0 (Test Browser)");
    expect(metadata.referrer).toBe("https://example.com/cart");
    expect(metadata.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it("should handle missing optional fields", async () => {
    // Update mocks to have empty optional fields
    vi.stubGlobal("document", {
      title: "",
      referrer: "",
    });

    vi.stubGlobal("navigator", {
      userAgent: "",
    });

    vi.resetModules();
    const { collectBrowserMetadata } = await import("../browser.js");

    const metadata = collectBrowserMetadata();

    expect(metadata.url).toBe("https://example.com/checkout?item=123");
    expect(metadata.origin).toBe("https://example.com");
    expect(metadata.pageTitle).toBeUndefined();
    expect(metadata.userAgent).toBeUndefined();
    expect(metadata.referrer).toBeUndefined();
    expect(metadata.timestamp).toBeDefined();
  });
});
