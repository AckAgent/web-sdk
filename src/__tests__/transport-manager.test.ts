/**
 * Tests for TransportManager: priority-based routing, fallback behavior,
 * preferred transport selection, and availability checking.
 */

import { vi, describe, it, expect, beforeEach } from "vitest";
import {
  TransportManager,
  NoTransportsError,
  AllTransportsFailedError,
} from "../transport/manager.js";
import type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "../transport/types.js";

function createMockTransport(
  name: string,
  priority: number,
  available = true,
): Transport {
  return {
    name,
    priority,
    isAvailable: vi.fn().mockResolvedValue(available),
    send: vi.fn().mockResolvedValue({
      id: "test",
      status: "responded",
      expiresAt: "",
    } as TransportResponse),
  };
}

const mockRequest: TransportRequest = {
  id: "req-1",
  pairingId: "pair-1",
  ephemeralPublic: new Uint8Array(33),
  encryptedPayload: new Uint8Array(32),
  payloadNonce: new Uint8Array(12),
  expiresIn: 300,
  timestamp: Date.now(),
};

describe("NoTransportsError", () => {
  it("sets name and message", () => {
    const err = new NoTransportsError();
    expect(err.name).toBe("NoTransportsError");
    expect(err.message).toBe("No transports registered");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("AllTransportsFailedError", () => {
  it("sets name, message, and stores lastError", () => {
    const cause = new Error("connection lost");
    const err = new AllTransportsFailedError(cause);
    expect(err.name).toBe("AllTransportsFailedError");
    expect(err.message).toBe("All transports failed: connection lost");
    expect(err.lastError).toBe(cause);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("TransportManager", () => {
  let manager: TransportManager;

  beforeEach(() => {
    manager = new TransportManager();
  });

  describe("register / getTransports", () => {
    it("returns transports sorted by priority (lower = higher priority)", () => {
      const low = createMockTransport("low", 10);
      const high = createMockTransport("high", 1);
      const mid = createMockTransport("mid", 5);

      manager.register(low);
      manager.register(high);
      manager.register(mid);

      const transports = manager.getTransports();
      expect(transports.map((t) => t.name)).toEqual(["high", "mid", "low"]);
    });

    it("returns an empty array when no transports registered", () => {
      expect(manager.getTransports()).toEqual([]);
    });
  });

  describe("send", () => {
    it("throws NoTransportsError when no transports registered", async () => {
      await expect(manager.send(mockRequest, 5000)).rejects.toThrow(
        NoTransportsError,
      );
    });

    it("uses the first available transport by priority", async () => {
      const high = createMockTransport("high", 1);
      const low = createMockTransport("low", 10);

      manager.register(low);
      manager.register(high);

      await manager.send(mockRequest, 5000);

      expect(high.send).toHaveBeenCalledWith(mockRequest, 5000, undefined);
      expect(low.send).not.toHaveBeenCalled();
    });

    it("skips unavailable transports", async () => {
      const unavailable = createMockTransport("unavail", 1, false);
      const available = createMockTransport("avail", 5);

      manager.register(unavailable);
      manager.register(available);

      await manager.send(mockRequest, 5000);

      expect(unavailable.send).not.toHaveBeenCalled();
      expect(available.send).toHaveBeenCalled();
    });

    it("falls back to next transport on send failure", async () => {
      const primary = createMockTransport("primary", 1);
      (primary.send as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("send failed"),
      );
      const backup = createMockTransport("backup", 5);

      manager.register(primary);
      manager.register(backup);

      const response = await manager.send(mockRequest, 5000);

      expect(primary.send).toHaveBeenCalled();
      expect(backup.send).toHaveBeenCalled();
      expect(response.status).toBe("responded");
    });

    it("throws AllTransportsFailedError when all transports fail", async () => {
      const t1 = createMockTransport("t1", 1);
      (t1.send as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("fail 1"),
      );
      const t2 = createMockTransport("t2", 2);
      (t2.send as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("fail 2"),
      );

      manager.register(t1);
      manager.register(t2);

      await expect(manager.send(mockRequest, 5000)).rejects.toThrow(
        AllTransportsFailedError,
      );
    });

    it("handles isAvailable() throwing an exception", async () => {
      const throwing = createMockTransport("throwing", 1);
      (throwing.isAvailable as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("check failed"),
      );
      const fallback = createMockTransport("fallback", 5);

      manager.register(throwing);
      manager.register(fallback);

      const response = await manager.send(mockRequest, 5000);

      expect(throwing.send).not.toHaveBeenCalled();
      expect(fallback.send).toHaveBeenCalled();
      expect(response.status).toBe("responded");
    });

    it("throws NoTransportsError when all transports are unavailable and none fail send", async () => {
      const t1 = createMockTransport("t1", 1, false);
      const t2 = createMockTransport("t2", 2, false);

      manager.register(t1);
      manager.register(t2);

      await expect(manager.send(mockRequest, 5000)).rejects.toThrow(
        NoTransportsError,
      );
    });
  });

  describe("sendWithPreference", () => {
    it("tries the preferred transport first", async () => {
      const high = createMockTransport("high", 1);
      const preferred = createMockTransport("preferred", 10);

      manager.register(high);
      manager.register(preferred);

      await manager.sendWithPreference(mockRequest, 5000, "preferred");

      expect(preferred.send).toHaveBeenCalled();
      expect(high.send).not.toHaveBeenCalled();
    });

    it("falls back to priority order when preferred is unavailable", async () => {
      const preferred = createMockTransport("preferred", 10, false);
      const fallback = createMockTransport("fallback", 1);

      manager.register(preferred);
      manager.register(fallback);

      await manager.sendWithPreference(mockRequest, 5000, "preferred");

      expect(preferred.send).not.toHaveBeenCalled();
      expect(fallback.send).toHaveBeenCalled();
    });

    it("falls back when preferred transport send fails", async () => {
      const preferred = createMockTransport("preferred", 10);
      (preferred.send as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("preferred failed"),
      );
      const fallback = createMockTransport("fallback", 1);

      manager.register(preferred);
      manager.register(fallback);

      const response = await manager.sendWithPreference(
        mockRequest,
        5000,
        "preferred",
      );

      expect(preferred.send).toHaveBeenCalled();
      expect(fallback.send).toHaveBeenCalled();
      expect(response.status).toBe("responded");
    });

    it("falls back when preferred transport name is not found", async () => {
      const t1 = createMockTransport("t1", 1);

      manager.register(t1);

      await manager.sendWithPreference(mockRequest, 5000, "nonexistent");

      expect(t1.send).toHaveBeenCalled();
    });
  });

  describe("checkAvailability", () => {
    it("returns a map of transport availability", async () => {
      const available = createMockTransport("avail", 1, true);
      const unavailable = createMockTransport("unavail", 2, false);

      manager.register(available);
      manager.register(unavailable);

      const result = await manager.checkAvailability();

      expect(result.get("avail")).toBe(true);
      expect(result.get("unavail")).toBe(false);
    });

    it("catches isAvailable exceptions and reports false", async () => {
      const throwing = createMockTransport("throwing", 1);
      (throwing.isAvailable as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("boom"),
      );

      manager.register(throwing);

      const result = await manager.checkAvailability();

      expect(result.get("throwing")).toBe(false);
    });
  });
});
