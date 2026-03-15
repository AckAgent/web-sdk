import { describe, it, expect, vi, afterEach } from "vitest";
import { base64Decode, base64Encode, hexEncode } from "../encoding.js";
import {
  BluetoothTransport,
  REQUEST_CHARACTERISTIC_UUID,
  RESPONSE_CHARACTERISTIC_UUID,
  ACKAGENT_SERVICE_UUID,
  STATUS_CHARACTERISTIC_UUID,
  isWebBluetoothSupported,
  createBluetoothTransport,
  type BluetoothTransportOptions,
} from "../transport/local/bluetooth.js";
import {
  BLEFragmenter,
  BLEReassembler,
  decodeFragment,
  encodeFragment,
} from "../transport/local/fragmentation.js";
import type { TransportRequest } from "../transport/types.js";

type MockBluetoothDevice = NonNullable<BluetoothTransportOptions["device"]>;

class MockCharacteristic extends EventTarget {
  readonly uuid: string;
  value?: DataView;
  writes: Uint8Array[] = [];
  onCompleteMessage?: (data: Uint8Array) => void;
  private readonly reassembler = new BLEReassembler();
  constructor(uuid: string) {
    super();
    this.uuid = uuid;
  }
  async writeValue(value: BufferSource): Promise<void> {
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(
            (value as ArrayBufferView).buffer,
            (value as ArrayBufferView).byteOffset,
            (value as ArrayBufferView).byteLength,
          );
    this.writes.push(bytes);
    const fragment = decodeFragment(bytes);
    if (!fragment) return;
    const complete = this.reassembler.addFragment(fragment);
    if (complete) this.onCompleteMessage?.(complete);
  }
  async startNotifications() {
    return this;
  }
  async stopNotifications() {
    return this;
  }
  notify(data: Uint8Array): void {
    this.value = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.dispatchEvent(new Event("characteristicvaluechanged"));
  }
  addEventListener(type: string, listener: (event: Event) => void): void {
    super.addEventListener(type, listener as EventListener);
  }
  removeEventListener(type: string, listener: (event: Event) => void): void {
    super.removeEventListener(type, listener as EventListener);
  }
}

class MockServer {
  connected = true;
  constructor(private readonly svc: MockService) {}
  async getPrimaryService(s: string): Promise<MockService> {
    if (s !== ACKAGENT_SERVICE_UUID) throw new Error(`Unknown service ${s}`);
    return this.svc;
  }
  disconnect(): void {
    this.connected = false;
  }
}

class MockService {
  constructor(
    private readonly req: MockCharacteristic,
    private readonly res: MockCharacteristic,
  ) {}
  async getCharacteristic(c: string): Promise<MockCharacteristic> {
    if (c === REQUEST_CHARACTERISTIC_UUID) return this.req;
    if (c === RESPONSE_CHARACTERISTIC_UUID) return this.res;
    throw new Error(`Unknown characteristic ${c}`);
  }
}

class MockDevice {
  readonly id = "mock-device";
  readonly name = "Mock iPhone";
  constructor(private readonly server: MockServer) {}
  readonly gatt = {
    connect: async () => this.server,
    disconnect: () => {
      this.server.disconnect();
    },
    get connected() {
      return this.server.connected;
    },
    server: this.server,
  };
}

function decodeFrame(data: Uint8Array): { type: number; payload: Uint8Array } {
  if (data.length < 6) throw new Error("Frame too short");
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    type: v.getUint16(4, false),
    payload: data.slice(6, 4 + v.getUint32(0, false)),
  };
}

function encodeFrame(type: number, payload: Uint8Array): Uint8Array {
  const result = new Uint8Array(6 + payload.length);
  const v = new DataView(result.buffer);
  v.setUint32(0, 2 + payload.length, false);
  v.setUint16(4, type, false);
  result.set(payload, 6);
  return result;
}

function setup(options?: { debug?: boolean }) {
  const reqChar = new MockCharacteristic(REQUEST_CHARACTERISTIC_UUID);
  const resChar = new MockCharacteristic(RESPONSE_CHARACTERISTIC_UUID);
  const svc = new MockService(reqChar, resChar);
  const server = new MockServer(svc);
  const device = new MockDevice(server);
  const transport = new BluetoothTransport({
    device: device as MockBluetoothDevice,
    ...options,
  });
  return { transport, reqChar, resChar, server, device };
}

function sendFragmented(
  char: MockCharacteristic,
  json: string,
  msgType = 0x0002,
) {
  const frame = encodeFrame(msgType, new TextEncoder().encode(json));
  for (const f of new BLEFragmenter().fragment(frame))
    char.notify(encodeFragment(f));
}

function notifyBadFrame(char: MockCharacteristic, frame: Uint8Array) {
  for (const f of new BLEFragmenter().fragment(frame))
    char.notify(encodeFragment(f));
}

const mockRequest: TransportRequest = {
  id: "req-123",
  pairingId: "pair-abc",
  keyId: "key-1",
  signingPublicKeyHex: "aabb01",
  ephemeralPublic: new Uint8Array([1, 2, 3, 4]),
  encryptedPayload: new Uint8Array([5, 6, 7, 8]),
  payloadNonce: new Uint8Array([9, 10, 11]),
  expiresIn: 120,
  timestamp: 123456789,
};

function mockResJson(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    id: "req-123",
    status: "responded",
    ephemeralPublic: base64Encode(new Uint8Array([12, 13, 14])),
    encryptedResponse: base64Encode(new Uint8Array([21, 22, 23])),
    responseNonce: base64Encode(new Uint8Array([31, 32, 33])),
    ...overrides,
  });
}

function autoRespond(
  s: ReturnType<typeof setup>,
  overrides: Record<string, unknown> = {},
) {
  s.reqChar.onCompleteMessage = () =>
    sendFragmented(s.resChar, mockResJson(overrides));
}

describe("BluetoothTransport (local)", () => {
  it("encodes requests with camelCase and base64, and parses responses", async () => {
    const s = setup();
    s.reqChar.onCompleteMessage = (data) => {
      const frame = decodeFrame(data);
      expect(frame.type).toBe(0x0001);
      const json = JSON.parse(
        new TextDecoder().decode(frame.payload),
      ) as Record<string, unknown>;
      expect(json.id).toBe(mockRequest.id);
      expect(json.requesterID).toBe(mockRequest.pairingId);
      expect(json.keyID).toBe(mockRequest.keyId);
      expect(json.signingPublicKey).toBe(mockRequest.signingPublicKeyHex);
      expect(json.expiresIn).toBe(mockRequest.expiresIn);
      expect(json.timestamp).toBe(mockRequest.timestamp);
      for (const key of [
        "ephemeralPublic",
        "encryptedPayload",
        "payloadNonce",
      ] as const) {
        expect(Array.from(base64Decode(json[key] as string))).toEqual(
          Array.from(mockRequest[key]),
        );
      }
      sendFragmented(s.resChar, mockResJson());
    };
    const res = await s.transport.send(mockRequest, 1000);
    expect(res.id).toBe(mockRequest.id);
    expect(res.status).toBe("responded");
    expect(Array.from(res.ephemeralPublic ?? [])).toEqual([12, 13, 14]);
    expect(Array.from(res.encryptedResponse ?? [])).toEqual([21, 22, 23]);
    expect(Array.from(res.responseNonce ?? [])).toEqual([31, 32, 33]);
  });
});

describe("isWebBluetoothSupported()", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each([
    [
      "true when navigator.bluetooth exists",
      { bluetooth: { requestDevice: vi.fn(), getAvailability: vi.fn() } },
      true,
    ],
    ["false when navigator is undefined", undefined, false],
    ["false when navigator.bluetooth is undefined", {}, false],
  ])("returns %s", (_desc, nav, expected) => {
    vi.stubGlobal("navigator", nav);
    expect(isWebBluetoothSupported()).toBe(expected);
  });
});

describe("isAvailable()", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each([
    [
      "true when getAvailability returns true",
      { bluetooth: { getAvailability: vi.fn().mockResolvedValue(true) } },
      true,
    ],
    [
      "false when getAvailability returns false",
      { bluetooth: { getAvailability: vi.fn().mockResolvedValue(false) } },
      false,
    ],
    ["false when navigator is undefined", undefined, false],
    [
      "false when getAvailability throws",
      {
        bluetooth: {
          getAvailability: vi.fn().mockRejectedValue(new Error("BLE error")),
        },
      },
      false,
    ],
  ])("returns %s", async (_desc, nav, expected) => {
    vi.stubGlobal("navigator", nav);
    expect(await new BluetoothTransport().isAvailable()).toBe(expected);
  });
});

describe("createBluetoothTransport()", () => {
  it.each([
    ["with defaults", undefined],
    ["with options", { debug: true }],
  ])("creates transport %s", (_desc, opts) => {
    const t = createBluetoothTransport(opts);
    expect(t).toBeInstanceOf(BluetoothTransport);
    if (!opts) expect(t.name).toBe("bluetooth");
  });
});

describe("requestDevice()", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls bluetooth.requestDevice with correct service filter", async () => {
    const fn = vi.fn().mockResolvedValue({ id: "dev-1", name: "Test Phone" });
    vi.stubGlobal("navigator", { bluetooth: { requestDevice: fn } });
    await new BluetoothTransport().requestDevice();
    expect(fn).toHaveBeenCalledWith({
      filters: [{ services: [ACKAGENT_SERVICE_UUID] }],
    });
  });

  it("stores the returned device", async () => {
    vi.stubGlobal("navigator", {
      bluetooth: {
        requestDevice: vi
          .fn()
          .mockResolvedValue({ id: "dev-1", name: "Test Phone" }),
      },
    });
    const device = await new BluetoothTransport().requestDevice();
    expect(device.id).toBe("dev-1");
    expect(device.name).toBe("Test Phone");
  });

  it("throws when no bluetooth API", async () => {
    vi.stubGlobal("navigator", {});
    await expect(new BluetoothTransport().requestDevice()).rejects.toThrow(
      "Web Bluetooth not supported",
    );
  });
});

describe("connect()", () => {
  it("throws when no device selected", async () => {
    await expect(new BluetoothTransport().connect()).rejects.toThrow(
      "No device selected. Call requestDevice() first.",
    );
  });

  it("connects successfully", async () => {
    const s = setup();
    await s.transport.connect();
    expect(s.server.connected).toBe(true);
  });

  it("throws when GATT is undefined on device", async () => {
    const t = new BluetoothTransport({
      device: { id: "no-gatt", name: "Bad" } as MockBluetoothDevice,
    });
    await expect(t.connect()).rejects.toThrow(
      "Failed to connect to GATT server",
    );
  });

  it("starts notifications on response characteristic", async () => {
    const s = setup();
    const spy = vi.spyOn(s.resChar, "startNotifications");
    await s.transport.connect();
    expect(spy).toHaveBeenCalled();
  });

  it("auto-connects when calling send() without prior connect()", async () => {
    const s = setup();
    autoRespond(s);
    expect((await s.transport.send(mockRequest, 1000)).status).toBe(
      "responded",
    );
  });
});

describe("disconnect()", () => {
  it("disconnects and clears state", async () => {
    const s = setup();
    await s.transport.connect();
    expect(s.server.connected).toBe(true);
    s.transport.disconnect();
    expect(s.server.connected).toBe(false);
  });

  it.each([
    ["when not connected", false],
    ["twice after connecting", true],
  ])("safe to call %s", async (_desc, shouldConnect) => {
    if (!shouldConnect) {
      new BluetoothTransport().disconnect();
      return;
    }
    const s = setup();
    await s.transport.connect();
    s.transport.disconnect();
    s.transport.disconnect();
  });
});

describe("send() happy paths", () => {
  it("omits optional fields from request JSON when undefined", async () => {
    const s = setup();
    let captured: Record<string, unknown> = {};
    s.reqChar.onCompleteMessage = (data) => {
      captured = JSON.parse(
        new TextDecoder().decode(decodeFrame(data).payload),
      );
      sendFragmented(s.resChar, mockResJson());
    };
    await s.transport.send(
      {
        id: "req-456",
        pairingId: "pair-xyz",
        ephemeralPublic: new Uint8Array([1, 2]),
        encryptedPayload: new Uint8Array([3, 4]),
        payloadNonce: new Uint8Array([5, 6]),
        expiresIn: 60,
        timestamp: 999999,
      },
      1000,
    );
    expect(captured.keyID).toBeUndefined();
    expect(captured.signingPublicKey).toBeUndefined();
    expect("keyID" in captured).toBe(false);
    expect("signingPublicKey" in captured).toBe(false);
  });

  it.each([
    ["pending response", { status: "pending" }, "pending"],
    ["responded after auto-reconnect", {}, "responded"],
  ])("handles %s correctly", async (_desc, overrides, expectedStatus) => {
    const s = setup();
    if (Object.keys(overrides).length === 0) s.server.connected = false;
    autoRespond(s, overrides);
    expect((await s.transport.send(mockRequest, 1000)).status).toBe(
      expectedStatus,
    );
  });

  it("serializes wrappedKeys with hex-to-base64 conversion", async () => {
    const s = setup();
    const wrappedKeyBytes = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const nonceBytes = new Uint8Array([0xdd, 0xee]);
    const ephemeralBytes = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
    let captured: Record<string, unknown> = {};
    s.reqChar.onCompleteMessage = (data) => {
      captured = JSON.parse(
        new TextDecoder().decode(decodeFrame(data).payload),
      );
      sendFragmented(s.resChar, mockResJson());
    };
    await s.transport.send(
      {
        ...mockRequest,
        wrappedKeys: [
          {
            encryptionPublicKeyHex: "abcdef01",
            wrappedKey: hexEncode(wrappedKeyBytes),
            wrappedKeyNonce: hexEncode(nonceBytes),
            requesterEphemeralKeyHex: hexEncode(ephemeralBytes),
          },
        ],
      },
      1000,
    );
    const keys = captured.wrappedKeys as Array<Record<string, string>>;
    expect(keys).toHaveLength(1);
    expect(keys[0].encryptionPublicKey).toBe("abcdef01");
    expect(Array.from(base64Decode(keys[0].wrappedKey))).toEqual(
      Array.from(wrappedKeyBytes),
    );
    expect(Array.from(base64Decode(keys[0].wrappedKeyNonce))).toEqual(
      Array.from(nonceBytes),
    );
    expect(Array.from(base64Decode(keys[0].ephemeralPublic))).toEqual(
      Array.from(ephemeralBytes),
    );
  });

  it("omits wrappedKeys when not provided", async () => {
    const s = setup();
    let captured: Record<string, unknown> = {};
    s.reqChar.onCompleteMessage = (data) => {
      captured = JSON.parse(
        new TextDecoder().decode(decodeFrame(data).payload),
      );
      sendFragmented(s.resChar, mockResJson());
    };
    await s.transport.send(mockRequest, 1000);
    expect("wrappedKeys" in captured).toBe(false);
  });
});

describe("send() errors", () => {
  it("throws when no device", async () => {
    await expect(
      new BluetoothTransport().send(mockRequest, 1000),
    ).rejects.toThrow("No device selected");
  });

  it("times out when no response received", async () => {
    vi.useFakeTimers();
    const s = setup();
    s.reqChar.onCompleteMessage = () => {};
    const assertion = expect(
      s.transport.send(mockRequest, 5000),
    ).rejects.toThrow("Response timeout");
    await vi.advanceTimersByTimeAsync(6000);
    await assertion;
    vi.useRealTimers();
  });

  it("rejects message > 1MB indirectly through send", async () => {
    await expect(
      setup().transport.send(
        {
          id: "req-huge",
          pairingId: "pair-huge",
          ephemeralPublic: new Uint8Array(1),
          encryptedPayload: new Uint8Array(1024 * 1024),
          payloadNonce: new Uint8Array(1),
          expiresIn: 60,
          timestamp: 1,
        },
        1000,
      ),
    ).rejects.toThrow("Message too large");
  });

  it("throws when characteristics undefined due to broken GATT", async () => {
    const t = new BluetoothTransport({
      device: {
        id: "broken",
        name: "Broken",
        gatt: {
          connect: async () => ({
            connected: true,
            disconnect: () => {},
            getPrimaryService: () => {
              throw new Error("Not connected");
            },
          }),
          disconnect: () => {},
          connected: false,
        },
      } as MockBluetoothDevice,
    });
    await expect(t.send(mockRequest, 1000)).rejects.toThrow();
  });
});

describe("Response parsing (via send())", () => {
  function makeBadFrame(
    lengthVal: number,
    typeVal: number,
    extraBytes: number[],
  ): Uint8Array {
    const frame = new Uint8Array(6 + extraBytes.length);
    const v = new DataView(frame.buffer);
    v.setUint32(0, lengthVal, false);
    v.setUint16(4, typeVal, false);
    extraBytes.forEach((b, i) => {
      frame[6 + i] = b;
    });
    return frame;
  }

  it.each([
    [
      "frame with < 6 bytes",
      (c: MockCharacteristic) => notifyBadFrame(c, new Uint8Array([1, 2, 3])),
      "Response too short",
    ],
    [
      "invalid length field",
      (c: MockCharacteristic) =>
        notifyBadFrame(c, makeBadFrame(9999, 0x0002, [0x7b, 0x7d])),
      "Invalid response length",
    ],
    [
      "wrong message type",
      (c: MockCharacteristic) => sendFragmented(c, mockResJson(), 0x0003),
      "Unexpected message type",
    ],
    [
      "response length field < 2",
      (c: MockCharacteristic) => notifyBadFrame(c, makeBadFrame(1, 0x0002, [])),
      "Invalid response length",
    ],
  ])("errors on %s", async (_desc, trigger, error) => {
    const s = setup();
    s.reqChar.onCompleteMessage = () => trigger(s.resChar);
    await expect(s.transport.send(mockRequest, 1000)).rejects.toThrow(error);
  });
});

describe("Timeout/cleanup", () => {
  it("listener cleaned up on success", async () => {
    const s = setup();
    const addSpy = vi.spyOn(s.resChar, "addEventListener");
    const removeSpy = vi.spyOn(s.resChar, "removeEventListener");
    autoRespond(s);
    await s.transport.connect();
    await s.transport.send(mockRequest, 1000);
    expect(removeSpy.mock.calls.length).toBeGreaterThanOrEqual(
      addSpy.mock.calls.filter((c) => c[0] === "characteristicvaluechanged")
        .length - 0,
    );
  });

  it("listener cleaned up on timeout", async () => {
    vi.useFakeTimers();
    const s = setup();
    const removeSpy = vi.spyOn(s.resChar, "removeEventListener");
    s.reqChar.onCompleteMessage = () => {};
    await s.transport.connect();
    const assertion = expect(
      s.transport.send(mockRequest, 5000),
    ).rejects.toThrow("Response timeout");
    await vi.advanceTimersByTimeAsync(6000);
    await assertion;
    expect(removeSpy).toHaveBeenCalledWith(
      "characteristicvaluechanged",
      expect.any(Function),
    );
    vi.useRealTimers();
  });

  it("ignores null/undefined value on characteristicvaluechanged event", async () => {
    vi.useFakeTimers();
    const s = setup();
    s.reqChar.onCompleteMessage = () => {
      const saved = s.resChar.value;
      s.resChar.value = undefined;
      s.resChar.dispatchEvent(new Event("characteristicvaluechanged"));
      s.resChar.value = saved;
      sendFragmented(s.resChar, mockResJson());
    };
    await s.transport.connect();
    const p = s.transport.send(mockRequest, 5000);
    await vi.advanceTimersByTimeAsync(100);
    expect((await p).status).toBe("responded");
    vi.useRealTimers();
  });
});

describe("Debug logging", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it.each([
    ["called when debug=true", true, true],
    ["NOT called when debug=false", false, false],
  ])("console.debug %s", async (_desc, debug, shouldBeCalled) => {
    const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
    const s = setup({ debug });
    autoRespond(s);
    await s.transport.send(mockRequest, 1000);
    if (shouldBeCalled) {
      expect(spy).toHaveBeenCalled();
      expect(spy.mock.calls[0][0]).toBe("[BluetoothTransport]");
    } else {
      expect(spy).not.toHaveBeenCalled();
    }
  });
});

describe("Constants/interface", () => {
  it.each([
    [
      "ACKAGENT_SERVICE_UUID",
      ACKAGENT_SERVICE_UUID,
      "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d",
    ],
    [
      "REQUEST_CHARACTERISTIC_UUID",
      REQUEST_CHARACTERISTIC_UUID,
      "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c01",
    ],
    [
      "RESPONSE_CHARACTERISTIC_UUID",
      RESPONSE_CHARACTERISTIC_UUID,
      "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c02",
    ],
    [
      "STATUS_CHARACTERISTIC_UUID",
      STATUS_CHARACTERISTIC_UUID,
      "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c03",
    ],
  ])("%s is correct", (_name, actual, expected) => {
    expect(actual).toBe(expected);
  });

  it("BluetoothTransport instance has name='bluetooth' and priority=5", () => {
    const t = new BluetoothTransport();
    expect(t.name).toBe("bluetooth");
    expect(t.priority).toBe(5);
  });
});
