/**
 * Web Bluetooth transport for direct communication with iOS app.
 * Uses GATT service with request/response characteristics.
 *
 * Requires user gesture to show device picker.
 * Only works in secure contexts (HTTPS).
 */

import type { PollConfig } from "../../client.js";
import { base64Decode, base64Encode, hexDecode } from "../../encoding.js";
import type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "../types.js";
import { TransportError } from "../types.js";
import {
  BLEFragmenter,
  BLEReassembler,
  encodeFragment,
  decodeFragment,
} from "./fragmentation.js";

// Web Bluetooth types - these are experimental APIs not in standard TypeScript lib
// We use 'any' to avoid needing external type packages
type BluetoothDevice = {
  readonly id: string;
  readonly name?: string;
  readonly gatt?: BluetoothRemoteGATTServer;
};

type BluetoothRemoteGATTServer = {
  readonly device: BluetoothDevice;
  readonly connected: boolean;
  connect(): Promise<BluetoothRemoteGATTServer>;
  disconnect(): void;
  getPrimaryService(service: string): Promise<BluetoothRemoteGATTService>;
};

type BluetoothRemoteGATTService = {
  getCharacteristic(
    characteristic: string,
  ): Promise<BluetoothRemoteGATTCharacteristic>;
};

type BluetoothRemoteGATTCharacteristic = EventTarget & {
  readonly service: BluetoothRemoteGATTService;
  readonly uuid: string;
  readonly value?: DataView;
  writeValue(value: BufferSource): Promise<void>;
  startNotifications(): Promise<BluetoothRemoteGATTCharacteristic>;
  stopNotifications(): Promise<BluetoothRemoteGATTCharacteristic>;
};

interface Bluetooth {
  getAvailability(): Promise<boolean>;
  requestDevice(options: {
    filters: Array<{ services: string[] }>;
  }): Promise<BluetoothDevice>;
}

declare global {
  interface Navigator {
    bluetooth?: Bluetooth;
  }
}

/** BLE service and characteristic UUIDs for AckAgent */
export const ACKAGENT_SERVICE_UUID = "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d";
export const REQUEST_CHARACTERISTIC_UUID =
  "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c01";
export const RESPONSE_CHARACTERISTIC_UUID =
  "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c02";
export const STATUS_CHARACTERISTIC_UUID =
  "a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c03";

/** Message type constants (matching MessageFraming) */
const MESSAGE_TYPE_REQUEST = 0x0001;
const MESSAGE_TYPE_RESPONSE = 0x0002;

/** Maximum message size (1MB) */
const MAX_MESSAGE_SIZE = 1024 * 1024;

/**
 * Options for creating a Bluetooth transport
 */
export interface BluetoothTransportOptions {
  /** Device to connect to (from previous requestDevice call) */
  device?: BluetoothDevice;

  /** Enable debug logging */
  debug?: boolean;
}

/**
 * Transport implementation using Web Bluetooth.
 * Connects directly to iOS app via BLE.
 */
export class BluetoothTransport implements Transport {
  readonly name = "bluetooth";
  readonly priority = 5; // Higher priority than relay (50)

  private device: BluetoothDevice | undefined;
  private server: BluetoothRemoteGATTServer | undefined;
  private requestCharacteristic: BluetoothRemoteGATTCharacteristic | undefined;
  private responseCharacteristic: BluetoothRemoteGATTCharacteristic | undefined;
  private readonly debug: boolean;

  constructor(options: BluetoothTransportOptions = {}) {
    this.device = options.device;
    this.debug = options.debug ?? false;
  }

  /**
   * Check if Web Bluetooth is available
   */
  async isAvailable(): Promise<boolean> {
    if (typeof navigator === "undefined" || !navigator.bluetooth) {
      return false;
    }

    try {
      // Check if Bluetooth is available on the system
      return await navigator.bluetooth.getAvailability();
    } catch {
      return false;
    }
  }

  /**
   * Request user to select a device.
   * MUST be called from a user gesture (click handler).
   */
  async requestDevice(): Promise<BluetoothDevice> {
    if (!navigator.bluetooth) {
      throw new Error("Web Bluetooth not supported");
    }

    this.log("Requesting device...");

    this.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [ACKAGENT_SERVICE_UUID] }],
    });

    this.log("Device selected:", this.device.name);
    return this.device;
  }

  /**
   * Connect to the selected device
   */
  async connect(): Promise<void> {
    if (!this.device) {
      throw new Error("No device selected. Call requestDevice() first.");
    }

    this.log("Connecting to device...");

    // Connect to GATT server
    this.server = await this.device.gatt?.connect();
    if (!this.server) {
      throw new Error("Failed to connect to GATT server");
    }

    this.log("Connected to GATT server");

    // Get service
    const service = await this.server.getPrimaryService(ACKAGENT_SERVICE_UUID);

    // Get characteristics
    this.requestCharacteristic = await service.getCharacteristic(
      REQUEST_CHARACTERISTIC_UUID,
    );
    this.responseCharacteristic = await service.getCharacteristic(
      RESPONSE_CHARACTERISTIC_UUID,
    );

    this.log("Characteristics acquired");

    // Start notifications for response characteristic
    await this.responseCharacteristic.startNotifications();
    this.log("Notifications started");
  }

  /**
   * Disconnect from the device
   */
  disconnect(): void {
    if (this.server?.connected) {
      this.server.disconnect();
    }
    this.server = undefined;
    this.requestCharacteristic = undefined;
    this.responseCharacteristic = undefined;
  }

  /**
   * Send a signing request via Bluetooth
   */
  async send(
    request: TransportRequest,
    timeoutMs: number,
    _pollConfig?: PollConfig,
  ): Promise<TransportResponse> {
    // Ensure we're connected
    if (!this.server?.connected) {
      await this.connect();
    }

    if (!this.requestCharacteristic || !this.responseCharacteristic) {
      throw new Error("Not connected");
    }

    // Build the request payload (matches iOS LocalRequest JSON structure)
    const requestPayload = JSON.stringify({
      id: request.id,
      requesterID: request.pairingId,
      keyID: request.keyId || undefined,
      signingPublicKey: request.signingPublicKeyHex || undefined,
      ephemeralPublic: base64Encode(request.ephemeralPublic),
      encryptedPayload: base64Encode(request.encryptedPayload),
      payloadNonce: base64Encode(request.payloadNonce),
      expiresIn: request.expiresIn,
      timestamp: request.timestamp,
      wrappedKeys: request.wrappedKeys?.map((wk) => ({
        encryptionPublicKey: wk.encryptionPublicKeyHex,
        wrappedKey: base64Encode(hexDecode(wk.wrappedKey)),
        wrappedKeyNonce: base64Encode(hexDecode(wk.wrappedKeyNonce)),
        ephemeralPublic: base64Encode(hexDecode(wk.requesterEphemeralKeyHex)),
      })),
    });

    // Frame the request
    const framedRequest = this.frameMessage(
      MESSAGE_TYPE_REQUEST,
      new TextEncoder().encode(requestPayload),
    );

    this.log("Sending request:", request.id);

    // Set up response listener
    const responsePromise = this.waitForResponse(timeoutMs);

    // Fragment and send the request
    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(framedRequest);

    this.log(`Sending ${fragments.length} fragments`);

    for (const fragment of fragments) {
      const encoded = encodeFragment(fragment);
      // Use buffer slice to get proper ArrayBuffer for writeValue
      // Cast needed because TypeScript's ArrayBufferLike includes SharedArrayBuffer
      const buffer = encoded.buffer.slice(
        encoded.byteOffset,
        encoded.byteOffset + encoded.byteLength,
      ) as ArrayBuffer;
      await this.requestCharacteristic.writeValue(buffer);
    }

    // Wait for response
    const responseData = await responsePromise;

    // Parse response
    return this.parseResponse(responseData);
  }

  /**
   * Frame a message with length prefix and type
   * Wire format: [length:4][type:2][payload:N]
   */
  private frameMessage(type: number, payload: Uint8Array): Uint8Array {
    const length = 2 + payload.length;
    if (length > MAX_MESSAGE_SIZE) {
      throw new Error(`Message too large: ${length}`);
    }

    const result = new Uint8Array(4 + length);
    const view = new DataView(result.buffer);

    // Length (4 bytes, big-endian)
    view.setUint32(0, length, false);

    // Type (2 bytes, big-endian)
    view.setUint16(4, type, false);

    // Payload
    result.set(payload, 6);

    return result;
  }

  /**
   * Wait for a complete response message
   */
  private async waitForResponse(timeoutMs: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const reassembler = new BLEReassembler();
      let timeoutId: ReturnType<typeof setTimeout>;

      const handler = (event: Event) => {
        const characteristic =
          event.target as BluetoothRemoteGATTCharacteristic;
        const value = characteristic.value;
        if (!value) return;

        const data = new Uint8Array(
          value.buffer,
          value.byteOffset,
          value.byteLength,
        );
        const fragment = decodeFragment(data);
        if (!fragment) {
          this.log("Failed to decode fragment");
          return;
        }

        const complete = reassembler.addFragment(fragment);
        if (complete) {
          clearTimeout(timeoutId);
          this.responseCharacteristic?.removeEventListener(
            "characteristicvaluechanged",
            handler,
          );
          resolve(complete);
        }
      };

      // Set up listener
      this.responseCharacteristic?.addEventListener(
        "characteristicvaluechanged",
        handler,
      );

      // Set up timeout
      timeoutId = setTimeout(() => {
        this.responseCharacteristic?.removeEventListener(
          "characteristicvaluechanged",
          handler,
        );
        reject(new TransportError("bluetooth", new Error("Response timeout")));
      }, timeoutMs);
    });
  }

  /**
   * Parse a framed response message
   */
  private parseResponse(data: Uint8Array): TransportResponse {
    if (data.length < 6) {
      throw new Error("Response too short");
    }

    const view = new DataView(data.buffer, data.byteOffset);

    // Read length (4 bytes, big-endian)
    const length = view.getUint32(0, false);
    if (length < 2 || data.length < 4 + length) {
      throw new Error("Invalid response length");
    }

    // Read type (2 bytes, big-endian)
    const type = view.getUint16(4, false);
    if (type !== MESSAGE_TYPE_RESPONSE) {
      throw new Error(`Unexpected message type: ${type}`);
    }

    // Parse JSON payload
    const payload = data.slice(6, 4 + length);
    const json = new TextDecoder().decode(payload);
    const response = JSON.parse(json);

    this.log("Received response:", response.id, response.status);

    return {
      id: response.id,
      status: response.status,
      ephemeralPublic: response.ephemeralPublic
        ? base64Decode(response.ephemeralPublic)
        : undefined,
      encryptedResponse: response.encryptedResponse
        ? base64Decode(response.encryptedResponse)
        : undefined,
      responseNonce: response.responseNonce
        ? base64Decode(response.responseNonce)
        : undefined,
      expiresAt: "",
    };
  }

  private log(...args: unknown[]): void {
    if (this.debug) {
      console.debug("[BluetoothTransport]", ...args);
    }
  }
}

/**
 * Check if Web Bluetooth is supported in this environment
 */
export function isWebBluetoothSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "bluetooth" in navigator &&
    navigator.bluetooth !== undefined &&
    typeof navigator.bluetooth.requestDevice === "function"
  );
}

/**
 * Create a Bluetooth transport.
 * Note: Call transport.requestDevice() from a user gesture before sending.
 */
export function createBluetoothTransport(
  options?: BluetoothTransportOptions,
): BluetoothTransport {
  return new BluetoothTransport(options);
}
