/**
 * Local transport implementations for direct device communication.
 *
 * These transports bypass the relay server and communicate directly
 * with the iOS app via Bluetooth.
 *
 * REMOVABILITY: This entire directory can be deleted to remove local
 * transport support. The core transport abstraction in ../index.ts
 * does not depend on this module.
 */

// Bluetooth transport
export {
  BluetoothTransport,
  createBluetoothTransport,
  isWebBluetoothSupported,
  ACKAGENT_SERVICE_UUID,
  REQUEST_CHARACTERISTIC_UUID,
  RESPONSE_CHARACTERISTIC_UUID,
  STATUS_CHARACTERISTIC_UUID,
} from "./bluetooth.js";
export type { BluetoothTransportOptions } from "./bluetooth.js";

// BLE fragmentation utilities
export {
  BLEFragmenter,
  BLEReassembler,
  encodeFragment,
  decodeFragment,
  BLE_MAX_FRAGMENT_SIZE,
  FragmentFlags,
} from "./fragmentation.js";
export type { BLEFragment } from "./fragmentation.js";
