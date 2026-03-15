/**
 * Transport layer exports.
 *
 * The transport layer provides a pluggable abstraction for sending signing
 * requests via different channels (HTTP relay, Bluetooth, etc.).
 */

// Core types
export type {
  Transport,
  TransportRequest,
  TransportResponse,
} from "./types.js";
export { TransportError } from "./types.js";

// Manager
export {
  TransportManager,
  NoTransportsError,
  AllTransportsFailedError,
} from "./manager.js";

// Relay transport (always available)
export { RelayTransport, createRelayTransport } from "./relay.js";
export type { RelayTransportOptions } from "./relay.js";

// Local transports are exported conditionally from local/index.ts
// They're in a separate directory so they can be tree-shaken when not used
