/**
 * Error types for the AckAgent Web SDK
 */

import { SigningErrorCode } from "./types.js";

/** Base error class for AckAgent SDK errors */
export class SignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerError";
  }
}

/** Error during pairing session */
export class PairingError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = "PairingError";
  }
}

/** Error during signing request */
export class SigningError extends SignerError {
  readonly code: SigningErrorCode;

  constructor(code: SigningErrorCode, message: string) {
    super(message);
    this.name = "SigningError";
    this.code = code;
  }
}

/** User rejected the signing request */
export class SigningRejectedError extends SigningError {
  constructor(message?: string) {
    super(SigningErrorCode.Rejected, message ?? "Signing request rejected");
    this.name = "SigningRejectedError";
  }
}

/** Signing request expired */
export class SigningExpiredError extends SigningError {
  constructor() {
    super(SigningErrorCode.Expired, "Signing request expired");
    this.name = "SigningExpiredError";
  }
}

/** Network or communication error */
export class NetworkError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = "NetworkError";
  }
}

/** Cryptographic operation failed */
export class CryptoError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

/** Timeout waiting for response */
export class TimeoutError extends SignerError {
  constructor(message?: string) {
    super(message ?? "Timeout waiting for response");
    this.name = "TimeoutError";
  }
}
