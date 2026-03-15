/**
 * Tests for error class hierarchy in the AckAgent Web SDK.
 * Validates constructors, inheritance chains, name properties, and error codes.
 */

import { describe, it, expect } from "vitest";
import {
  SignerError,
  PairingError,
  SigningError,
  SigningRejectedError,
  SigningExpiredError,
  NetworkError,
  CryptoError,
  TimeoutError,
} from "../errors.js";
import { SigningErrorCode } from "../types.js";

describe("SignerError", () => {
  it("sets name to SignerError", () => {
    const err = new SignerError("test message");
    expect(err.name).toBe("SignerError");
  });

  it("sets the message", () => {
    const err = new SignerError("something went wrong");
    expect(err.message).toBe("something went wrong");
  });

  it("extends Error", () => {
    const err = new SignerError("base");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("PairingError", () => {
  it("sets name to PairingError", () => {
    const err = new PairingError("pairing failed");
    expect(err.name).toBe("PairingError");
  });

  it("extends SignerError and Error", () => {
    const err = new PairingError("pairing failed");
    expect(err).toBeInstanceOf(SignerError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("NetworkError", () => {
  it("sets name to NetworkError", () => {
    const err = new NetworkError("connection refused");
    expect(err.name).toBe("NetworkError");
  });

  it("extends SignerError and Error", () => {
    const err = new NetworkError("timeout");
    expect(err).toBeInstanceOf(SignerError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("CryptoError", () => {
  it("sets name to CryptoError", () => {
    const err = new CryptoError("decryption failed");
    expect(err.name).toBe("CryptoError");
  });

  it("extends SignerError and Error", () => {
    const err = new CryptoError("bad key");
    expect(err).toBeInstanceOf(SignerError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("SigningError", () => {
  it("sets name to SigningError and stores the code", () => {
    const err = new SigningError(SigningErrorCode.InternalError, "internal");
    expect(err.name).toBe("SigningError");
    expect(err.code).toBe(SigningErrorCode.InternalError);
    expect(err.message).toBe("internal");
  });

  it("extends SignerError and Error", () => {
    const err = new SigningError(SigningErrorCode.KeyNotFound, "not found");
    expect(err).toBeInstanceOf(SignerError);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("SigningRejectedError", () => {
  it('has default message "Signing request rejected"', () => {
    const err = new SigningRejectedError();
    expect(err.message).toBe("Signing request rejected");
  });

  it("accepts a custom message", () => {
    const err = new SigningRejectedError("user said no");
    expect(err.message).toBe("user said no");
  });

  it("has code SigningErrorCode.Rejected (1)", () => {
    const err = new SigningRejectedError();
    expect(err.code).toBe(SigningErrorCode.Rejected);
    expect(err.code).toBe(1);
  });

  it("sets name to SigningRejectedError", () => {
    const err = new SigningRejectedError();
    expect(err.name).toBe("SigningRejectedError");
  });
});

describe("SigningExpiredError", () => {
  it('has fixed message "Signing request expired"', () => {
    const err = new SigningExpiredError();
    expect(err.message).toBe("Signing request expired");
  });

  it("has code SigningErrorCode.Expired (2)", () => {
    const err = new SigningExpiredError();
    expect(err.code).toBe(SigningErrorCode.Expired);
    expect(err.code).toBe(2);
  });

  it("sets name to SigningExpiredError", () => {
    const err = new SigningExpiredError();
    expect(err.name).toBe("SigningExpiredError");
  });
});

describe("TimeoutError", () => {
  it('has default message "Timeout waiting for response"', () => {
    const err = new TimeoutError();
    expect(err.message).toBe("Timeout waiting for response");
  });

  it("accepts a custom message", () => {
    const err = new TimeoutError("waited too long");
    expect(err.message).toBe("waited too long");
  });

  it("sets name to TimeoutError", () => {
    const err = new TimeoutError();
    expect(err.name).toBe("TimeoutError");
  });

  it("extends SignerError and Error", () => {
    const err = new TimeoutError();
    expect(err).toBeInstanceOf(SignerError);
    expect(err).toBeInstanceOf(Error);
  });
});
