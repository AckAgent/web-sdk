/**
 * W3C VC Data Integrity envelope helpers for anonymous attestation.
 *
 * This module defines a minimal envelope accepted by the verifier while we
 * transition from native attestation payloads to JSON-LD/Data Integrity inputs.
 */

import type {
  AnonymousAttestation,
  AttestationSecurityType,
  AnonymousAttestationScopedLinking,
  ApproverDeviceType,
} from "./attestation-types.js";

const ACKAGENT_W3C_CONTEXT = [
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/security/data-integrity/v2",
  "https://w3id.org/security/bbs/v1",
  "https://schemas.ackagent.com/credentials/anonymous-attestation/v1",
];

const ACKAGENT_W3C_TYPES = [
  "VerifiablePresentation",
  "AckAgentAnonymousAttestationPresentation",
];

/**
 * Minimal Data Integrity proof shape used for bbs-2023 presentations.
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: string;
  proofValue: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
}

/**
 * Minimal W3C VC/VP wrapper for AckAgent anonymous attestation.
 *
 * `proof.proofValue` contains the serialized BBS+ proof bytes
 * (multibase base64url preferred, raw base64/base64url accepted).
 */
export interface W3CAnonymousAttestationEnvelope {
  "@context": string[];
  type: string[] | string;
  proof: DataIntegrityProof;
  ackagentAnonymousAttestation: {
    pseudonym: string;
    scope: string;
    presentationHeader: string;
    issuerPublicKeyId?: string;
    revealedMessages: {
      attestationType: AttestationSecurityType;
      deviceType: ApproverDeviceType;
      expiresAt: number;
    };
    scopedLinking?: AnonymousAttestationScopedLinking;
  };
}

/**
 * Type guard for W3C anonymous attestation envelopes.
 */
export function isW3CAnonymousAttestationEnvelope(
  value: unknown,
): value is W3CAnonymousAttestationEnvelope {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.ackagentAnonymousAttestation === "object" &&
    candidate.ackagentAnonymousAttestation !== null &&
    typeof candidate.proof === "object" &&
    candidate.proof !== null
  );
}

/**
 * Parse a W3C/Data-Integrity envelope into the native AnonymousAttestation.
 *
 * @throws Error when required fields are missing or unsupported.
 */
export function parseW3CAnonymousAttestationEnvelope(
  envelope: W3CAnonymousAttestationEnvelope,
): AnonymousAttestation {
  if (envelope.proof.type !== "DataIntegrityProof") {
    throw new Error(
      `unsupported proof type: expected "DataIntegrityProof", got "${envelope.proof.type}"`,
    );
  }
  if (envelope.proof.cryptosuite !== "bbs-2023") {
    throw new Error(
      `unsupported cryptosuite: expected "bbs-2023", got "${envelope.proof.cryptosuite}"`,
    );
  }

  const body = envelope.ackagentAnonymousAttestation;
  if (!body.scope || body.scope.length === 0) {
    throw new Error("W3C envelope missing scope");
  }

  const bbsProof = decodeProofValue(envelope.proof.proofValue);
  const pseudonym = decodeBase64(body.pseudonym);
  const presentationHeader = decodeBase64(body.presentationHeader);

  return {
    bbsProof,
    pseudonym,
    scope: body.scope,
    presentationHeader,
    issuerPublicKeyId: body.issuerPublicKeyId,
    revealedMessages: {
      attestationType: body.revealedMessages.attestationType,
      deviceType: body.revealedMessages.deviceType,
      expiresAt: body.revealedMessages.expiresAt,
    },
    scopedLinking: body.scopedLinking,
  };
}

/**
 * Convert native anonymous attestation into a W3C/Data-Integrity envelope.
 *
 * Uses multibase base64url (`u...`) for `proof.proofValue`.
 */
export function toW3CAnonymousAttestationEnvelope(
  attestation: AnonymousAttestation,
): W3CAnonymousAttestationEnvelope {
  return {
    "@context": ACKAGENT_W3C_CONTEXT,
    type: ACKAGENT_W3C_TYPES,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "bbs-2023",
      proofValue: toMultibaseBase64Url(attestation.bbsProof),
    },
    ackagentAnonymousAttestation: {
      pseudonym: encodeBase64(attestation.pseudonym),
      scope: attestation.scope,
      presentationHeader: encodeBase64(attestation.presentationHeader),
      ...(attestation.issuerPublicKeyId && {
        issuerPublicKeyId: attestation.issuerPublicKeyId,
      }),
      revealedMessages: {
        attestationType: attestation.revealedMessages.attestationType,
        deviceType: attestation.revealedMessages.deviceType,
        expiresAt: attestation.revealedMessages.expiresAt,
      },
      scopedLinking: attestation.scopedLinking,
    },
  };
}

/**
 * Parse Data Integrity proofValue.
 *
 * Supports:
 * - multibase base64url (leading `u`)
 * - base64url
 * - base64
 */
function decodeProofValue(value: string): Uint8Array {
  if (!value || value.length === 0) {
    throw new Error("W3C envelope missing proof.proofValue");
  }

  if (value.startsWith("u")) {
    return decodeBase64Url(value.slice(1));
  }

  // Prefer base64url decoding first, then base64 fallback.
  try {
    return decodeBase64Url(value);
  } catch {
    return decodeBase64(value);
  }
}

/**
 * Decode base64url into bytes.
 */
function decodeBase64Url(base64url: string): Uint8Array {
  const normalized = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded =
    padding === 0 ? normalized : normalized + "=".repeat(4 - padding);
  return decodeBase64(padded);
}

/**
 * Decode base64 into bytes.
 */
function decodeBase64(base64: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(base64);
    const output = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      output[i] = binary.charCodeAt(i);
    }
    return output;
  }
  const maybeBuffer = (
    globalThis as {
      Buffer?: {
        from(input: string, encoding: string): Uint8Array;
      };
    }
  ).Buffer;
  if (maybeBuffer) {
    return new Uint8Array(maybeBuffer.from(base64, "base64"));
  }

  throw new Error("base64 decoding unavailable in this runtime");
}

function toMultibaseBase64Url(value: Uint8Array): string {
  const base64 = encodeBase64(value);
  const base64url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `u${base64url}`;
}

function encodeBase64(value: Uint8Array): string {
  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of value) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }
  const maybeBuffer = (
    globalThis as {
      Buffer?: {
        from(input: Uint8Array): { toString(encoding: string): string };
      };
    }
  ).Buffer;
  if (maybeBuffer) {
    return maybeBuffer.from(value).toString("base64");
  }
  throw new Error("base64 encoding unavailable in this runtime");
}
