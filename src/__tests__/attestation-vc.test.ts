/**
 * Tests for W3C/Data-Integrity anonymous attestation envelope support.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AnonymousAttestationVerifier,
  type AnonymousAttestation,
} from "../attestation.js";
import {
  isW3CAnonymousAttestationEnvelope,
  parseW3CAnonymousAttestationEnvelope,
  toW3CAnonymousAttestationEnvelope,
  type W3CAnonymousAttestationEnvelope,
} from "../attestation-vc.js";

type PseudonymVector = {
  issuerPublicKeyHex: string;
  proofHex: string;
  pseudonymHex: string;
  presentationHeaderHex: string;
  scopeHex: string;
  disclosedMessages: Array<{
    index: number;
    valueHex: string;
  }>;
};

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hexToUtf8(hex: string): string {
  return new TextDecoder().decode(hexToBytes(hex));
}

function toMultibaseBase64Url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  const base64url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `u${base64url}`;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function decodeInt64BigEndian(bytes: Uint8Array): number {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return Number(value);
}

function loadVector(
  fixtureFile = "android-bbs-pseudonym-vector.json",
): PseudonymVector {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const fixturePath = path.join(here, "fixtures", fixtureFile);
  return JSON.parse(fs.readFileSync(fixturePath, "utf8")) as PseudonymVector;
}

function makeEnvelope(
  vector: PseudonymVector,
): W3CAnonymousAttestationEnvelope {
  const disclosed = new Map<number, Uint8Array>(
    vector.disclosedMessages.map((msg) => [
      msg.index,
      hexToBytes(msg.valueHex),
    ]),
  );

  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v2",
      "https://w3id.org/security/bbs/v1",
      "https://schemas.ackagent.com/credentials/anonymous-attestation/v1",
    ],
    type: [
      "VerifiablePresentation",
      "AckAgentAnonymousAttestationPresentation",
    ],
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "bbs-2023",
      proofValue: toMultibaseBase64Url(hexToBytes(vector.proofHex)),
    },
    ackagentAnonymousAttestation: {
      pseudonym: toBase64(hexToBytes(vector.pseudonymHex)),
      scope: hexToUtf8(vector.scopeHex),
      presentationHeader: toBase64(hexToBytes(vector.presentationHeaderHex)),
      revealedMessages: {
        attestationType: new TextDecoder().decode(
          disclosed.get(0) ?? new Uint8Array(),
        ) as AnonymousAttestation["revealedMessages"]["attestationType"],
        deviceType: new TextDecoder().decode(
          disclosed.get(1) ?? new Uint8Array(),
        ) as AnonymousAttestation["revealedMessages"]["deviceType"],
        expiresAt: decodeInt64BigEndian(disclosed.get(3) ?? new Uint8Array()),
      },
    },
  };
}

describe("W3C anonymous attestation envelope", () => {
  it("parses bbs-2023 envelope into native attestation", () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);

    expect(isW3CAnonymousAttestationEnvelope(envelope)).toBe(true);

    const parsed = parseW3CAnonymousAttestationEnvelope(envelope);
    expect(parsed.scope).toBe(hexToUtf8(vector.scopeHex));
    expect(Buffer.from(parsed.bbsProof).toString("hex")).toBe(vector.proofHex);
    expect(Buffer.from(parsed.pseudonym).toString("hex")).toBe(
      vector.pseudonymHex,
    );
  });

  it("parses optional scopedLinking metadata", () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);
    envelope.ackagentAnonymousAttestation.scopedLinking = {
      mode: "pairwise_account_secret",
      scopeType: "organization",
      scopeId: "org_123",
      linkHandle: "QWNjb3VudExpbmtIYW5kbGVfMDEyMzQ1Njc",
    };

    const parsed = parseW3CAnonymousAttestationEnvelope(envelope);
    expect(parsed.scopedLinking).toEqual({
      mode: "pairwise_account_secret",
      scopeType: "organization",
      scopeId: "org_123",
      linkHandle: "QWNjb3VudExpbmtIYW5kbGVfMDEyMzQ1Njc",
    });
  });

  it("verifier accepts W3C envelope input directly", async () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);
    const verifier = new AnonymousAttestationVerifier();

    const result = await verifier.verify(envelope, {
      issuerPublicKey: hexToBytes(vector.issuerPublicKeyHex),
      expectedRequestId: hexToUtf8(vector.scopeHex),
    });

    expect(result.valid).toBe(true);
    expect(result.proofValid).toBe(true);
    expect(result.pseudonymVerified).toBe(true);
  });

  it("parses envelope with issuerPublicKeyId", () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);
    envelope.ackagentAnonymousAttestation.issuerPublicKeyId =
      "key-rotation-2026-03";

    const parsed = parseW3CAnonymousAttestationEnvelope(envelope);
    expect(parsed.issuerPublicKeyId).toBe("key-rotation-2026-03");
  });

  it("parses envelope without issuerPublicKeyId as undefined", () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);

    const parsed = parseW3CAnonymousAttestationEnvelope(envelope);
    expect(parsed.issuerPublicKeyId).toBeUndefined();
  });

  it("round-trips issuerPublicKeyId through native to W3C and back", () => {
    const vector = loadVector();
    const native = parseW3CAnonymousAttestationEnvelope(makeEnvelope(vector));
    native.issuerPublicKeyId = "key-abc-123";

    const envelope = toW3CAnonymousAttestationEnvelope(native);
    expect(envelope.ackagentAnonymousAttestation.issuerPublicKeyId).toBe(
      "key-abc-123",
    );

    const roundTripped = parseW3CAnonymousAttestationEnvelope(envelope);
    expect(roundTripped.issuerPublicKeyId).toBe("key-abc-123");
  });

  it("does not include issuerPublicKeyId in envelope when absent", () => {
    const vector = loadVector();
    const native = parseW3CAnonymousAttestationEnvelope(makeEnvelope(vector));
    expect(native.issuerPublicKeyId).toBeUndefined();

    const envelope = toW3CAnonymousAttestationEnvelope(native);
    expect("issuerPublicKeyId" in envelope.ackagentAnonymousAttestation).toBe(
      false,
    );
  });

  it("rejects unsupported cryptosuite", () => {
    const vector = loadVector();
    const envelope = makeEnvelope(vector);
    envelope.proof.cryptosuite = "eddsa-2022";

    expect(() => parseW3CAnonymousAttestationEnvelope(envelope)).toThrow(
      /unsupported cryptosuite/i,
    );
  });

  it("converts native attestation to W3C envelope and round-trips", () => {
    const vector = loadVector();
    const native = parseW3CAnonymousAttestationEnvelope(makeEnvelope(vector));
    const envelope = toW3CAnonymousAttestationEnvelope(native);
    const roundTripped = parseW3CAnonymousAttestationEnvelope(envelope);

    expect(roundTripped.scope).toBe(native.scope);
    expect(Buffer.from(roundTripped.bbsProof).toString("hex")).toBe(
      Buffer.from(native.bbsProof).toString("hex"),
    );
    expect(Buffer.from(roundTripped.pseudonym).toString("hex")).toBe(
      Buffer.from(native.pseudonym).toString("hex"),
    );
  });
});
