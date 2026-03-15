import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyBbsSignature,
  verifyBbsProof,
  verifyBbsProofWithPseudonym,
} from "../bbs.js";
import { bbs } from "@mattrglobal/pairing-crypto";

const encoder = new TextEncoder();

type PseudonymVector = {
  issuerPublicKeyHex: string;
  proofHex: string;
  pseudonymHex: string;
  headerHex: string;
  presentationHeaderHex: string;
  scopeHex: string;
  totalSignerMessages: number;
  disclosedMessages: Array<{ index: number; valueHex: string }>;
  disclosedCommittedMessages: Array<{ index: number; valueHex: string }>;
  disclosedCommitmentIndices: number[];
};

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function loadPseudonymVector(
  fixtureFile = "bbs-pseudonym-vector.json",
): PseudonymVector {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const fixturePath = path.join(here, "fixtures", fixtureFile);
  const raw = fs.readFileSync(fixturePath, "utf8");
  return JSON.parse(raw) as PseudonymVector;
}

type PseudonymVerifyInput = {
  issuerPublicKey: Uint8Array;
  proof: Uint8Array;
  pseudonym: Uint8Array;
  header: Uint8Array;
  presentationHeader: Uint8Array;
  scope: Uint8Array;
  disclosedMessages: Map<number, Uint8Array>;
  totalSignerMessages: number;
  disclosedCommittedMessages: Map<number, Uint8Array>;
  disclosedCommitmentIndices: number[];
};

function makePseudonymInput(v: PseudonymVector): PseudonymVerifyInput {
  return {
    issuerPublicKey: hexToBytes(v.issuerPublicKeyHex),
    proof: hexToBytes(v.proofHex),
    pseudonym: hexToBytes(v.pseudonymHex),
    header: hexToBytes(v.headerHex),
    presentationHeader: hexToBytes(v.presentationHeaderHex),
    scope: hexToBytes(v.scopeHex),
    disclosedMessages: new Map(
      v.disclosedMessages.map((m) => [m.index, hexToBytes(m.valueHex)]),
    ),
    totalSignerMessages: v.totalSignerMessages,
    disclosedCommittedMessages: new Map(
      v.disclosedCommittedMessages.map((m) => [
        m.index,
        hexToBytes(m.valueHex),
      ]),
    ),
    disclosedCommitmentIndices: v.disclosedCommitmentIndices,
  };
}

function callVerifyWithPseudonym(input: PseudonymVerifyInput) {
  return verifyBbsProofWithPseudonym(
    input.issuerPublicKey,
    input.proof,
    input.pseudonym,
    input.header,
    input.presentationHeader,
    input.scope,
    input.disclosedMessages,
    input.totalSignerMessages,
    input.disclosedCommittedMessages,
    input.disclosedCommitmentIndices,
  );
}

async function generateTestFixture(
  messages: Uint8Array[],
  header?: Uint8Array,
) {
  const keyPair = await bbs.bls12381_sha256.generateKeyPair();
  const signature = await bbs.bls12381_sha256.sign({
    secretKey: keyPair.secretKey,
    publicKey: keyPair.publicKey,
    header: header ?? new Uint8Array(),
    messages,
  });
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    signature,
  };
}

describe("verifyBbsSignature", () => {
  it("should verify a valid BBS+ signature", async () => {
    const messages = [
      encoder.encode("credential-type:device-attestation"),
      encoder.encode("device-id:abc123"),
      encoder.encode("timestamp:1700000000"),
    ];
    const header = encoder.encode("ackagent-bbs-v1");
    const fixture = await generateTestFixture(messages, header);

    const result = await verifyBbsSignature(
      fixture.publicKey,
      fixture.signature,
      header,
      messages,
    );

    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should verify a valid signature with empty header", async () => {
    const messages = [encoder.encode("message-one")];
    const emptyHeader = new Uint8Array();
    const fixture = await generateTestFixture(messages, emptyHeader);

    const result = await verifyBbsSignature(
      fixture.publicKey,
      fixture.signature,
      emptyHeader,
      messages,
    );

    expect(result.verified).toBe(true);
  });

  it("should verify a valid signature with no messages", async () => {
    const messages: Uint8Array[] = [];
    const header = encoder.encode("empty-messages");
    const fixture = await generateTestFixture(messages, header);

    const result = await verifyBbsSignature(
      fixture.publicKey,
      fixture.signature,
      header,
      messages,
    );

    expect(result.verified).toBe(true);
  });

  it.each([
    {
      name: "invalid signature bytes",
      mutate: (
        f: Awaited<ReturnType<typeof generateTestFixture>>,
        msgs: Uint8Array[],
        hdr: Uint8Array,
      ) => {
        const badSig = new Uint8Array(f.signature);
        badSig[0] ^= 0xff;
        badSig[10] ^= 0xff;
        return {
          publicKey: f.publicKey,
          signature: badSig,
          header: hdr,
          messages: msgs,
        };
      },
    },
    {
      name: "wrong public key",
      mutate: async (
        f: Awaited<ReturnType<typeof generateTestFixture>>,
        msgs: Uint8Array[],
        hdr: Uint8Array,
      ) => {
        const otherKeyPair = await bbs.bls12381_sha256.generateKeyPair();
        return {
          publicKey: otherKeyPair.publicKey,
          signature: f.signature,
          header: hdr,
          messages: msgs,
        };
      },
    },
    {
      name: "modified messages",
      mutate: (
        f: Awaited<ReturnType<typeof generateTestFixture>>,
        _msgs: Uint8Array[],
        hdr: Uint8Array,
      ) => ({
        publicKey: f.publicKey,
        signature: f.signature,
        header: hdr,
        messages: [
          encoder.encode("tampered-message-1"),
          encoder.encode("original-message-2"),
        ],
      }),
    },
    {
      name: "wrong header",
      mutate: (
        f: Awaited<ReturnType<typeof generateTestFixture>>,
        msgs: Uint8Array[],
        _hdr: Uint8Array,
      ) => ({
        publicKey: f.publicKey,
        signature: f.signature,
        header: encoder.encode("wrong-header"),
        messages: msgs,
      }),
    },
  ])("should return verified=false for $name", async ({ mutate }) => {
    const messages = [
      encoder.encode("original-message-1"),
      encoder.encode("original-message-2"),
    ];
    const header = encoder.encode("test-header");
    const fixture = await generateTestFixture(messages, header);
    const args = await mutate(fixture, messages, header);

    const result = await verifyBbsSignature(
      args.publicKey,
      args.signature,
      args.header,
      args.messages,
    );

    expect(result.verified).toBe(false);
  });

  it("should return error for invalid public key length", async () => {
    const result = await verifyBbsSignature(
      new Uint8Array(32),
      new Uint8Array(80),
      new Uint8Array(),
      [],
    );

    expect(result.verified).toBe(false);
    expect(result.error).toContain("public key must be 96 bytes");
    expect(result.error).toContain("got 32");
  });
});

describe("verifyBbsProof", () => {
  it("should verify a valid selective disclosure proof", async () => {
    const messages = [
      encoder.encode("credential-type:device-attestation"),
      encoder.encode("device-id:abc123"),
      encoder.encode("timestamp:1700000000"),
      encoder.encode("status:active"),
    ];
    const header = encoder.encode("ackagent-bbs-v1");
    const presentationHeader = encoder.encode("presentation-context-001");
    const fixture = await generateTestFixture(messages, header);

    const proof = await bbs.bls12381_sha256.deriveProof({
      publicKey: fixture.publicKey,
      signature: fixture.signature,
      header,
      presentationHeader,
      verifySignature: true,
      messages: [
        { value: messages[0], reveal: true },
        { value: messages[1], reveal: false },
        { value: messages[2], reveal: true },
        { value: messages[3], reveal: false },
      ],
    });

    const disclosedMessages = new Map<number, Uint8Array>();
    disclosedMessages.set(0, messages[0]);
    disclosedMessages.set(2, messages[2]);

    const result = await verifyBbsProof(
      fixture.publicKey,
      proof,
      header,
      presentationHeader,
      disclosedMessages,
    );

    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should verify a proof with all messages disclosed", async () => {
    const messages = [encoder.encode("msg-a"), encoder.encode("msg-b")];
    const header = encoder.encode("header");
    const presentationHeader = encoder.encode("pres");
    const fixture = await generateTestFixture(messages, header);

    const proof = await bbs.bls12381_sha256.deriveProof({
      publicKey: fixture.publicKey,
      signature: fixture.signature,
      header,
      presentationHeader,
      verifySignature: true,
      messages: messages.map((m) => ({ value: m, reveal: true })),
    });

    const disclosedMessages = new Map<number, Uint8Array>();
    disclosedMessages.set(0, messages[0]);
    disclosedMessages.set(1, messages[1]);

    const result = await verifyBbsProof(
      fixture.publicKey,
      proof,
      header,
      presentationHeader,
      disclosedMessages,
    );

    expect(result.verified).toBe(true);
  });

  it.each([
    {
      name: "invalid proof bytes",
      tweakProof: true,
      useWrongKey: false,
    },
    {
      name: "wrong public key",
      tweakProof: false,
      useWrongKey: true,
    },
  ])("should return verified=false for $name", async ({
    tweakProof,
    useWrongKey,
  }) => {
    const messages = [encoder.encode("test-message")];
    const header = encoder.encode("test-header");
    const presentationHeader = encoder.encode("pres-header");
    const fixture = await generateTestFixture(messages, header);

    let proofBytes = await bbs.bls12381_sha256.deriveProof({
      publicKey: fixture.publicKey,
      signature: fixture.signature,
      header,
      presentationHeader,
      verifySignature: true,
      messages: [{ value: messages[0], reveal: true }],
    });

    if (tweakProof) {
      proofBytes = new Uint8Array(proofBytes);
      proofBytes[0] ^= 0xff;
      proofBytes[10] ^= 0xff;
    }

    let publicKey = fixture.publicKey;
    if (useWrongKey) {
      const otherKeyPair = await bbs.bls12381_sha256.generateKeyPair();
      publicKey = otherKeyPair.publicKey;
    }

    const disclosedMessages = new Map<number, Uint8Array>();
    disclosedMessages.set(0, messages[0]);

    const result = await verifyBbsProof(
      publicKey,
      proofBytes,
      header,
      presentationHeader,
      disclosedMessages,
    );

    expect(result.verified).toBe(false);
  });

  it("should return error for invalid public key length on proof", async () => {
    const disclosedMessages = new Map<number, Uint8Array>();
    disclosedMessages.set(0, encoder.encode("msg"));

    const result = await verifyBbsProof(
      new Uint8Array(48),
      new Uint8Array(100),
      new Uint8Array(),
      new Uint8Array(),
      disclosedMessages,
    );

    expect(result.verified).toBe(false);
    expect(result.error).toContain("public key must be 96 bytes");
    expect(result.error).toContain("got 48");
  });
});

describe("verifyBbsProofWithPseudonym", () => {
  const iosVector = loadPseudonymVector();
  const androidVector = loadPseudonymVector(
    "android-bbs-pseudonym-vector.json",
  );
  const iosInput = makePseudonymInput(iosVector);
  const androidInput = makePseudonymInput(androidVector);

  const vectors = [
    { platform: "iOS", vector: iosVector, input: iosInput },
    { platform: "Android", vector: androidVector, input: androidInput },
  ] as const;

  it.each([
    {
      name: "wrong length (32 bytes)",
      pseudonym: new Uint8Array(32).fill(0xaa),
      errorContains: ["pseudonym must be 48 bytes", "got 32"],
    },
    {
      name: "zero length",
      pseudonym: new Uint8Array(0),
      errorContains: ["pseudonym must be 48 bytes", "got 0"],
    },
    {
      name: "all-zero (identity point)",
      pseudonym: new Uint8Array(48).fill(0x00),
      errorContains: ["must not be the identity point"],
    },
  ])("should reject pseudonym with $name", async ({
    pseudonym,
    errorContains,
  }) => {
    const result = await callVerifyWithPseudonym({ ...iosInput, pseudonym });

    expect(result.verified).toBe(false);
    for (const s of errorContains) {
      expect(result.error).toContain(s);
    }
  });

  it.each(
    vectors,
  )("should verify a valid $platform pseudonym proof vector", async ({
    input,
  }) => {
    const result = await callVerifyWithPseudonym(input);

    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it.each(
    vectors,
  )("should reject $platform vector when scope does not match", async ({
    input,
  }) => {
    const wrongScope = new Uint8Array(input.scope);
    wrongScope[0] ^= 0xff;

    const result = await callVerifyWithPseudonym({
      ...input,
      scope: wrongScope,
    });

    expect(result.verified).toBe(false);
  });

  it.each([
    {
      name: "pseudonym bytes are tampered",
      tweakField: "pseudonym" as const,
    },
    {
      name: "proof bytes are tampered",
      tweakField: "proof" as const,
    },
  ])("should reject when $name", async ({ tweakField }) => {
    const tampered = new Uint8Array(iosInput[tweakField]);
    if (tweakField === "proof") {
      tampered[0] ^= 0xff;
    }
    tampered[10] ^= 0xff;

    const result = await callVerifyWithPseudonym({
      ...iosInput,
      [tweakField]: tampered,
    });

    expect(result.verified).toBe(false);
  });

  it("should return error for invalid public key length", async () => {
    const result = await callVerifyWithPseudonym({
      ...iosInput,
      issuerPublicKey: new Uint8Array(32),
    });

    expect(result.verified).toBe(false);
    expect(result.error).toContain("public key must be 96 bytes");
  });
});
