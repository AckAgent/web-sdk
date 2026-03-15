import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  AnonymousAttestationVerifier,
  buildScopedLinkingStoreScope,
  createAnonymousAttestationVerifier,
  verifyAnonymousAttestation,
  createAnonymousVerifier,
  type AnonymousAttestation,
  type AnonymousAttestationVerifyOptions,
} from "../attestation.js";
import { NullifierStore } from "../nullifier-store.js";

// Mock bbs.ts to avoid loading WASM in unit tests
vi.mock("../bbs.js", () => ({
  verifyBbsProofWithPseudonym: vi.fn().mockResolvedValue({
    verified: true,
  }),
}));

import { verifyBbsProofWithPseudonym } from "../bbs.js";
const mockVerifyBbsProofWithPseudonym = vi.mocked(verifyBbsProofWithPseudonym);

/** Build valid test attestation data. */
function makeAttestation(
  overrides?: Partial<AnonymousAttestation>,
): AnonymousAttestation {
  const futureExpiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  return {
    bbsProof: new Uint8Array(256).fill(0x01),
    pseudonym: new Uint8Array(48).fill(0xaa),
    scope: "request-id-001",
    presentationHeader: new Uint8Array(32).fill(0xbb),
    revealedMessages: {
      attestationType: "ios_secure_enclave",
      deviceType: "ios",
      expiresAt: futureExpiry,
    },
    ...overrides,
  };
}

/** Build a mock 96-byte issuer public key. */
function makeIssuerPublicKey(): Uint8Array {
  return new Uint8Array(96).fill(0xcc);
}

describe("AnonymousAttestationVerifier", () => {
  let verifier: AnonymousAttestationVerifier;

  beforeEach(() => {
    verifier = new AnonymousAttestationVerifier();
    mockVerifyBbsProofWithPseudonym.mockResolvedValue({ verified: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("successful verification", () => {
    it("should verify valid anonymous attestation with direct issuer key", async () => {
      const attestation = makeAttestation();
      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        expectedRequestId: "request-id-001",
      });

      expect(result.valid).toBe(true);
      expect(result.proofValid).toBe(true);
      expect(result.pseudonymVerified).toBe(true);
      expect(result.notExpired).toBe(true);
      expect(result.scopeValid).toBe(true);
      expect(result.attestationType).toBe("ios_secure_enclave");
      expect(result.deviceType).toBe("ios");
      expect(result.errors).toHaveLength(0);
      expect(result.verifiedAt).toBeInstanceOf(Date);
    });

    it("should pass when expectedRequestId is not provided (no scope check)", async () => {
      const attestation = makeAttestation();
      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
      });

      expect(result.valid).toBe(true);
      expect(result.scopeValid).toBe(true);
    });

    it("should verify android attestation type", async () => {
      const attestation = makeAttestation({
        revealedMessages: {
          attestationType: "android_strongbox",
          deviceType: "android",
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
        },
      });
      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
      });

      expect(result.valid).toBe(true);
      expect(result.attestationType).toBe("android_strongbox");
      expect(result.deviceType).toBe("android");
    });
  });

  describe("invalid field rejection", () => {
    const key = () => makeIssuerPublicKey();
    const iosExpiry = (offset: number) => ({
      revealedMessages: {
        attestationType: "ios_secure_enclave" as const,
        deviceType: "ios" as const,
        expiresAt: Math.floor(Date.now() / 1000) + offset,
      },
    });

    it.each([
      {
        name: "scope mismatch",
        overrides: { scope: "wrong-request-id" },
        options: {
          issuerPublicKey: key(),
          expectedRequestId: "expected-request-id",
        },
        errorMatch: "scope mismatch",
        extraCheck: "scopeValid" as const,
      },
      {
        name: "empty scope",
        overrides: { scope: "" },
        options: { issuerPublicKey: key() },
        errorMatch: "scope must not be empty",
        extraCheck: undefined,
      },
      {
        name: "expired credential (1 min ago)",
        overrides: iosExpiry(-60),
        options: { issuerPublicKey: key() },
        errorMatch: "credential expired",
        extraCheck: "notExpired" as const,
      },
      {
        name: "credential at boundary",
        overrides: iosExpiry(0),
        options: { issuerPublicKey: key() },
        errorMatch: undefined,
        extraCheck: "notExpired" as const,
      },
      {
        name: "pseudonym wrong length",
        overrides: { pseudonym: new Uint8Array(32).fill(0xaa) },
        options: { issuerPublicKey: key() },
        errorMatch: "pseudonym must be 48 bytes",
        extraCheck: undefined,
      },
      {
        name: "no issuerPublicKey or credentialClient",
        overrides: {},
        options: {},
        errorMatch:
          "either issuerPublicKey or credentialClient must be provided",
        extraCheck: undefined,
      },
    ])("should reject $name", async ({
      overrides,
      options,
      errorMatch,
      extraCheck,
    }) => {
      const result = await verifier.verify(
        makeAttestation(overrides as Partial<AnonymousAttestation>),
        options,
      );
      expect(result.valid).toBe(false);
      if (errorMatch)
        expect(result.errors.some((e) => e.includes(errorMatch))).toBe(true);
      if (extraCheck) expect(result[extraCheck]).toBe(false);
    });
  });

  describe("pseudonym validation", () => {
    it("should include hex-encoded pseudonym in result", async () => {
      const pseudonym = new Uint8Array(48);
      pseudonym[0] = 0xde;
      pseudonym[1] = 0xad;
      pseudonym[47] = 0xff;
      const attestation = makeAttestation({ pseudonym });

      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
      });

      expect(result.pseudonymHex).toMatch(/^dead/);
      expect(result.pseudonymHex).toMatch(/ff$/);
      expect(result.pseudonymHex.length).toBe(96); // 48 bytes * 2 hex chars
    });
  });

  describe("issuer public key resolution", () => {
    function makeCredentialClient(getBbsOverride?: ReturnType<typeof vi.fn>) {
      return {
        getBbsPublicKey:
          getBbsOverride ??
          vi.fn().mockResolvedValue({ publicKeyBytes: makeIssuerPublicKey() }),
        getIssuerPublicKeys: vi.fn(),
        invalidateCache: vi.fn(),
      };
    }

    it("should use credentialClient when issuerPublicKey not provided", async () => {
      const mockClient = makeCredentialClient();
      const result = await verifier.verify(makeAttestation(), {
        credentialClient: mockClient as never,
      });

      expect(result.valid).toBe(true);
      expect(mockClient.getBbsPublicKey).toHaveBeenCalledTimes(1);
    });

    it("should handle credentialClient fetch failure", async () => {
      const mockClient = makeCredentialClient(
        vi.fn().mockRejectedValue(new Error("network down")),
      );
      const result = await verifier.verify(makeAttestation(), {
        credentialClient: mockClient as never,
      });

      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) =>
          e.includes("failed to fetch issuer public key"),
        ),
      ).toBe(true);
      expect(result.errors.some((e) => e.includes("network down"))).toBe(true);
    });

    it.each([
      {
        name: "with key ID",
        keyId: "key-v2-2026" as string | undefined,
        expectedArg: "key-v2-2026",
      },
      {
        name: "without key ID",
        keyId: undefined as string | undefined,
        expectedArg: undefined,
      },
    ])("should call getBbsPublicKey $name", async ({ keyId, expectedArg }) => {
      const mockClient = makeCredentialClient();
      const result = await verifier.verify(
        makeAttestation(keyId ? { issuerPublicKeyId: keyId } : {}),
        { credentialClient: mockClient as never },
      );

      expect(result.valid).toBe(true);
      expect(mockClient.getBbsPublicKey).toHaveBeenCalledWith(expectedArg);
    });

    it("should prefer direct issuerPublicKey over credentialClient", async () => {
      const mockClient = makeCredentialClient();
      const result = await verifier.verify(makeAttestation(), {
        issuerPublicKey: makeIssuerPublicKey(),
        credentialClient: mockClient as never,
      });

      expect(result.valid).toBe(true);
      expect(mockClient.getBbsPublicKey).not.toHaveBeenCalled();
    });
  });

  describe("BBS+ proof verification", () => {
    it.each([
      {
        name: "with error message",
        mockReturn: { verified: false, error: "invalid proof signature" },
        expectedError: "invalid proof signature",
      },
      {
        name: "without error message",
        mockReturn: { verified: false },
        expectedError: "BBS+ proof verification failed",
      },
    ])("should fail $name", async ({ mockReturn, expectedError }) => {
      mockVerifyBbsProofWithPseudonym.mockResolvedValue(mockReturn);
      const result = await verifier.verify(makeAttestation(), {
        issuerPublicKey: makeIssuerPublicKey(),
      });

      expect(result.valid).toBe(false);
      expect(result.proofValid).toBe(false);
      expect(result.errors).toContain(expectedError);
    });

    it("should pass correct parameters to verifyBbsProofWithPseudonym", async () => {
      mockVerifyBbsProofWithPseudonym.mockClear();
      mockVerifyBbsProofWithPseudonym.mockResolvedValue({ verified: true });

      const attestation = makeAttestation();
      const issuerPublicKey = makeIssuerPublicKey();

      await verifier.verify(attestation, {
        issuerPublicKey,
        expectedRequestId: "request-id-001",
      });

      expect(mockVerifyBbsProofWithPseudonym).toHaveBeenCalledTimes(1);
      const callArgs = mockVerifyBbsProofWithPseudonym.mock.calls[0];

      // issuerPublicKey
      expect(callArgs[0]).toBe(issuerPublicKey);
      // bbsProof
      expect(callArgs[1]).toStrictEqual(attestation.bbsProof);
      // pseudonym
      expect(callArgs[2]).toStrictEqual(attestation.pseudonym);
      // header (credential header UTF-8)
      expect(new TextDecoder().decode(callArgs[3])).toBe(
        "ackagent-anonymous-attestation-v2",
      );
      // presentationHeader
      expect(callArgs[4]).toStrictEqual(attestation.presentationHeader);
      // scope (UTF-8)
      expect(new TextDecoder().decode(callArgs[5])).toBe("request-id-001");
      // disclosedMessages (Map with indices 0, 1, 3)
      const disclosedMessages = callArgs[6] as Map<number, Uint8Array>;
      expect(disclosedMessages.size).toBe(3);
      expect(disclosedMessages.has(0)).toBe(true); // attestationType
      expect(disclosedMessages.has(1)).toBe(true); // deviceType
      expect(disclosedMessages.has(2)).toBe(false); // issuedAt is hidden
      expect(disclosedMessages.has(3)).toBe(true); // expiresAt
      // Verify string encoding
      expect(new TextDecoder().decode(disclosedMessages.get(0))).toBe(
        "ios_secure_enclave",
      );
      expect(new TextDecoder().decode(disclosedMessages.get(1))).toBe("ios");
      // Verify int64 big-endian encoding of expiresAt
      const expiresAtBytes = disclosedMessages.get(3);
      expect(expiresAtBytes).toBeDefined();
      expect(expiresAtBytes?.length).toBe(8);
      // totalSignerMessages
      expect(callArgs[7]).toBe(4);
      // disclosedCommittedMessages (empty Map)
      expect((callArgs[8] as Map<number, Uint8Array>).size).toBe(0);
      // disclosedCommitmentIndices (empty array)
      expect((callArgs[9] as number[]).length).toBe(0);
    });
  });

  describe("pseudonym replay prevention", () => {
    it("should accept first use of a pseudonym", async () => {
      const attestation = makeAttestation();
      const nullifierStore = new NullifierStore("test-anon-pseudonyms");

      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        nullifierStore,
      });

      expect(result.valid).toBe(true);
    });

    it("should reject replay of same pseudonym for same scope", async () => {
      const attestation = makeAttestation();
      const nullifierStore = new NullifierStore("test-replay-pseudonyms");

      const options: AnonymousAttestationVerifyOptions = {
        issuerPublicKey: makeIssuerPublicKey(),
        nullifierStore,
      };

      // First verification passes
      const result1 = await verifier.verify(attestation, options);
      expect(result1.valid).toBe(true);

      // Second verification with same pseudonym+scope fails
      const result2 = await verifier.verify(attestation, options);
      expect(result2.valid).toBe(false);
      expect(result2.errors).toContain("pseudonym already used for this scope");
    });

    it("should accept same pseudonym for different scopes", async () => {
      const pseudonym = new Uint8Array(48).fill(0xdd);
      const nullifierStore = new NullifierStore("test-scope-pseudonyms");
      const options: AnonymousAttestationVerifyOptions = {
        issuerPublicKey: makeIssuerPublicKey(),
        nullifierStore,
      };

      const attestation1 = makeAttestation({ pseudonym, scope: "scope-alpha" });
      const attestation2 = makeAttestation({ pseudonym, scope: "scope-beta" });

      const result1 = await verifier.verify(attestation1, options);
      expect(result1.valid).toBe(true);

      const result2 = await verifier.verify(attestation2, options);
      expect(result2.valid).toBe(true);
    });

    it("should not record pseudonym when proof verification fails", async () => {
      mockVerifyBbsProofWithPseudonym.mockResolvedValue({
        verified: false,
        error: "bad proof",
      });

      const attestation = makeAttestation();
      const nullifierStore = new NullifierStore("test-no-record-pseudonyms");

      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        nullifierStore,
      });

      expect(result.valid).toBe(false);
      expect(nullifierStore.size).toBe(0);
    });
  });

  describe("scoped linking policy (AA-06 prototype)", () => {
    it("should reject when scoped linking is required but missing", async () => {
      const attestation = makeAttestation();
      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        scopedLinking: {
          scopeType: "organization",
          scopeId: "org_123",
        },
      });

      expect(result.valid).toBe(false);
      expect(result.scopedLinkingVerified).toBe(false);
      expect(result.errors).toContain(
        "scoped linking enabled but attestation.scopedLinking is missing",
      );
    });

    it("should enforce scoped linking scope and record first-seen handle", async () => {
      const attestation = makeAttestation({
        scopedLinking: {
          mode: "pairwise_account_secret",
          scopeType: "organization",
          scopeId: "org_123",
          linkHandle: "Q2NvdW50TGluazEyMzQ1Njc4OTBhYmNk",
        },
      });
      const linkStore = new NullifierStore("test-scoped-linking");

      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        scopedLinking: {
          scopeType: "organization",
          scopeId: "org_123",
          store: linkStore,
        },
      });

      expect(result.valid).toBe(true);
      expect(result.scopedLinkingVerified).toBe(true);
      expect(result.scopedLinkingScope).toBe(
        "ackagent_link:organization:org_123",
      );
      expect(result.scopedLinkingHandle).toBe(
        "q2nvdw50tgluazeymzq1njc4otbhymnk",
      );
      expect(result.scopedLinkingSeenBefore).toBe(false);
    });

    it("should mark scoped linking handle as seen before on subsequent proofs", async () => {
      const linkStore = new NullifierStore("test-scoped-linking-reuse");
      const scopedLinking = {
        mode: "pairwise_account_secret" as const,
        scopeType: "relying_party" as const,
        scopeId: "rp_example",
        linkHandle: "ZXhhbXBsZS1saW5rLWhhbmRsZS0wMDAx",
      };
      const options = {
        issuerPublicKey: makeIssuerPublicKey(),
        scopedLinking: {
          scopeType: "relying_party" as const,
          scopeId: "rp_example",
          store: linkStore,
        },
      };

      const first = await verifier.verify(
        makeAttestation({ scope: "request-a", scopedLinking }),
        options,
      );
      const second = await verifier.verify(
        makeAttestation({ scope: "request-b", scopedLinking }),
        options,
      );

      expect(first.valid).toBe(true);
      expect(first.scopedLinkingSeenBefore).toBe(false);
      expect(second.valid).toBe(true);
      expect(second.scopedLinkingSeenBefore).toBe(true);
    });

    it("should reject scoped linking scope mismatch", async () => {
      const attestation = makeAttestation({
        scopedLinking: {
          mode: "pairwise_account_secret",
          scopeType: "organization",
          scopeId: "org_abc",
          linkHandle: "YWNjb3VudC1saW5rLWhhbmRsZS0xMjM0NTY",
        },
      });

      const result = await verifier.verify(attestation, {
        issuerPublicKey: makeIssuerPublicKey(),
        scopedLinking: {
          scopeType: "organization",
          scopeId: "org_expected",
        },
      });

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'scoped linking scopeId mismatch: expected "org_expected", got "org_abc"',
      );
    });
  });
});

describe("buildScopedLinkingStoreScope", () => {
  it("should build a namespaced scope for scoped linking", () => {
    expect(buildScopedLinkingStoreScope("relying_party", "rp_main")).toBe(
      "ackagent_link:relying_party:rp_main",
    );
  });

  it("should reject invalid scope IDs", () => {
    expect(() =>
      buildScopedLinkingStoreScope("organization", "bad scope id"),
    ).toThrow(/invalid scoped linking scopeId/i);
  });
});

describe("convenience functions", () => {
  beforeEach(() => {
    mockVerifyBbsProofWithPseudonym.mockResolvedValue({ verified: true });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("createAnonymousAttestationVerifier should return verifier instance", () => {
    expect(createAnonymousAttestationVerifier()).toBeInstanceOf(
      AnonymousAttestationVerifier,
    );
  });

  it("verifyAnonymousAttestation should verify via convenience function", async () => {
    const result = await verifyAnonymousAttestation(makeAttestation(), {
      issuerPublicKey: makeIssuerPublicKey(),
    });
    expect(result.valid).toBe(true);
  });

  it("createAnonymousVerifier should create a verifier and nullifier store pair", () => {
    const { verifier, nullifierStore } = createAnonymousVerifier();
    expect(verifier).toBeInstanceOf(AnonymousAttestationVerifier);
    expect(nullifierStore).toBeInstanceOf(NullifierStore);
  });

  it("createAnonymousVerifier should accept custom storage key", () => {
    const { nullifierStore } = createAnonymousVerifier("custom_key");
    nullifierStore.markSpent("test-scope", "test-value");
    expect(nullifierStore.isSpent("test-scope", "test-value")).toBe(true);
  });
});
