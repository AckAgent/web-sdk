/**
 * WASM bridge for bbs-ffi pseudonym proof verification.
 *
 * This module loads the Rust bbs-ffi WASM artifact and calls the low-level
 * C-ABI verifier (`bbs_ffi_proof_verify_with_nym`) to perform cryptographic
 * pseudonym binding verification.
 */

import initBbsFfiWasm, {
  type InitOutput,
} from "./generated/bbs_ffi_wasm/bbs_ffi.js";

/** FFI result code for success. */
const BBS_FFI_OK = 0;

/** Memory alignment for byte buffers. */
const ALIGN_U8 = 1;
/** Memory alignment for u32/int32 values and structs. */
const ALIGN_U32 = 4;
/** Size of `BbsMessage` C struct: `data: u32` + `len: u32`. */
const BBS_MESSAGE_STRUCT_SIZE = 8;
/** int32 byte length. */
const I32_BYTE_LENGTH = 4;

/** Raw allocation tracked for deterministic cleanup. */
interface Allocation {
  ptr: number;
  len: number;
  align: number;
}

/** Pointer + count for FFI message arrays. */
interface MessageArrayPointer {
  ptr: number;
  count: number;
}

/** Pointer + count for FFI u32 arrays. */
interface U32ArrayPointer {
  ptr: number;
  count: number;
}

/** Result of WASM pseudonym verification. */
export interface BbsFfiWasmVerifyResult {
  /** Whether proof + pseudonym verification succeeded. */
  verified: boolean;
  /** Optional error context when verification could not complete. */
  error?: string;
}

/** Minimal shape for runtime Node.js process detection. */
interface NodeProcessShape {
  versions?: {
    node?: string;
  };
}

let wasmInitPromise: Promise<InitOutput> | null = null;

/**
 * Verify a BBS+ selective disclosure proof with scope-bound pseudonym.
 *
 * @param issuerPublicKey - 96-byte BLS12-381 issuer public key
 * @param proof - Serialized BBS+ proof
 * @param pseudonym - 48-byte pseudonym bound to scope
 * @param header - Credential header used at signing
 * @param presentationHeader - Per-presentation binding header
 * @param scope - Scope for pseudonym derivation/verification
 * @param disclosedMessages - Disclosed signer messages keyed by signer index
 * @param totalSignerMessages - Total count of signer messages in the credential
 * @param disclosedCommittedMessages - Disclosed committed messages keyed by committed index
 * @param disclosedCommitmentIndices - Indices of disclosed committed messages
 * @returns Verification result
 */
export async function verifyBbsProofWithPseudonymWasm(
  issuerPublicKey: Uint8Array,
  proof: Uint8Array,
  pseudonym: Uint8Array,
  header: Uint8Array,
  presentationHeader: Uint8Array,
  scope: Uint8Array,
  disclosedMessages: Map<number, Uint8Array>,
  totalSignerMessages: number,
  disclosedCommittedMessages: Map<number, Uint8Array>,
  disclosedCommitmentIndices: number[],
): Promise<BbsFfiWasmVerifyResult> {
  const allocations: Allocation[] = [];

  try {
    const wasm = await getWasm();

    const disclosedPairs = sortDisclosedMessages(disclosedMessages);
    const disclosedIndices = disclosedPairs.map(([index]) => index);
    const disclosedMessageValues = disclosedPairs.map(([, value]) => value);

    const committedDisclosure = normalizeCommittedDisclosures(
      disclosedCommittedMessages,
      disclosedCommitmentIndices,
    );

    const issuerRegion = writeBytes(wasm, issuerPublicKey, allocations);
    const proofRegion = writeBytes(wasm, proof, allocations);
    const pseudonymRegion = writeBytes(wasm, pseudonym, allocations);
    const headerRegion = writeBytes(wasm, header, allocations);
    const presentationHeaderRegion = writeBytes(
      wasm,
      presentationHeader,
      allocations,
    );
    const scopeRegion = writeBytes(wasm, scope, allocations);

    const disclosedMessageRegion = writeMessageArray(
      wasm,
      disclosedMessageValues,
      allocations,
    );
    const disclosedCommittedMessageRegion = writeMessageArray(
      wasm,
      committedDisclosure.messages,
      allocations,
    );

    const disclosedIndexRegion = writeU32Array(
      wasm,
      disclosedIndices,
      allocations,
    );
    const disclosedCommittedIndexRegion = writeU32Array(
      wasm,
      committedDisclosure.indices,
      allocations,
    );

    const validOutRegion = allocRegion(
      wasm,
      I32_BYTE_LENGTH,
      ALIGN_U32,
      allocations,
    );
    writeInt32(wasm, validOutRegion.ptr, 0);

    const ffiResult = wasm.bbs_ffi_proof_verify_with_nym(
      issuerRegion.ptr,
      issuerRegion.len,
      proofRegion.ptr,
      proofRegion.len,
      pseudonymRegion.ptr,
      pseudonymRegion.len,
      headerRegion.ptr,
      headerRegion.len,
      presentationHeaderRegion.ptr,
      presentationHeaderRegion.len,
      scopeRegion.ptr,
      scopeRegion.len,
      totalSignerMessages >>> 0,
      disclosedMessageRegion.ptr,
      disclosedMessageRegion.count,
      disclosedCommittedMessageRegion.ptr,
      disclosedCommittedMessageRegion.count,
      disclosedIndexRegion.ptr,
      disclosedIndexRegion.count,
      disclosedCommittedIndexRegion.ptr,
      disclosedCommittedIndexRegion.count,
      validOutRegion.ptr,
    );

    if (ffiResult !== BBS_FFI_OK) {
      return {
        verified: false,
        error: mapFfiResultToError(ffiResult),
      };
    }

    const validValue = readInt32(wasm, validOutRegion.ptr);
    if (validValue === 1) {
      return { verified: true };
    }

    return {
      verified: false,
      error: "BBS+ proof or pseudonym binding invalid",
    };
  } catch (err) {
    return {
      verified: false,
      error: `WASM pseudonym verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    const wasm = await getWasm().catch(() => null);
    if (wasm) {
      freeRegions(wasm, allocations);
    }
  }
}

/**
 * Lazily initialize and cache the WASM instance.
 *
 * @returns Initialized WASM exports
 */
async function getWasm(): Promise<InitOutput> {
  if (!wasmInitPromise) {
    wasmInitPromise = initializeWasm().catch((err) => {
      wasmInitPromise = null;
      throw err;
    });
  }
  return wasmInitPromise;
}

/**
 * Initialize the bbs-ffi WASM module.
 *
 * In browsers, the generated loader fetches the sibling `.wasm` URL.
 * In Node.js, file URL fetch can fail, so we load bytes via fs.
 *
 * @returns Initialized WASM exports
 */
async function initializeWasm(): Promise<InitOutput> {
  const wasmUrl = new URL(
    "./generated/bbs_ffi_wasm/bbs_ffi_bg.wasm",
    import.meta.url,
  );

  if (isNodeRuntime()) {
    const wasmBytes = await readWasmFileNode(wasmUrl);
    return initBbsFfiWasm({ module_or_path: wasmBytes });
  }

  return initBbsFfiWasm({ module_or_path: wasmUrl });
}

/**
 * Detect whether the current runtime is Node.js.
 *
 * @returns true when running under Node.js
 */
function isNodeRuntime(): boolean {
  const maybeProcess = (globalThis as { process?: NodeProcessShape }).process;
  return typeof maybeProcess?.versions?.node === "string";
}

/**
 * Read the WASM artifact from disk in Node.js.
 *
 * Uses runtime dynamic import to avoid bundling Node builtins in browser builds.
 *
 * @param wasmUrl - URL of the wasm file
 * @returns Raw wasm bytes
 */
async function readWasmFileNode(wasmUrl: URL): Promise<Uint8Array> {
  const specifier = "node:fs/promises";
  const dynamicImport = import(specifier) as Promise<{
    readFile: (url: URL) => Promise<Uint8Array>;
  }>;
  const fsPromises = await dynamicImport;
  return fsPromises.readFile(wasmUrl);
}

/**
 * Allocate a region in wasm memory and register it for cleanup.
 *
 * @param wasm - WASM exports
 * @param len - Number of bytes
 * @param align - Required alignment
 * @param allocations - Allocation tracking list
 * @returns Allocated region descriptor
 */
function allocRegion(
  wasm: InitOutput,
  len: number,
  align: number,
  allocations: Allocation[],
): Allocation {
  if (len === 0) {
    return { ptr: 0, len: 0, align };
  }

  const ptr = wasm.bbs_ffi_alloc(len, align);
  if (ptr === 0) {
    throw new Error(`bbs_ffi_alloc failed for ${len} bytes (align=${align})`);
  }

  const allocation: Allocation = { ptr, len, align };
  allocations.push(allocation);
  return allocation;
}

/**
 * Write bytes into wasm memory.
 *
 * @param wasm - WASM exports
 * @param bytes - Input bytes
 * @param allocations - Allocation tracking list
 * @returns Allocated region descriptor
 */
function writeBytes(
  wasm: InitOutput,
  bytes: Uint8Array,
  allocations: Allocation[],
): Allocation {
  const allocation = allocRegion(wasm, bytes.length, ALIGN_U8, allocations);
  if (allocation.ptr !== 0 && allocation.len > 0) {
    new Uint8Array(wasm.memory.buffer, allocation.ptr, allocation.len).set(
      bytes,
    );
  }
  return allocation;
}

/**
 * Encode a `BbsMessage[]` equivalent into wasm memory.
 *
 * @param wasm - WASM exports
 * @param messages - Message byte arrays
 * @param allocations - Allocation tracking list
 * @returns Pointer and count for FFI call
 */
function writeMessageArray(
  wasm: InitOutput,
  messages: Uint8Array[],
  allocations: Allocation[],
): MessageArrayPointer {
  if (messages.length === 0) {
    return { ptr: 0, count: 0 };
  }

  const messageRegions = messages.map((message) =>
    writeBytes(wasm, message, allocations),
  );

  const structsByteLen = messages.length * BBS_MESSAGE_STRUCT_SIZE;
  const structs = allocRegion(wasm, structsByteLen, ALIGN_U32, allocations);

  const view = new DataView(wasm.memory.buffer);
  for (let i = 0; i < messageRegions.length; i++) {
    const base = structs.ptr + i * BBS_MESSAGE_STRUCT_SIZE;
    view.setUint32(base, messageRegions[i].ptr >>> 0, true);
    view.setUint32(base + 4, messageRegions[i].len >>> 0, true);
  }

  return {
    ptr: structs.ptr,
    count: messages.length,
  };
}

/**
 * Write u32 values into wasm memory.
 *
 * @param wasm - WASM exports
 * @param values - u32 values
 * @param allocations - Allocation tracking list
 * @returns Pointer and count for FFI call
 */
function writeU32Array(
  wasm: InitOutput,
  values: number[],
  allocations: Allocation[],
): U32ArrayPointer {
  if (values.length === 0) {
    return { ptr: 0, count: 0 };
  }

  const byteLen = values.length * 4;
  const allocation = allocRegion(wasm, byteLen, ALIGN_U32, allocations);
  const view = new DataView(wasm.memory.buffer);

  for (let i = 0; i < values.length; i++) {
    view.setUint32(allocation.ptr + i * 4, values[i] >>> 0, true);
  }

  return {
    ptr: allocation.ptr,
    count: values.length,
  };
}

/**
 * Write int32 into wasm memory.
 *
 * @param wasm - WASM exports
 * @param ptr - Destination pointer
 * @param value - int32 value
 */
function writeInt32(wasm: InitOutput, ptr: number, value: number): void {
  const view = new DataView(wasm.memory.buffer);
  view.setInt32(ptr, value, true);
}

/**
 * Read int32 from wasm memory.
 *
 * @param wasm - WASM exports
 * @param ptr - Source pointer
 * @returns int32 value
 */
function readInt32(wasm: InitOutput, ptr: number): number {
  const view = new DataView(wasm.memory.buffer);
  return view.getInt32(ptr, true);
}

/**
 * Free all tracked allocations in reverse order.
 *
 * @param wasm - WASM exports
 * @param allocations - Allocation tracking list
 */
function freeRegions(wasm: InitOutput, allocations: Allocation[]): void {
  for (let i = allocations.length - 1; i >= 0; i--) {
    const allocation = allocations[i];
    if (allocation.ptr !== 0 && allocation.len > 0) {
      wasm.bbs_ffi_dealloc(allocation.ptr, allocation.len, allocation.align);
    }
  }
}

/**
 * Sort and validate disclosed signer messages by index.
 *
 * @param disclosedMessages - Map of disclosed signer messages
 * @returns Sorted disclosure pairs [index, bytes]
 */
function sortDisclosedMessages(
  disclosedMessages: Map<number, Uint8Array>,
): Array<[number, Uint8Array]> {
  const pairs = Array.from(disclosedMessages.entries());
  pairs.sort((a, b) => a[0] - b[0]);

  for (const [index] of pairs) {
    validateIndex(index, "disclosed message index");
  }

  return pairs;
}

/**
 * Normalize disclosed committed messages and indices.
 *
 * @param disclosedCommittedMessages - Map of disclosed committed messages
 * @param disclosedCommitmentIndices - Explicit disclosed committed indices
 * @returns Normalized indices + message values in matching order
 */
function normalizeCommittedDisclosures(
  disclosedCommittedMessages: Map<number, Uint8Array>,
  disclosedCommitmentIndices: number[],
): { indices: number[]; messages: Uint8Array[] } {
  if (
    disclosedCommittedMessages.size === 0 &&
    disclosedCommitmentIndices.length === 0
  ) {
    return {
      indices: [],
      messages: [],
    };
  }

  if (disclosedCommitmentIndices.length > 0) {
    const messages: Uint8Array[] = [];
    for (const index of disclosedCommitmentIndices) {
      validateIndex(index, "disclosed committed message index");
      const message = disclosedCommittedMessages.get(index);
      if (!message) {
        throw new Error(
          `missing disclosed committed message for index ${index}`,
        );
      }
      messages.push(message);
    }

    return {
      indices: disclosedCommitmentIndices,
      messages,
    };
  }

  const pairs = Array.from(disclosedCommittedMessages.entries()).sort(
    (a, b) => a[0] - b[0],
  );

  for (const [index] of pairs) {
    validateIndex(index, "disclosed committed message index");
  }

  return {
    indices: pairs.map(([index]) => index),
    messages: pairs.map(([, value]) => value),
  };
}

/**
 * Validate disclosure index shape.
 *
 * @param value - Candidate index
 * @param label - Error context label
 */
function validateIndex(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer, got ${value}`);
  }
}

/**
 * Convert `BbsFfiResult` code into an actionable error message.
 *
 * @param code - FFI result code
 * @returns Descriptive error message
 */
function mapFfiResultToError(code: number): string {
  switch (code) {
    case 1:
      return "BBS FFI key generation failed";
    case 2:
      return "BBS FFI signing failed";
    case 3:
      return "BBS FFI verification failed";
    case 4:
      return "BBS FFI invalid input";
    case 5:
      return "BBS FFI proof generation failed";
    case 6:
      return "BBS FFI proof verification failed";
    case 7:
      return "BBS FFI commitment failed";
    default:
      return `BBS FFI error code ${code}`;
  }
}
