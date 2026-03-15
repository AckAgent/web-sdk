/* tslint:disable */
/* eslint-disable */

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly uniffi_bbs_ffi_checksum_func_bbs_blind_sign_with_nym: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_commit_with_nym: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_generate_keypair: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_generate_nym_secret: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_proof_gen: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_proof_gen_with_nym: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_proof_verify: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_proof_verify_with_nym: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_sign: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_verify: () => number;
    readonly uniffi_bbs_ffi_checksum_func_bbs_verify_blind_sign_with_nym: () => number;
    readonly uniffi_bbs_ffi_checksum_func_parse_bbs_credential: () => number;
    readonly uniffi_bbs_ffi_fn_func_bbs_blind_sign_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_commit_with_nym: (a: number, b: number, c: number, d: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_generate_keypair: (a: number, b: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_generate_nym_secret: (a: number, b: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_proof_gen: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_proof_gen_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_proof_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly uniffi_bbs_ffi_fn_func_bbs_proof_verify_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => number;
    readonly uniffi_bbs_ffi_fn_func_bbs_sign: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly uniffi_bbs_ffi_fn_func_bbs_verify: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly uniffi_bbs_ffi_fn_func_bbs_verify_blind_sign_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
    readonly uniffi_bbs_ffi_fn_func_parse_bbs_credential: (a: number, b: number, c: number) => void;
    readonly bbs_ffi_alloc: (a: number, b: number) => number;
    readonly bbs_ffi_blind_sign_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => number;
    readonly bbs_ffi_commit_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly bbs_ffi_dealloc: (a: number, b: number, c: number) => void;
    readonly bbs_ffi_free_buffer: (a: number) => void;
    readonly bbs_ffi_generate_keypair: (a: number, b: number) => number;
    readonly bbs_ffi_generate_nym_secret: (a: number) => number;
    readonly bbs_ffi_proof_gen: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => number;
    readonly bbs_ffi_proof_gen_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number, w: number, x: number) => number;
    readonly bbs_ffi_proof_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => number;
    readonly bbs_ffi_proof_verify_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number) => number;
    readonly bbs_ffi_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
    readonly bbs_ffi_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
    readonly bbs_ffi_verify_blind_sign_with_nym: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => number;
    readonly __wbindgen_export: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
