/**
 * Stub TypeScript module for WASM integration.
 * This file is replaced at build time with the actual WASM binary embedded as base64.
 */

/**
 * Returns the WASM binary as a Uint8Array.
 * At build time, this is replaced with the actual WASM bytes embedded as base64.
 */
export function getWasmBytes(): Uint8Array {
  throw new Error('WASM module not built. Run "nix build" to build the WASM module with embedded binary.');
}
