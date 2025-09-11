/**
 * TypeScript declarations for the WASM module.
 */

/**
 * Get the WASM bytes for initialization.
 * This is replaced at build time with the actual WASM binary embedded as base64.
 */
export declare function getWasmBytes(): Uint8Array;

/**
 * Global Go instance for WASM execution.
 */
declare global {
  var Go: any;
  var wasmInstance: WebAssembly.Instance | undefined;
  var wasmModule: WebAssembly.Module | undefined;
}

export {};