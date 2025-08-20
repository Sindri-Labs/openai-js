/**
 * WASM module loader.
 * This file will be replaced during the build process with the actual WASM bytes.
 */

// Placeholder for the WASM module.
// During build, this will be replaced with the actual base64-encoded WASM.
const WASM_BASE64 = 'WASM_MODULE_PLACEHOLDER';

/**
 * Get the WASM module as a Uint8Array.
 */
export function getWasmBytes(): Uint8Array {
  if (WASM_BASE64 === 'WASM_MODULE_PLACEHOLDER') {
    throw new Error('WASM module not built. Please run the build process to generate the WASM module.');
  }

  // Decode base64 to Uint8Array.
  const binaryString = atob(WASM_BASE64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
