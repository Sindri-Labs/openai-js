/**
 * WASM module loader stub.
 * This file will be replaced during the build process with the actual WASM loader.
 */

// Stub implementation that will be replaced at build time.
function getWasmBytes() {
  throw new Error('WASM module not built. Please run the nix build process to generate the WASM module.');
}

module.exports = { getWasmBytes };
