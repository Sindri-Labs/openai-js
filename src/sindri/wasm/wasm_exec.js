/**
 * Go WASM runtime stub.
 * This file will be replaced during the build process with the actual Go WASM runtime.
 */

// Stub implementation that will be replaced at build time.
if (typeof global !== 'undefined') {
  global.Go = class Go {
    constructor() {
      throw new Error('WASM runtime not built. Please run the nix build process to generate the WASM runtime.');
    }
  };
}