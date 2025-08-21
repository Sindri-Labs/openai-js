/**
 * Sindri TEE integration module for OpenAI SDK.
 * This module provides WebAssembly-based TEE attestation and encryption.
 */

// Type definitions for the WASM module.
interface WASMExports {
  helloWorld: () => void;
  add: (a: number, b: number) => number;
  multiply: (a: number, b: number) => number;
  incrementCounter: () => number;
  getCounter: () => number;
  resetCounter: () => void;
  addToAccumulator: (value: number) => number;
  getAccumulator: () => number;
  resetAccumulator: () => void;
  getLastResult: () => number;
  memory: any; // WebAssembly.Memory not available in Node types.
}

interface WASMInstance {
  exports: WASMExports;
}

export interface TEEConfig {
  // Future configuration options for TEE.
  debug?: boolean;
}

/**
 * SindriTEE provides TEE attestation and encryption capabilities.
 */
export class SindriTEE {
  private static instance: SindriTEE | null = null;
  private static wasmInstance: WASMInstance | null = null;
  private static initialized = false;
  private static goInstance: any = null;

  /**
   * Initialize the TEE module.
   */
  static async initialize(config: TEEConfig = {}): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      await this.loadWASM(config);
      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize SindriTEE:', error);
      throw error;
    }
  }

  /**
   * Load and instantiate the WASM module.
   */
  private static async loadWASM(config: TEEConfig): Promise<void> {
    // Dynamically import the runtime first.
    // @ts-ignore - wasm_exec.js is not a TypeScript module.
    await import('./wasm/wasm_exec.js');

    // Initialize Go runtime if available (for syscall/js functions).
    if ((globalThis as any).Go) {
      this.goInstance = new (globalThis as any).Go();
    }

    // Import the WASM module with embedded base64.
    // @ts-ignore - wasm.js is generated at build time.
    const wasmModule = await import('./wasm/wasm.js');

    // Get the WASM bytes.
    const wasmBytes = wasmModule.getWasmBytes();

    // Instantiate the WASM module.
    const importObject = this.goInstance?.importObject || {};
    // WebAssembly is available in both Node.js and browsers.
    const wasmResult = await (globalThis as any).WebAssembly.instantiate(wasmBytes, importObject);
    this.wasmInstance = wasmResult.instance as WASMInstance;

    // Run the Go runtime if available (for syscall/js functions).
    // With TinyGo and //export, this is optional.
    if (this.goInstance && this.goInstance.run) {
      // TinyGo doesn't block on run(), so we can call it without await.
      this.goInstance.run(this.wasmInstance);
    }

    if (config.debug) {
      console.log('SindriTEE WASM module loaded successfully');
      console.log('Available exports:', Object.keys(this.wasmInstance.exports));
    }
  }

  /**
   * Check if the TEE module is initialized.
   */
  static isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get the WASM instance exports.
   */
  static getExports(): WASMExports | null {
    return this.wasmInstance?.exports || null;
  }

  /**
   * Call the helloWorld function.
   */
  static helloWorld(): void {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    this.wasmInstance.exports.helloWorld();
  }

  /**
   * Call the add function.
   */
  static add(a: number, b: number): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.add(a, b);
  }

  /**
   * Call the multiply function.
   */
  static multiply(a: number, b: number): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.multiply(a, b);
  }

  /**
   * Increment and return the global counter.
   */
  static incrementCounter(): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.incrementCounter();
  }

  /**
   * Get the current counter value.
   */
  static getCounter(): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.getCounter();
  }

  /**
   * Reset the counter to zero.
   */
  static resetCounter(): void {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    this.wasmInstance.exports.resetCounter();
  }

  /**
   * Add a value to the accumulator and return the new total.
   */
  static addToAccumulator(value: number): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.addToAccumulator(value);
  }

  /**
   * Get the current accumulator value.
   */
  static getAccumulator(): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.getAccumulator();
  }

  /**
   * Reset the accumulator to zero.
   */
  static resetAccumulator(): void {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    this.wasmInstance.exports.resetAccumulator();
  }

  /**
   * Get the result of the last add or multiply operation.
   */
  static getLastResult(): number {
    if (!this.wasmInstance) {
      throw new Error('SindriTEE not initialized. Call initialize() first.');
    }
    return this.wasmInstance.exports.getLastResult();
  }
}
