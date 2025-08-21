/**
 * Type definitions for Go WebAssembly runtime.
 */

declare global {
  class Go {
    constructor();
    importObject: WebAssembly.Imports;
    run(instance: WebAssembly.Instance): Promise<void>;
    exited: boolean;
    exit(code: number): void;
  }
}

export {};
