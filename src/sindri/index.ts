/**
 * Sindri TEE integration module for OpenAI SDK.
 * This module provides WebAssembly-based HPKE encryption for secure communication with Sindri's TEE.
 */

import type { OpenAI } from '../client';
import type { SindriTEEConfig, SindriClientConfig, EncryptionConfig } from './types';

// Type definitions for the WASM module functions matching the new Go interface.
interface SindriWASMFunctions {
  sindri_initialize: (configJSON: string) => {
    success?: boolean;
    message?: string;
    error?: string;
  };
  sindri_chatCompletion: (requestBody: string) => Promise<{
    response?: string;
    status?: number;
    error?: string;
  }>;
  sindri_getServerPublicKey: () => {
    publicKey?: string;
    error?: string;
  };
  sindri_exportPublicKey: () => {
    message?: string;
    publicKey?: string;
    error?: string;
  };
}

/**
 * SindriTEE provides HPKE encryption capabilities for secure communication with Sindri.
 */
export class SindriTEE {
  private static instance: SindriTEE | null = null;
  private static initialized = false;
  private static goInstance: any = null;
  private static wasmFunctions: SindriWASMFunctions | null = null;
  private static config: SindriTEEConfig | null = null;

  /**
   * Initialize the TEE module with evllm-proxy configuration.
   */
  static async initialize(config: Partial<SindriTEEConfig> = {}): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Build complete configuration with defaults inline.
    const fullConfig: SindriTEEConfig = {
      // Optional fields with defaults.
      requestTimeoutSeconds: config.requestTimeoutSeconds ?? 300,
      ...(config.logLevel && { logLevel: config.logLevel }),

      // TEE-specific settings.
      enabled: config.enabled !== false,
      debug: config.debug === true,

      // Encryption configuration with defaults.
      encryption: {
        enabled: config.encryption?.enabled ?? true,
        keySource: config.encryption?.keySource ?? 'ephemeral',
        ...(config.encryption?.privateKey && { privateKey: config.encryption.privateKey }),
        ...(config.encryption?.publicKey && { publicKey: config.encryption.publicKey }),
        attestation: {
          validityPeriodMinutes: config.encryption?.attestation?.validityPeriodMinutes ?? 60,
          renewalThresholdSeconds: config.encryption?.attestation?.renewalThresholdSeconds ?? 30,
          verifyRegisters: config.encryption?.attestation?.verifyRegisters ?? false,
          ...(config.encryption?.attestation?.approvedMeasurements && {
            approvedMeasurements: config.encryption.attestation.approvedMeasurements,
          }),
        },
      },
    };

    // Store configuration.
    this.config = fullConfig;

    try {
      await this.loadWASM();
      await this.initializeWASM();
      this.initialized = true;

      if (this.config?.debug) {
        console.log('SindriTEE initialized successfully');
      }
    } catch (error) {
      console.error('Failed to initialize SindriTEE:', error);
      throw error;
    }
  }

  /**
   * Load and instantiate the WASM module.
   */
  private static async loadWASM(): Promise<void> {
    // Dynamically import the runtime.
    // @ts-ignore - wasm_exec.js is not a TypeScript module.
    await import('./wasm/wasm_exec.js');

    // Initialize Go runtime.
    if ((globalThis as any).Go) {
      this.goInstance = new (globalThis as any).Go();
    } else {
      throw new Error('Go WASM runtime not available');
    }

    // Import the WASM module with embedded bytes.
    const wasmModule = await import('./wasm/wasm');

    // Get the WASM bytes.
    const wasmBytes = wasmModule.getWasmBytes();

    // Instantiate the WASM module.
    const wasmResult = await (globalThis as any).WebAssembly.instantiate(
      wasmBytes,
      this.goInstance.importObject,
    );

    // Run the Go program.
    this.goInstance.run(wasmResult.instance);

    // Wait for the module to initialize.
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Check if Sindri functions are available.
    const global = globalThis as any;
    if (typeof global.sindri_initialize === 'function') {
      this.wasmFunctions = {
        sindri_initialize: global.sindri_initialize,
        sindri_chatCompletion: global.sindri_chatCompletion,
        sindri_getServerPublicKey: global.sindri_getServerPublicKey,
        sindri_exportPublicKey: global.sindri_exportPublicKey,
      };

      if (this.config?.debug) {
        console.log('WASM functions loaded successfully');
      }
    } else {
      throw new Error('WASM functions not found');
    }
  }

  /**
   * Initialize the WASM module with configuration.
   */
  private static async initializeWASM(): Promise<void> {
    if (!this.wasmFunctions) {
      return;
    }

    // Pass the full configuration to the WASM module.
    const configJSON = JSON.stringify(this.config);
    const result = this.wasmFunctions.sindri_initialize(configJSON);

    if (result.error) {
      throw new Error(`Failed to initialize WASM module: ${result.error}`);
    }

    if (this.config?.debug && result.message) {
      console.log('WASM initialization:', result.message);
    }
  }

  /**
   * Check if the TEE module is initialized.
   */
  static isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Check if encryption is enabled.
   */
  static isEncryptionEnabled(): boolean {
    return this.initialized && this.config?.encryption?.enabled === true;
  }

  /**
   * Get the server's public key if available.
   */
  static getServerPublicKey(): string | null {
    if (!this.wasmFunctions) {
      return null;
    }

    const result = this.wasmFunctions.sindri_getServerPublicKey();
    return result.publicKey || null;
  }

  /**
   * Export the client's public key (mainly for debugging).
   */
  static exportPublicKey(): string | null {
    if (!this.wasmFunctions) {
      return null;
    }

    const result = this.wasmFunctions.sindri_exportPublicKey();
    return result.publicKey || result.message || null;
  }


  /**
   * Update TEE configuration at runtime.
   * Note: Some changes may require re-initialization.
   */
  static updateConfig(config: Partial<SindriTEEConfig>): void {
    if (!this.config) {
      // If no existing config, just store the partial config.
      // Full defaults will be applied on initialize.
      this.config = config as SindriTEEConfig;
      return;
    }

    // Merge with existing configuration.
    const oldConfig = this.config;
    this.config = {
      // Core fields.
      ...(config.requestTimeoutSeconds !== undefined || oldConfig.requestTimeoutSeconds !== undefined
        ? { requestTimeoutSeconds: config.requestTimeoutSeconds ?? oldConfig.requestTimeoutSeconds }
        : {}),
      ...(config.logLevel !== undefined || oldConfig.logLevel !== undefined
        ? { logLevel: config.logLevel ?? oldConfig.logLevel }
        : {}),

      // TEE-specific settings.
      ...(config.enabled !== undefined || oldConfig.enabled !== undefined
        ? { enabled: config.enabled ?? oldConfig.enabled }
        : {}),
      ...(config.debug !== undefined || oldConfig.debug !== undefined
        ? { debug: config.debug ?? oldConfig.debug }
        : {}),

      // Merge encryption configuration.
    };

    // Handle encryption configuration separately to satisfy exactOptionalPropertyTypes
    if (config.encryption !== undefined || oldConfig.encryption !== undefined) {
      if (config.encryption) {
        const encryptionConfig: EncryptionConfig = {
          enabled: config.encryption.enabled ?? oldConfig.encryption?.enabled ?? true,
        };
        
        // Add optional fields only if they have values
        const keySource = config.encryption.keySource ?? oldConfig.encryption?.keySource;
        if (keySource !== undefined) {
          encryptionConfig.keySource = keySource;
        }
        
        const privateKey = config.encryption.privateKey ?? oldConfig.encryption?.privateKey;
        if (privateKey !== undefined) {
          encryptionConfig.privateKey = privateKey;
        }
        
        const publicKey = config.encryption.publicKey ?? oldConfig.encryption?.publicKey;
        if (publicKey !== undefined) {
          encryptionConfig.publicKey = publicKey;
        }
        
        // Handle attestation
        if (config.encryption.attestation || oldConfig.encryption?.attestation) {
          if (config.encryption.attestation) {
            encryptionConfig.attestation = {
              ...oldConfig.encryption?.attestation,
              ...config.encryption.attestation,
            };
          } else if (oldConfig.encryption?.attestation) {
            encryptionConfig.attestation = oldConfig.encryption.attestation;
          }
        }
        
        this.config.encryption = encryptionConfig;
      } else if (oldConfig.encryption) {
        this.config.encryption = oldConfig.encryption;
      }
    }

    // If significant changes, suggest re-initialization.
    if (this.initialized && this.wasmFunctions) {
      if (config.encryption !== undefined) {
        console.warn('Configuration changes may require re-initialization to take effect');
      }
    }
  }

  /**
   * Get current TEE configuration.
   */
  static getConfig(): Readonly<SindriTEEConfig> | null {
    return this.config ? { ...this.config } : null;
  }

  /**
   * Check if TEE is enabled.
   */
  static isEnabled(): boolean {
    return this.config?.enabled !== false;
  }

  /**
   * Intercept chat completion requests and route through TEE.
   * The WASM module handles all encryption, attestation, and communication.
   * 
   * @param body - The request body
   * @param options - Request options
   * @param apiKey - API key from the OpenAI client
   * @param baseURL - Base URL from the OpenAI client
   */
  static async interceptChatCompletion(
    body: any,
    options?: any,
    apiKey?: string,
    baseURL?: string,
  ): Promise<any> {
    // Check if TEE is enabled.
    if (!this.isEnabled()) {
      return null; // Let the normal flow continue.
    }

    // Initialize WASM if needed.
    if (!this.initialized) {
      await this.initialize({});
    }

    // Check that we have required credentials from the OpenAI client.
    if (!apiKey || !baseURL) {
      if (this.config?.debug) {
        console.warn('[TEE] Missing API key or base URL from OpenAI client');
      }
      return null;
    }

    try {
      // Call the WASM chat completion function with credentials.
      // The WASM module handles all encryption and attestation internally.
      return await this.chatCompletionWithAuth(body, apiKey, baseURL);
    } catch (error) {
      if (this.config?.debug) {
        console.error('[TEE] Chat completion failed:', error);
      }
      throw error;
    }
  }

  /**
   * Make a chat completion request with specific auth and endpoint.
   * This method will be called by interceptChatCompletion with credentials
   * passed through from the OpenAI client.
   */
  static async chatCompletionWithAuth(requestBody: any, apiKey: string, baseURL: string): Promise<any> {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    // Pass the auth and endpoint to the WASM module
    const bodyStr = JSON.stringify({
      ...requestBody,
      __tee_auth: apiKey,
      __tee_endpoint: baseURL + '/v1/chat/completions',
    });
    
    const result = await this.wasmFunctions.sindri_chatCompletion(bodyStr);

    if (result.error) {
      throw new Error(`Chat completion failed: ${result.error}`);
    }

    if (result.response) {
      try {
        return JSON.parse(result.response);
      } catch {
        return result.response;
      }
    }

    return result;
  }
}
