/**
 * Sindri TEE integration module for OpenAI SDK.
 * This module provides WebAssembly-based HPKE encryption for secure communication with Sindri's TEE.
 */

import type { OpenAI } from '../client';

// Type definitions for the WASM module functions.
interface SindriWASMFunctions {
  sindri_initializeKeys: (useEphemeral: boolean, privateKeyPEM?: string, publicKeyPEM?: string, debug?: boolean) => {
    success?: boolean;
    publicKey?: string;
    error?: string;
  };
  sindri_getPublicKey: () => {
    publicKey?: string;
    error?: string;
  };
  sindri_setServerPublicKey: (publicKeyPEM: string) => {
    success?: boolean;
    error?: string;
  };
  sindri_setCredentials: (apiKey: string, baseURL: string) => {
    success?: boolean;
    error?: string;
  };
  sindri_generateKeyPair: () => {
    publicKey?: string;
    privateKey?: string;
    error?: string;
  };
  sindri_generateKeyPairPEM: () => {
    publicKeyPEM?: string;
    privateKeyPEM?: string;
    error?: string;
  };
  sindri_encryptMessage: (message: string) => {
    encrypted?: string;
    error?: string;
  };
  sindri_decryptMessage: (encrypted: string) => {
    decrypted?: string;
    error?: string;
  };
  sindri_encryptBundle: (bundle: string) => {
    encrypted?: string;
    publicKey?: string;
    error?: string;
  };
  sindri_chatCompletion: (requestBody: string) => Promise<{
    response?: string;
    encrypted?: boolean;
    status?: number;
    error?: string;
  }>;
  sindri_fetchAttestation: () => Promise<{
    attestation: any;
    serverPublicKey?: string;
    status: number;
  }>;
}

export interface SindriConfig {
  // Enable TEE integration.
  enabled?: boolean;
  // Base URL for Sindri API.
  baseURL?: string;
  // API key for authentication.
  apiKey?: string;
  // Enable encryption for requests.
  encryptionEnabled?: boolean;
  // Use ephemeral keys (recommended).
  useEphemeralKeys?: boolean;
  // Static keys if not using ephemeral.
  privateKeyPEM?: string;
  publicKeyPEM?: string;
  // Server public key from attestation.
  serverPublicKey?: string;
  // Debug mode.
  debug?: boolean;
  // Log level.
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  // Attestation validity period in minutes.
  attestationValidityMinutes?: number;
}

/**
 * SindriTEE provides HPKE encryption capabilities for secure communication with Sindri.
 */
export class SindriTEE {
  private static instance: SindriTEE | null = null;
  private static initialized = false;
  private static goInstance: any = null;
  private static wasmFunctions: SindriWASMFunctions | null = null;
  private static config: SindriConfig = {};

  /**
   * Initialize the TEE module.
   */
  static async initialize(config: SindriConfig = {}): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Set default values.
    this.config = {
      enabled: true,
      baseURL: 'https://sindri.app/api/ai/v1/openai',
      apiKey: process.env['OPENAI_API_KEY'] || '',
      encryptionEnabled: true,
      useEphemeralKeys: true,
      attestationValidityMinutes: 60,
      logLevel: 'info',
      ...config,
    };

    try {
      await this.loadWASM();
      await this.setupEncryption();
      this.initialized = true;

      if (this.config.debug) {
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
      this.goInstance.importObject
    );

    // Run the Go program.
    this.goInstance.run(wasmResult.instance);

    // Wait for the module to initialize.
    await new Promise(resolve => setTimeout(resolve, 100));

    // Check if Sindri functions are available.
    const global = globalThis as any;
    if (typeof global.sindri_initializeKeys === 'function') {
      this.wasmFunctions = {
        sindri_initializeKeys: global.sindri_initializeKeys,
        sindri_getPublicKey: global.sindri_getPublicKey,
        sindri_setServerPublicKey: global.sindri_setServerPublicKey,
        sindri_setCredentials: global.sindri_setCredentials,
        sindri_generateKeyPair: global.sindri_generateKeyPair,
        sindri_generateKeyPairPEM: global.sindri_generateKeyPairPEM,
        sindri_encryptMessage: global.sindri_encryptMessage,
        sindri_decryptMessage: global.sindri_decryptMessage,
        sindri_encryptBundle: global.sindri_encryptBundle,
        sindri_chatCompletion: global.sindri_chatCompletion,
        sindri_fetchAttestation: global.sindri_fetchAttestation,
      };

      if (this.config.debug) {
        console.log('WASM encryption functions loaded successfully');
      }
    } else {
      throw new Error('WASM encryption functions not found');
    }
  }

  /**
   * Setup encryption keys.
   */
  private static async setupEncryption(): Promise<void> {
    if (!this.wasmFunctions || !this.config.encryptionEnabled) {
      return;
    }

    // Initialize keys.
    const useEphemeral = this.config.useEphemeralKeys !== false; // Default to ephemeral.
    const result = this.wasmFunctions.sindri_initializeKeys(
      useEphemeral,
      this.config.privateKeyPEM,
      this.config.publicKeyPEM,
      this.config.debug === true // Pass debug flag
    );

    if (result.error) {
      throw new Error(`Failed to initialize keys: ${result.error}`);
    }

    if (this.config.debug && result.publicKey) {
      console.log('Client public key:', result.publicKey);
    }

    // Set server public key if provided.
    if (this.config.serverPublicKey) {
      const serverResult = this.wasmFunctions.sindri_setServerPublicKey(this.config.serverPublicKey);
      if (serverResult.error) {
        throw new Error(`Failed to set server public key: ${serverResult.error}`);
      }
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
    return this.initialized && this.config.encryptionEnabled === true;
  }

  /**
   * Get the client public key.
   */
  static getPublicKey(): string | null {
    if (!this.wasmFunctions) {
      return null;
    }

    const result = this.wasmFunctions.sindri_getPublicKey();
    return result.publicKey || null;
  }

  /**
   * Set the server public key from attestation.
   */
  static setServerPublicKey(publicKeyPEM: string): void {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    const result = this.wasmFunctions.sindri_setServerPublicKey(publicKeyPEM);
    if (result.error) {
      throw new Error(`Failed to set server public key: ${result.error}`);
    }
  }

  /**
   * Encrypt a message for the server.
   */
  static encryptMessage(message: string): string {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    const result = this.wasmFunctions.sindri_encryptMessage(message);
    if (result.error) {
      throw new Error(`Failed to encrypt message: ${result.error}`);
    }

    return result.encrypted!;
  }

  /**
   * Decrypt a message from the server.
   */
  static decryptMessage(encrypted: string): string {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    const result = this.wasmFunctions.sindri_decryptMessage(encrypted);
    if (result.error) {
      throw new Error(`Failed to decrypt message: ${result.error}`);
    }

    return result.decrypted!;
  }

  /**
   * Encrypt a bundle with ephemeral keys.
   */
  static encryptBundle(bundle: string): { encrypted: string; publicKey: string } {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    const result = this.wasmFunctions.sindri_encryptBundle(bundle);
    if (result.error) {
      throw new Error(`Failed to encrypt bundle: ${result.error}`);
    }

    return {
      encrypted: result.encrypted!,
      publicKey: result.publicKey!,
    };
  }

  /**
   * Intercept and encrypt an OpenAI API request.
   */
  static async encryptRequest(body: any): Promise<any> {
    if (!this.isEncryptionEnabled()) {
      return body; // Pass through unencrypted.
    }

    try {
      const bodyStr = JSON.stringify(body);
      const encrypted = this.encryptMessage(bodyStr);
      
      return {
        encrypted: encrypted,
        publicKey: this.getPublicKey(),
      };
    } catch (error) {
      if (this.config.debug) {
        console.error('Failed to encrypt request:', error);
      }
      throw error;
    }
  }

  /**
   * Intercept and decrypt an OpenAI API response.
   */
  static async decryptResponse(response: any): Promise<any> {
    if (!this.isEncryptionEnabled()) {
      return response; // Pass through unencrypted.
    }

    try {
      if (response.encrypted) {
        const decrypted = this.decryptMessage(response.encrypted);
        return JSON.parse(decrypted);
      }
      return response;
    } catch (error) {
      if (this.config.debug) {
        console.error('Failed to decrypt response:', error);
      }
      throw error;
    }
  }

  /**
   * Set API credentials for direct WASM requests.
   */
  static setCredentials(apiKey: string, baseURL: string): void {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }
    
    const result = this.wasmFunctions.sindri_setCredentials(apiKey, baseURL);
    if (result.error) {
      throw new Error(`Failed to set credentials: ${result.error}`);
    }
  }

  /**
   * Make a chat completion request directly from WASM.
   */
  static async chatCompletion(requestBody: any): Promise<any> {
    if (!this.wasmFunctions) {
      throw new Error('SindriTEE not initialized');
    }

    const bodyStr = JSON.stringify(requestBody);
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

  /**
   * Update TEE configuration at runtime.
   */
  static updateConfig(config: Partial<SindriConfig>): void {
    this.config = { ...this.config, ...config };
    
    // Update WASM configuration if initialized.
    if (this.initialized && this.wasmFunctions) {
      // Update credentials if provided.
      if (config.apiKey !== undefined || config.baseURL !== undefined) {
        const apiKey = config.apiKey || this.config.apiKey || '';
        const baseURL = config.baseURL || this.config.baseURL || '';
        this.setCredentials(apiKey, baseURL);
      }
    }
  }

  /**
   * Get current TEE configuration.
   */
  static getConfig(): Readonly<SindriConfig> {
    return { ...this.config };
  }

  /**
   * Check if TEE is enabled.
   */
  static isEnabled(): boolean {
    return this.config.enabled !== false;
  }

  /**
   * Intercept chat completion requests and route through TEE.
   */
  static async interceptChatCompletion(body: any, options?: any, apiKey?: string, baseURL?: string): Promise<any> {
    // Check if TEE is enabled.
    if (!this.isEnabled()) {
      return null; // Let the normal flow continue.
    }
    
    // Initialize WASM if needed.
    if (!this.initialized) {
      await this.initialize();
    }
    
    // Use provided credentials or fall back to config.
    const finalApiKey = apiKey || this.config.apiKey || process.env['OPENAI_API_KEY'] || '';
    const finalBaseURL = baseURL || this.config.baseURL || 'https://sindri.app/api/ai/v1/openai';
    
    // Set credentials.
    if (finalApiKey && finalBaseURL) {
      this.setCredentials(finalApiKey, finalBaseURL);
    } else {
      if (this.config.debug) {
        console.warn('[TEE] Missing API key or base URL for TEE request');
      }
      return null;
    }
    
    try {
      // Call the WASM chat completion function.
      return await this.chatCompletion(body);
    } catch (error) {
      if (this.config.debug) {
        console.error('[TEE] Chat completion failed:', error);
      }
      throw error;
    }
  }
}