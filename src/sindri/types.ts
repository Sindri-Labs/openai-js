/**
 * TypeScript types for evllm-proxy configuration.
 * Matches the YAML configuration structure used by the native evllm-proxy.
 *
 * IMPORTANT: All validation is performed in Go/WASM. These types provide
 * compile-time type safety but no runtime validation in TypeScript.
 */

/**
 * Key source options for encryption keys.
 * - 'ephemeral': Keys are generated automatically and managed internally
 * - 'file': Keys are loaded from files (NOT supported in WASM)
 * - 'value': Keys are provided directly as strings
 */
export type EncryptionKeySource = 'ephemeral' | 'file' | 'value';

/**
 * Configuration for encryption keys.
 * Used when keySource is 'file' or 'value'.
 */
export interface EncryptionKeyConfig {
  /**
   * If keySource is "file", this is the path to the key file.
   * The file must be in PEM format.
   * NOTE: File sources are NOT supported in WASM environment.
   */
  filePath?: string;

  /**
   * If keySource is "value", this is the actual key value.
   * The value must be a base64-encoded string or PEM format.
   * The Go code will attempt base64 decoding first, then treat as PEM if that fails.
   */
  value?: string;
}

/**
 * Approved measurements configuration for Intel TDX attestation.
 * Used to verify the integrity of the TEE environment.
 */
export interface ApprovedMeasurementsConfig {
  /**
   * Approved RTMR1 values (Runtime Measurement Register 1).
   * These are hex-encoded hash values from the TEE.
   */
  rtmr1?: string[];

  /**
   * Approved RTMR2 values (Runtime Measurement Register 2).
   * These are hex-encoded hash values from the TEE.
   */
  rtmr2?: string[];

  /**
   * Approved RTMR3 values (Runtime Measurement Register 3).
   * These are hex-encoded hash values from the TEE.
   */
  rtmr3?: string[];
}

/**
 * Attestation configuration for TEE verification.
 * Controls how attestation reports are validated and cached.
 */
export interface AttestationConfig {
  /**
   * How long attestation reports are considered valid (in minutes).
   * Default: 60 minutes if not specified.
   * Must be positive if provided.
   */
  validityPeriodMinutes?: number;

  /**
   * When to start trying to renew the attestation (seconds before expiry).
   * Default: 30 seconds if not specified.
   * Must be positive if provided.
   */
  renewalThresholdSeconds?: number;

  /**
   * Whether to verify registers against approved values.
   * If true, approvedMeasurements should be provided.
   * Default: false.
   */
  verifyRegisters?: boolean;

  /**
   * Approved measurement values for register verification.
   * Only used when verifyRegisters is true.
   */
  approvedMeasurements?: ApprovedMeasurementsConfig;
}

/**
 * Encryption configuration for HPKE-based secure communication.
 * Controls encryption, key management, and attestation settings.
 */
export interface EncryptionConfig {
  /**
   * Enable encryption features.
   * When false, requests are sent unencrypted (not recommended).
   * Default: true.
   */
  enabled: boolean;

  /**
   * Source of encryption keys.
   * - 'ephemeral': Keys generated automatically (recommended)
   * - 'value': Keys provided as strings in config
   * - 'file': Keys loaded from files (NOT supported in WASM)
   * Default: 'ephemeral'.
   */
  keySource?: EncryptionKeySource;

  /**
   * Private key configuration.
   * Only used when keySource is 'value' or 'file'.
   * Not needed for ephemeral keys.
   */
  privateKey?: EncryptionKeyConfig;

  /**
   * Public key configuration.
   * Only used when keySource is 'value' or 'file'.
   * Not needed for ephemeral keys.
   */
  publicKey?: EncryptionKeyConfig;

  /**
   * Attestation settings for TEE verification.
   * Controls how the TEE environment is validated.
   */
  attestation?: AttestationConfig;
}

/**
 * Main SindriClient configuration.
 * This configuration is for TEE-specific settings only.
 * Authentication and endpoint are passed through from the OpenAI client.
 *
 * Validation rules (enforced in Go):
 * - requestTimeoutSeconds: Must be positive if provided
 */
export interface SindriClientConfig {
  /**
   * Request timeout in seconds.
   * Default: 300 seconds if not specified.
   * Must be positive if provided.
   */
  requestTimeoutSeconds?: number;

  /**
   * Encryption and attestation configuration.
   * Default: Encryption enabled with ephemeral keys.
   */
  encryption?: EncryptionConfig;

  /**
   * Log level for the evllm-proxy logger.
   * Controls verbosity of console output.
   * Default: 'info'.
   */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

/**
 * Extended configuration for the WASM TEE module.
 * Includes additional settings specific to the JavaScript integration.
 */
export interface SindriTEEConfig extends SindriClientConfig {
  /**
   * Enable the TEE integration.
   * When false, requests bypass TEE and use standard OpenAI flow.
   * Default: true.
   */
  enabled?: boolean;

  /**
   * Enable debug logging in JavaScript console.
   * Separate from logLevel which controls evllm-proxy logging.
   * Default: false.
   */
  debug?: boolean;
}
