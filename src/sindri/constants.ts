/**
 * Constants for Sindri TEE integration.
 * Centralized configuration values to avoid duplication and magic strings.
 */

// Endpoint configuration.
export const SINDRI_BASE_URL = 'https://sindri.app/api/ai/v1/openai';
export const SINDRI_API_PREFIX = 'sindri_';

// TEE detection patterns.
export const SINDRI_DOMAINS = ['sindri.app', 'sindri.ai'] as const;

// Cache configuration.
export const MAX_CACHE_SIZE = 100;
export const CACHE_TTL_MINUTES = 60;

// Request configuration.
export const DEFAULT_REQUEST_TIMEOUT_SECONDS = 300;

// Attestation defaults.
export const DEFAULT_ATTESTATION_VALIDITY_MINUTES = 60;
export const DEFAULT_ATTESTATION_RENEWAL_SECONDS = 30;

// WASM loading configuration.
export const WASM_LOAD_MAX_ATTEMPTS = 50;
export const WASM_LOAD_INITIAL_DELAY_MS = 10;
export const WASM_LOAD_MAX_DELAY_MS = 100;
export const WASM_LOAD_BACKOFF_FACTOR = 1.5;

// Supported models.
export const SINDRI_SUPPORTED_MODELS = ['gemma3'] as const;

/**
 * Check if a URL is a Sindri endpoint that requires TEE encryption.
 */
export function isSindriEndpoint(url: string): boolean {
  const lowerUrl = url.toLowerCase();
  return SINDRI_DOMAINS.some(domain => lowerUrl.includes(domain));
}

/**
 * Check if an API key is a Sindri API key.
 */
export function isSindriApiKey(apiKey: string | undefined): boolean {
  return apiKey?.startsWith(SINDRI_API_PREFIX) ?? false;
}
