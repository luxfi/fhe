/**
 * FHE Key pair returned by generateKeys()
 */
export interface KeyPair {
  /** Secret key (base64 encoded) - keep private! */
  secretKey: string;
  /** Public key (base64 encoded) - can be shared */
  publicKey: string;
  /** Bootstrap key (base64 encoded) - needed for operations */
  bootstrapKey: string;
}

/**
 * Supported bit widths for FHE operations
 */
export type BitWidth = 4 | 8 | 16 | 32 | 64 | 128 | 160 | 256;

/**
 * Ciphertext is a base64-encoded encrypted value
 */
export type Ciphertext = string;

/**
 * Error returned from WASM operations
 */
export class LuxFHEError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LuxFHEError';
  }
}

/**
 * Raw WASM module interface (internal use)
 */
export interface LuxFHEWasm {
  version(): string;
  generateKeys(): KeyPair;
  encrypt(value: number, bitWidth: number, publicKey: string): string;
  decrypt(ciphertext: string, secretKey: string): number | string;
  add(ct1: string, ct2: string, bootstrapKey: string, secretKey: string): string;
  sub(ct1: string, ct2: string, bootstrapKey: string, secretKey: string): string;
  eq(ct1: string, ct2: string, bootstrapKey: string, secretKey: string): string;
  lt(ct1: string, ct2: string, bootstrapKey: string, secretKey: string): string;
}

/**
 * Initialization options
 */
export interface InitOptions {
  /** Custom path to WASM file */
  wasmPath?: string;
  /** Custom path to wasm_exec.js */
  execPath?: string;
}
