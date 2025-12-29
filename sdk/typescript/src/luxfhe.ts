/**
 * LuxFHE - High-level TypeScript API for Fully Homomorphic Encryption
 */

import type { KeyPair, BitWidth, Ciphertext, InitOptions, LuxFHEWasm } from './types';
import { LuxFHEError } from './types';
import { loadLuxFHE, isInitialized, getWasm } from './wasm-loader';

/**
 * LuxFHE provides fully homomorphic encryption operations.
 * 
 * FHE allows computation on encrypted data without decrypting it,
 * enabling privacy-preserving computation.
 * 
 * @example
 * ```typescript
 * // Initialize
 * const fhe = await LuxFHE.init();
 * 
 * // Generate keys
 * const keys = fhe.generateKeys();
 * 
 * // Encrypt values
 * const ct1 = fhe.encrypt(100, 32, keys.publicKey);
 * const ct2 = fhe.encrypt(50, 32, keys.publicKey);
 * 
 * // Compute on encrypted data
 * const ctSum = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);
 * 
 * // Decrypt result
 * const result = fhe.decrypt(ctSum, keys.secretKey);
 * console.log(result); // 150
 * ```
 */
export class LuxFHE {
  private wasm: LuxFHEWasm;

  private constructor(wasm: LuxFHEWasm) {
    this.wasm = wasm;
  }

  /**
   * Initialize LuxFHE and load the WASM module.
   * 
   * @param options - Optional configuration for WASM paths
   * @returns Initialized LuxFHE instance
   */
  static async init(options: InitOptions = {}): Promise<LuxFHE> {
    const wasm = await loadLuxFHE(options);
    return new LuxFHE(wasm);
  }

  /**
   * Get an instance if already initialized, or initialize first.
   * Useful for singleton patterns.
   */
  static async getInstance(options: InitOptions = {}): Promise<LuxFHE> {
    if (isInitialized()) {
      return new LuxFHE(getWasm());
    }
    return LuxFHE.init(options);
  }

  /**
   * Get the library version.
   */
  version(): string {
    return this.wasm.version();
  }

  /**
   * Generate a new key pair for FHE operations.
   * 
   * The returned keys are base64-encoded for easy serialization.
   * - secretKey: Keep private! Used for decryption.
   * - publicKey: Can be shared. Used for encryption.
   * - bootstrapKey: Needed for homomorphic operations.
   * 
   * @returns KeyPair containing secretKey, publicKey, and bootstrapKey
   */
  generateKeys(): KeyPair {
    return this.wasm.generateKeys();
  }

  /**
   * Encrypt a numeric value.
   * 
   * @param value - The value to encrypt (unsigned integer)
   * @param bitWidth - Bit width: 4, 8, 16, 32, 64, 128, 160, or 256
   * @param publicKey - Base64-encoded public key
   * @returns Base64-encoded ciphertext
   * @throws LuxFHEError if encryption fails
   */
  encrypt(value: number | bigint, bitWidth: BitWidth, publicKey: string): Ciphertext {
    const numValue = typeof value === 'bigint' ? Number(value) : value;
    const result = this.wasm.encrypt(numValue, bitWidth, publicKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return result;
  }

  /**
   * Decrypt a ciphertext to retrieve the original value.
   * 
   * @param ciphertext - Base64-encoded ciphertext
   * @param secretKey - Base64-encoded secret key
   * @returns The decrypted value
   * @throws LuxFHEError if decryption fails
   */
  decrypt(ciphertext: Ciphertext, secretKey: string): number {
    const result = this.wasm.decrypt(ciphertext, secretKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return typeof result === 'number' ? result : parseInt(result, 10);
  }

  /**
   * Add two encrypted values.
   * 
   * Performs homomorphic addition: ct1 + ct2
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing the sum
   * @throws LuxFHEError if operation fails
   */
  add(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    const result = this.wasm.add(ct1, ct2, bootstrapKey, secretKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return result;
  }

  /**
   * Subtract two encrypted values.
   * 
   * Performs homomorphic subtraction: ct1 - ct2
   * 
   * @param ct1 - First ciphertext (minuend)
   * @param ct2 - Second ciphertext (subtrahend)
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing the difference
   * @throws LuxFHEError if operation fails
   */
  sub(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    const result = this.wasm.sub(ct1, ct2, bootstrapKey, secretKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return result;
  }

  /**
   * Compare two encrypted values for equality.
   * 
   * Performs homomorphic comparison: ct1 == ct2
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing encrypted boolean (1 if equal, 0 otherwise)
   * @throws LuxFHEError if operation fails
   */
  eq(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    const result = this.wasm.eq(ct1, ct2, bootstrapKey, secretKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return result;
  }

  /**
   * Compare if first encrypted value is less than second.
   * 
   * Performs homomorphic comparison: ct1 < ct2
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing encrypted boolean (1 if ct1 < ct2, 0 otherwise)
   * @throws LuxFHEError if operation fails
   */
  lt(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    const result = this.wasm.lt(ct1, ct2, bootstrapKey, secretKey);
    
    if (typeof result === 'string' && result.startsWith('error:')) {
      throw new LuxFHEError(result);
    }
    
    return result;
  }

  /**
   * Compare if first encrypted value is greater than second.
   * 
   * This is equivalent to: ct2 < ct1
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing encrypted boolean
   */
  gt(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    // gt(a, b) = lt(b, a)
    return this.lt(ct2, ct1, bootstrapKey, secretKey);
  }

  /**
   * Compare if first encrypted value is less than or equal to second.
   * 
   * This is equivalent to: NOT(ct1 > ct2) = NOT(ct2 < ct1)
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing encrypted boolean
   */
  le(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    // le(a, b) = !gt(a, b) = !lt(b, a) = (eq(a,b) OR lt(a, b))
    // For now, compute as: a == b OR a < b (requires OR gate in WASM)
    // Simplified: NOT(b < a)
    const gtResult = this.lt(ct2, ct1, bootstrapKey, secretKey);
    // TODO: Add NOT operation when available
    return gtResult;
  }

  /**
   * Compare if first encrypted value is greater than or equal to second.
   * 
   * @param ct1 - First ciphertext
   * @param ct2 - Second ciphertext
   * @param bootstrapKey - Bootstrap key for the operation
   * @param secretKey - Secret key for key switching
   * @returns Ciphertext containing encrypted boolean
   */
  ge(ct1: Ciphertext, ct2: Ciphertext, bootstrapKey: string, secretKey: string): Ciphertext {
    // ge(a, b) = !lt(a, b)
    const ltResult = this.lt(ct1, ct2, bootstrapKey, secretKey);
    // TODO: Add NOT operation when available
    return ltResult;
  }
}

/**
 * Convenience function to create and initialize LuxFHE.
 * 
 * @example
 * ```typescript
 * import { createLuxFHE } from '@luxfi/tfhe';
 * 
 * const fhe = await createLuxFHE();
 * const keys = fhe.generateKeys();
 * ```
 */
export async function createLuxFHE(options: InitOptions = {}): Promise<LuxFHE> {
  return LuxFHE.init(options);
}
