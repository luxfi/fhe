/**
 * @luxfi/tfhe - TypeScript bindings for LuxFHE
 * 
 * Fully Homomorphic Encryption for Node.js and browsers.
 * 
 * @example
 * ```typescript
 * import { LuxFHE } from '@luxfi/tfhe';
 * 
 * const fhe = await LuxFHE.init();
 * const keys = fhe.generateKeys();
 * 
 * const ct1 = fhe.encrypt(42, 32, keys.publicKey);
 * const ct2 = fhe.encrypt(8, 32, keys.publicKey);
 * 
 * const ctResult = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);
 * const result = fhe.decrypt(ctResult, keys.secretKey);
 * console.log(result); // 50
 * ```
 */

// Re-export types
export * from './types';
export * from './wasm-loader';
export * from './luxfhe';

// Default export
export { LuxFHE as default } from './luxfhe';

// Named exports for convenience
export { LuxFHE } from './luxfhe';
