/**
 * Tests for @luxfi/tfhe TypeScript bindings
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { LuxFHE, createLuxFHE } from './luxfhe';
import type { KeyPair } from './types';

describe('LuxFHE', () => {
  let fhe: LuxFHE;
  let keys: KeyPair;

  beforeAll(async () => {
    fhe = await LuxFHE.init({
      wasmPath: './wasm/luxfhe.wasm',
      execPath: './wasm/wasm_exec.js',
    });
    keys = fhe.generateKeys();
  });

  describe('initialization', () => {
    it('should initialize successfully', () => {
      expect(fhe).toBeDefined();
    });

    it('should return version', () => {
      const version = fhe.version();
      expect(version).toBe('1.0.0');
    });
  });

  describe('key generation', () => {
    it('should generate key pair', () => {
      expect(keys.secretKey).toBeTruthy();
      expect(keys.publicKey).toBeTruthy();
      expect(keys.bootstrapKey).toBeTruthy();
    });

    it('should generate base64 encoded keys', () => {
      // Base64 strings contain only valid characters
      const base64Regex = /^[A-Za-z0-9+/]+=*$/;
      expect(keys.secretKey).toMatch(base64Regex);
      expect(keys.publicKey).toMatch(base64Regex);
      expect(keys.bootstrapKey).toMatch(base64Regex);
    });
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt 32-bit value', () => {
      const value = 42;
      const ciphertext = fhe.encrypt(value, 32, keys.publicKey);
      const decrypted = fhe.decrypt(ciphertext, keys.secretKey);
      expect(decrypted).toBe(value);
    });

    it('should encrypt and decrypt zero', () => {
      const value = 0;
      const ciphertext = fhe.encrypt(value, 32, keys.publicKey);
      const decrypted = fhe.decrypt(ciphertext, keys.secretKey);
      expect(decrypted).toBe(value);
    });

    it('should encrypt and decrypt 8-bit value', () => {
      const value = 255;
      const ciphertext = fhe.encrypt(value, 8, keys.publicKey);
      const decrypted = fhe.decrypt(ciphertext, keys.secretKey);
      expect(decrypted).toBe(value);
    });

    it('should encrypt and decrypt 64-bit value', () => {
      const value = 1000000;
      const ciphertext = fhe.encrypt(value, 64, keys.publicKey);
      const decrypted = fhe.decrypt(ciphertext, keys.secretKey);
      expect(decrypted).toBe(value);
    });
  });

  describe('homomorphic operations', () => {
    it('should add encrypted values', () => {
      const a = 100;
      const b = 50;
      
      const ct1 = fhe.encrypt(a, 32, keys.publicKey);
      const ct2 = fhe.encrypt(b, 32, keys.publicKey);
      
      const ctResult = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);
      const result = fhe.decrypt(ctResult, keys.secretKey);
      
      expect(result).toBe(a + b);
    });

    it('should subtract encrypted values', () => {
      const a = 100;
      const b = 30;
      
      const ct1 = fhe.encrypt(a, 32, keys.publicKey);
      const ct2 = fhe.encrypt(b, 32, keys.publicKey);
      
      const ctResult = fhe.sub(ct1, ct2, keys.bootstrapKey, keys.secretKey);
      const result = fhe.decrypt(ctResult, keys.secretKey);
      
      expect(result).toBe(a - b);
    });

    it('should compare encrypted values for equality', () => {
      const a = 42;
      const b = 42;
      
      const ct1 = fhe.encrypt(a, 32, keys.publicKey);
      const ct2 = fhe.encrypt(b, 32, keys.publicKey);
      
      const ctResult = fhe.eq(ct1, ct2, keys.bootstrapKey, keys.secretKey);
      const result = fhe.decrypt(ctResult, keys.secretKey);
      
      expect(result).toBe(1); // true
    });

    it('should compare encrypted values less than', () => {
      const a = 10;
      const b = 20;
      
      const ct1 = fhe.encrypt(a, 32, keys.publicKey);
      const ct2 = fhe.encrypt(b, 32, keys.publicKey);
      
      const ctResult = fhe.lt(ct1, ct2, keys.bootstrapKey, keys.secretKey);
      const result = fhe.decrypt(ctResult, keys.secretKey);
      
      expect(result).toBe(1); // true: 10 < 20
    });
  });
});

describe('createLuxFHE', () => {
  it('should be a convenience function', async () => {
    const fhe = await createLuxFHE({
      wasmPath: './wasm/luxfhe.wasm',
      execPath: './wasm/wasm_exec.js',
    });
    expect(fhe).toBeInstanceOf(LuxFHE);
  });
});
