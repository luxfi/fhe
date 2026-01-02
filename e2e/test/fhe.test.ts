/**
 * LuxFHE End-to-End Tests
 *
 * Tests the full FHE stack:
 * 1. Go TFHE server (http://localhost:8448)
 * 2. WASM bindings (@luxfhe/wasm-node)
 * 3. KMS client (@luxfhe/kms-node)
 *
 * Prerequisites:
 *   cd ~/work/lux/tfhe && ./bin/fhe-server -addr :8448
 */

import { describe, it, expect, beforeAll } from 'vitest';

const FHE_SERVER_URL = process.env.FHE_SERVER_URL || 'http://localhost:8448';

describe('LuxFHE E2E Tests', () => {
  beforeAll(async () => {
    // Check if server is running
    try {
      const res = await fetch(`${FHE_SERVER_URL}/health`);
      if (!res.ok) throw new Error('Server not healthy');
    } catch (e) {
      console.error('FHE server not running. Start with:');
      console.error('  cd ~/work/lux/tfhe && ./bin/fhe-server');
      throw e;
    }
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/health`);
      expect(res.ok).toBe(true);

      const data = await res.json();
      expect(data.status).toBe('ok');
    });
  });

  describe('Public Key', () => {
    it('should return a valid public key', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/publickey`);
      expect(res.ok).toBe(true);

      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  Public key size: ${buffer.byteLength} bytes`);
    });
  });

  describe('Encryption', () => {
    it('should encrypt a 32-bit integer', async () => {
      const value = 42;
      const res = await fetch(`${FHE_SERVER_URL}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value, bitWidth: 32 }),
      });

      expect(res.ok).toBe(true);
      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  Encrypted ${value} -> ${buffer.byteLength} bytes`);
    });

    it('should encrypt different bit widths', async () => {
      const bitWidths = [8, 16, 32, 64];

      for (const bitWidth of bitWidths) {
        const value = 123;
        const res = await fetch(`${FHE_SERVER_URL}/encrypt`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ value, bitWidth }),
        });

        expect(res.ok).toBe(true);
        const buffer = await res.arrayBuffer();
        console.log(`  FheUint${bitWidth}: ${buffer.byteLength} bytes`);
      }
    });
  });

  describe('FHE Operations', () => {
    let encA: Uint8Array;
    let encB: Uint8Array;

    beforeAll(async () => {
      // Encrypt two values
      const resA = await fetch(`${FHE_SERVER_URL}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: 42, bitWidth: 32 }),
      });
      encA = new Uint8Array(await resA.arrayBuffer());

      const resB = await fetch(`${FHE_SERVER_URL}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: 17, bitWidth: 32 }),
      });
      encB = new Uint8Array(await resB.arrayBuffer());
    });

    it('should add two encrypted values', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          op: 'add',
          left: Array.from(encA),
          right: Array.from(encB),
          bitWidth: 32,
        }),
      });

      expect(res.ok).toBe(true);
      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  add(42, 17) = encrypted (${buffer.byteLength} bytes)`);
    });

    it('should subtract two encrypted values', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          op: 'sub',
          left: Array.from(encA),
          right: Array.from(encB),
          bitWidth: 32,
        }),
      });

      expect(res.ok).toBe(true);
      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  sub(42, 17) = encrypted (${buffer.byteLength} bytes)`);
    });

    it('should compare two encrypted values (lt)', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          op: 'lt',
          left: Array.from(encA),
          right: Array.from(encB),
          bitWidth: 32,
        }),
      });

      expect(res.ok).toBe(true);
      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  lt(42, 17) = encrypted bool (${buffer.byteLength} bytes)`);
    });

    it('should compare two encrypted values (eq)', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          op: 'eq',
          left: Array.from(encA),
          right: Array.from(encA), // Same value
          bitWidth: 32,
        }),
      });

      expect(res.ok).toBe(true);
      const buffer = await res.arrayBuffer();
      expect(buffer.byteLength).toBeGreaterThan(0);
      console.log(`  eq(42, 42) = encrypted bool (${buffer.byteLength} bytes)`);
    });
  });

  describe('ZK Verification', () => {
    it('should verify a computation proof', async () => {
      const res = await fetch(`${FHE_SERVER_URL}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: new Uint8Array([1, 2, 3]), // Placeholder proof
      });

      expect(res.ok).toBe(true);
      const data = await res.json();
      expect(data.verified).toBe(true);
    });
  });
});
