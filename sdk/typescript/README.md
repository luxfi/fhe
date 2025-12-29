# @luxfi/tfhe

TypeScript bindings for LuxFHE - Fully Homomorphic Encryption for Node.js and browsers.

## Installation

```bash
npm install @luxfi/tfhe
# or
pnpm add @luxfi/tfhe
# or
yarn add @luxfi/tfhe
```

## Usage

### Basic Example

```typescript
import { LuxFHE } from '@luxfi/tfhe';

async function main() {
  // Initialize the FHE library
  const fhe = await LuxFHE.init();
  
  // Generate keys
  const keys = fhe.generateKeys();
  console.log('Keys generated!');
  
  // Encrypt values
  const ct1 = fhe.encrypt(100, 32, keys.publicKey);
  const ct2 = fhe.encrypt(50, 32, keys.publicKey);
  
  // Compute on encrypted data (no one can see the values!)
  const ctSum = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);
  
  // Decrypt the result
  const result = fhe.decrypt(ctSum, keys.secretKey);
  console.log('100 + 50 =', result); // 150
}

main();
```

### Browser Usage

```html
<script type="module">
import { LuxFHE } from './node_modules/@luxfi/tfhe/dist/index.mjs';

const fhe = await LuxFHE.init({
  wasmPath: './node_modules/@luxfi/tfhe/wasm/luxfhe.wasm',
  execPath: './node_modules/@luxfi/tfhe/wasm/wasm_exec.js',
});

const keys = fhe.generateKeys();
// ... use FHE operations
</script>
```

## API Reference

### `LuxFHE.init(options?)`

Initialize the FHE library. Must be called before any operations.

```typescript
const fhe = await LuxFHE.init({
  wasmPath: '/path/to/luxfhe.wasm',  // optional
  execPath: '/path/to/wasm_exec.js', // optional
});
```

### `fhe.generateKeys()`

Generate a new key pair.

```typescript
const keys = fhe.generateKeys();
// keys.secretKey    - Keep private! Used for decryption
// keys.publicKey    - Can be shared. Used for encryption
// keys.bootstrapKey - Needed for homomorphic operations
```

### `fhe.encrypt(value, bitWidth, publicKey)`

Encrypt a value with the public key.

```typescript
const ciphertext = fhe.encrypt(42, 32, keys.publicKey);
```

**Bit widths:** 4, 8, 16, 32, 64, 128, 160, 256

### `fhe.decrypt(ciphertext, secretKey)`

Decrypt a ciphertext with the secret key.

```typescript
const value = fhe.decrypt(ciphertext, keys.secretKey);
```

### Homomorphic Operations

All operations work on encrypted data:

```typescript
// Addition
const ctSum = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);

// Subtraction
const ctDiff = fhe.sub(ct1, ct2, keys.bootstrapKey, keys.secretKey);

// Equality comparison (returns encrypted 1 or 0)
const ctEq = fhe.eq(ct1, ct2, keys.bootstrapKey, keys.secretKey);

// Less than comparison
const ctLt = fhe.lt(ct1, ct2, keys.bootstrapKey, keys.secretKey);

// Greater than comparison
const ctGt = fhe.gt(ct1, ct2, keys.bootstrapKey, keys.secretKey);
```

## What is FHE?

Fully Homomorphic Encryption (FHE) allows computation on encrypted data without ever decrypting it. This enables:

- **Privacy-preserving computation**: Process sensitive data without seeing it
- **Secure cloud computing**: Send encrypted data to the cloud, get encrypted results
- **Confidential smart contracts**: Execute logic on encrypted blockchain state

## Security Notes

- **Never share your secret key!** Only the public key should be shared.
- Keys are base64-encoded for easy serialization and storage.
- The bootstrap key can be large (several MB) - consider storage implications.

## Performance

FHE operations are computationally intensive. For best performance:

- Use the smallest bit width that fits your data
- Batch operations where possible
- Consider using WebWorkers in browsers

## License

BSD-3-Clause - Copyright (c) 2025, Lux Industries Inc
