# LuxFHE SDK

Multi-language SDK for Fully Homomorphic Encryption.

## SDKs

| Directory | Language | Description |
|-----------|----------|-------------|
| `c/` | C/C++ | Native shared library with C API |
| `python/` | Python | CFFI bindings for Python 3.9+ |
| `rust/` | Rust | Safe Rust bindings via bindgen |
| `typescript/` | TypeScript | ESM/CJS package for Node.js and browsers |
| `wasm/` | WebAssembly | Go-based WASM module |

## Quick Start

### Go (Core Library)

```go
import "github.com/luxfi/tfhe"

params := tfhe.ParamsPN10QP27
sk, pk := tfhe.NewKeyGenerator(params).GenKeyPair()
enc := tfhe.NewBitwisePublicEncryptor(params, pk)
eval := tfhe.NewBitwiseEvaluator(params, sk.BootstrapKey(), sk)

ct1 := enc.EncryptUint(42, 8)
ct2 := enc.EncryptUint(8, 8)
ctSum := eval.Add(ct1, ct2)
result := tfhe.NewBitwiseDecryptor(params, sk).DecryptUint(ctSum)
// result = 50
```

### TypeScript

```typescript
import { LuxFHE } from '@luxfi/tfhe';

const fhe = await LuxFHE.init();
const keys = fhe.generateKeys();
const ct1 = fhe.encrypt(42, 32, keys.publicKey);
const ct2 = fhe.encrypt(8, 32, keys.publicKey);
const ctSum = fhe.add(ct1, ct2, keys.bootstrapKey, keys.secretKey);
const result = fhe.decrypt(ctSum, keys.secretKey);
// result = 50
```

### Python

```python
from luxfhe import Context, ParamSet

ctx = Context(ParamSet.PN10QP27)
sk = ctx.generate_secret_key()
pk = ctx.generate_public_key(sk)
bsk = ctx.generate_bootstrap_key(sk)
enc = ctx.encryptor(pk)
eval = ctx.evaluator(bsk, sk)
dec = ctx.decryptor(sk)

ct1 = enc.encrypt_uint(42, 8)
ct2 = enc.encrypt_uint(8, 8)
ct_sum = eval.add(ct1, ct2)
result = dec.decrypt_uint(ct_sum)
# result = 50
```

### Rust

```rust
use luxfhe::{Context, ParamSet};

let ctx = Context::new(ParamSet::PN10QP27)?;
let sk = ctx.generate_secret_key()?;
let pk = ctx.generate_public_key(&sk)?;
let bsk = ctx.generate_bootstrap_key(&sk)?;
let enc = ctx.encryptor(&pk)?;
let eval = ctx.evaluator(&bsk, &sk)?;
let dec = ctx.decryptor(&sk)?;

let ct1 = enc.encrypt_uint(42, 8)?;
let ct2 = enc.encrypt_uint(8, 8)?;
let ct_sum = eval.add(&ct1, &ct2)?;
let result = dec.decrypt_uint(&ct_sum)?;
// result = 50
```

### C

```c
#include "luxfhe.h"

LuxFHE_Context ctx;
luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);

LuxFHE_SecretKey sk;
luxfhe_secret_key_new(ctx, &sk);

LuxFHE_PublicKey pk;
luxfhe_public_key_new(ctx, sk, &pk);

LuxFHE_BootstrapKey bsk;
luxfhe_bootstrap_key_new(ctx, sk, &bsk);

// ... encrypt, evaluate, decrypt
```

## Building

### C Library

```bash
cd sdk/c
CGO_ENABLED=1 go build -buildmode=c-shared -o lib/libluxfhe.so ../c/src/luxfhe.go
```

### TypeScript

```bash
cd sdk/typescript
npm install
npm run build
```

### Python

```bash
cd sdk/python
pip install -e .
```

### Rust

```bash
cd sdk/rust
cargo build --release
```

### WASM

```bash
cd sdk/wasm
GOOS=js GOARCH=wasm go build -o luxfhe.wasm ./main.go
```

## Documentation

See https://tfhe.lux.network/docs/sdk for full documentation.
