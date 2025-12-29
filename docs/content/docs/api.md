---
title: API Reference
description: Complete API documentation for Lux TFHE
---

# API Reference

## Integer Types

| Type | Bits | Use Case |
|------|------|----------|
| `FheBool` | 1 | Boolean flags, comparison results |
| `FheUint4` | 4 | Nibbles, small counters |
| `FheUint8` | 8 | Bytes, small integers |
| `FheUint16` | 16 | Short integers |
| `FheUint32` | 32 | Standard integers |
| `FheUint64` | 64 | Large integers |
| `FheUint128` | 128 | UUIDs, very large values |
| `FheUint160` | 160 | Ethereum addresses |
| `FheUint256` | 256 | EVM word size |

## Key Types

### SecretKey

The private key used for decryption. **Never share this key.**

### PublicKey

The public key used for encryption. Can be freely shared with users.

### BootstrapKey

The key used for homomorphic operations. Share with computation servers.

## Encryptors

### BitwiseEncryptor (Secret Key)

```go
enc := tfhe.NewBitwiseEncryptor(params, sk)
ct := enc.EncryptUint64(value, tfhe.FheUint8)
```

### BitwisePublicEncryptor (Public Key)

```go
pubEnc := tfhe.NewBitwisePublicEncryptor(params, pk)
ct := pubEnc.EncryptUint64(value, tfhe.FheUint8)
```

## Decryptor

```go
dec := tfhe.NewBitwiseDecryptor(params, sk)
value := dec.DecryptUint64(ct)
```

## Evaluator

### Arithmetic Operations

```go
eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)

// Addition
sum, err := eval.Add(a, b)

// Subtraction
diff, err := eval.Sub(a, b)

// Scalar addition (add plaintext constant)
result, err := eval.ScalarAdd(a, 5)

// Negation
neg, err := eval.Neg(a)
```

### Comparison Operations

```go
// All comparisons return a single encrypted bit (FheBool)
eq, err := eval.Eq(a, b)   // Equal
lt, err := eval.Lt(a, b)   // Less than
le, err := eval.Le(a, b)   // Less than or equal
gt, err := eval.Gt(a, b)   // Greater than
ge, err := eval.Ge(a, b)   // Greater than or equal

// Min/Max return the minimum/maximum of two values
min, err := eval.Min(a, b)
max, err := eval.Max(a, b)
```

### Bitwise Operations

```go
and, err := eval.And(a, b)   // Bitwise AND
or, err := eval.Or(a, b)     // Bitwise OR
xor, err := eval.Xor(a, b)   // Bitwise XOR
not, err := eval.Not(a)      // Bitwise NOT
```

### Shift Operations

```go
left, err := eval.Shl(a, 2)   // Shift left by 2
right, err := eval.Shr(a, 2)  // Shift right by 2
```

### Selection

```go
// Select based on encrypted condition (MUX)
// Returns a if cond is true, b otherwise
result, err := eval.Select(cond, a, b)
```

### Type Conversion

```go
// Convert from one type to another
result, err := eval.CastTo(value, tfhe.FheUint16)
```

## Boolean Gates

For low-level operations on individual encrypted bits:

```go
boolEval := tfhe.NewEvaluator(params, bsk)

and := boolEval.And(a, b)
or := boolEval.Or(a, b)
xor := boolEval.Xor(a, b)
not := boolEval.Not(a)
nand := boolEval.Nand(a, b)
nor := boolEval.Nor(a, b)
xnor := boolEval.Xnor(a, b)
mux := boolEval.Mux(cond, a, b)
```

## Serialization

```go
// Serialize ciphertext
bytes, err := ct.MarshalBinary()

// Deserialize ciphertext
ct := new(tfhe.BitCiphertext)
err := ct.UnmarshalBinary(bytes)

// Keys can also be serialized
skBytes, _ := sk.MarshalBinary()
pkBytes, _ := pk.MarshalBinary()
bskBytes, _ := bsk.MarshalBinary()
```

## Random Number Generation

```go
// Secret key RNG (for trusted environments)
rng := tfhe.NewFheRNG(params, sk, seed)
randomCt := rng.RandomUint(tfhe.FheUint8)

// Public key RNG (for untrusted environments)
pubRng := tfhe.NewFheRNGPublic(params, pk, seed)
randomCt := pubRng.RandomUint(tfhe.FheUint8)
```
