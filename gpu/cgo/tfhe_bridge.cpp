// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// C++ bridge implementation for OpenFHE BinFHE (TFHE) operations
// This bridges Go's CGO calls to OpenFHE's C++ API

#include "tfhe_bridge.h"

#include <binfhecontext.h>
#include <utils/serial.h>
#include <vector>
#include <sstream>
#include <cstring>
#include <memory>

using namespace lbcrypto;

// Version
#define TFHE_BRIDGE_VERSION 0x00010000 // 1.0.0

// =============================================================================
// Internal Context Wrapper
// =============================================================================

struct TfheContextInternal {
    BinFHEContext context;
    BINFHE_PARAMSET paramset;
    BINFHE_METHOD method;
    LWEPrivateKey secretKey;
    bool hasSecretKey;
    bool hasBootstrapKey;

    TfheContextInternal() : hasSecretKey(false), hasBootstrapKey(false) {}
};

// Internal integer wrapper (bit-vector representation)
struct TfheIntegerInternal {
    std::vector<LWECiphertext> bits;
    TfheIntType itype;

    TfheIntegerInternal(TfheIntType t) : itype(t) {
        bits.resize(static_cast<int>(t));
    }

    TfheIntegerInternal(int bitLen) {
        if (bitLen <= 4) itype = TFHE_UINT4;
        else if (bitLen <= 8) itype = TFHE_UINT8;
        else if (bitLen <= 16) itype = TFHE_UINT16;
        else if (bitLen <= 32) itype = TFHE_UINT32;
        else if (bitLen <= 64) itype = TFHE_UINT64;
        else if (bitLen <= 128) itype = TFHE_UINT128;
        else if (bitLen <= 160) itype = TFHE_UINT160;
        else itype = TFHE_UINT256;
        bits.resize(static_cast<int>(itype));
    }

    int numBits() const { return static_cast<int>(itype); }
};

// =============================================================================
// Helper Functions
// =============================================================================

static BINFHE_PARAMSET mapSecurityLevel(TfheSecurityLevel level) {
    switch (level) {
        case TFHE_TOY:           return TOY;
        case TFHE_STD128:        return STD128;
        case TFHE_STD128_AP:     return STD128_AP;
        case TFHE_STD128_LMKCDEY: return STD128_LMKCDEY;
        case TFHE_STD192:        return STD192;
        case TFHE_STD256:        return STD256;
        default:                 return STD128;
    }
}

static BINFHE_METHOD mapMethod(TfheMethod method) {
    switch (method) {
        case TFHE_METHOD_GINX:    return GINX;
        case TFHE_METHOD_AP:      return AP;
        case TFHE_METHOD_LMKCDEY: return LMKCDEY;
        default:                  return GINX;
    }
}

// =============================================================================
// Context Management
// =============================================================================

extern "C" TfheContext tfhe_context_new(TfheSecurityLevel level, TfheMethod method) {
    try {
        auto* ctx = new TfheContextInternal();
        ctx->paramset = mapSecurityLevel(level);
        ctx->method = mapMethod(method);
        ctx->context = BinFHEContext();
        ctx->context.GenerateBinFHEContext(ctx->paramset, ctx->method);
        return static_cast<TfheContext>(ctx);
    } catch (...) {
        return nullptr;
    }
}

extern "C" void tfhe_context_free(TfheContext ctx) {
    if (ctx) {
        delete static_cast<TfheContextInternal*>(ctx);
    }
}

extern "C" uint32_t tfhe_version(void) {
    return TFHE_BRIDGE_VERSION;
}

// =============================================================================
// Key Generation
// =============================================================================

extern "C" TfheSecretKey tfhe_keygen(TfheContext ctx) {
    if (!ctx) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto sk = internal->context.KeyGen();
        internal->secretKey = sk;
        internal->hasSecretKey = true;
        auto* skCopy = new LWEPrivateKey(sk);
        return static_cast<TfheSecretKey>(skCopy);
    } catch (...) {
        return nullptr;
    }
}

extern "C" void tfhe_secretkey_free(TfheSecretKey sk) {
    if (sk) {
        delete static_cast<LWEPrivateKey*>(sk);
    }
}

extern "C" void tfhe_secret_key_free(TfheSecretKey sk) {
    tfhe_secretkey_free(sk);
}

extern "C" int tfhe_bootstrap_keygen(TfheContext ctx, TfheSecretKey sk) {
    if (!ctx || !sk) return -1;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        internal->context.BTKeyGen(*skPtr);
        internal->hasBootstrapKey = true;
        return 0;
    } catch (...) {
        return -1;
    }
}

extern "C" int tfhe_keyswitch_keygen(TfheContext ctx, TfheSecretKey sk) {
    if (!ctx || !sk) return -1;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        internal->context.BTKeyGen(*skPtr); // BTKeyGen includes key switching
        return 0;
    } catch (...) {
        return -1;
    }
}

extern "C" bool tfhe_has_bootstrap_key(TfheContext ctx) {
    if (!ctx) return false;
    auto* internal = static_cast<TfheContextInternal*>(ctx);
    return internal->hasBootstrapKey;
}

// =============================================================================
// Public Key Generation
// =============================================================================

extern "C" TfhePublicKey tfhe_public_keygen(TfheContext ctx, TfheSecretKey sk) {
    // OpenFHE BinFHE doesn't have separate public key - return nullptr
    // Public key encryption uses a different mechanism
    (void)ctx;
    (void)sk;
    return nullptr;
}

extern "C" void tfhe_public_key_free(TfhePublicKey pk) {
    (void)pk;
    // No-op for now
}

extern "C" int tfhe_publickey_serialize(TfhePublicKey pk, uint8_t** out, size_t* out_len) {
    (void)pk;
    (void)out;
    (void)out_len;
    return -1; // Not implemented
}

extern "C" TfhePublicKey tfhe_publickey_deserialize(TfheContext ctx, const uint8_t* data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
    return nullptr; // Not implemented
}

// =============================================================================
// Boolean Encryption / Decryption
// =============================================================================

extern "C" TfheCiphertext tfhe_encrypt(TfheContext ctx, TfheSecretKey sk, int value) {
    if (!ctx || !sk) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        auto ct = internal->context.Encrypt(*skPtr, value != 0 ? 1 : 0);
        auto* ctCopy = new LWECiphertext(ct);
        return static_cast<TfheCiphertext>(ctCopy);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_encrypt_bit(TfheContext ctx, TfheSecretKey sk, int value) {
    return tfhe_encrypt(ctx, sk, value);
}

extern "C" TfheCiphertext tfhe_encrypt_bit_public(TfheContext ctx, TfhePublicKey pk, int value) {
    // BinFHE doesn't have public key encryption in the traditional sense
    (void)ctx;
    (void)pk;
    (void)value;
    return nullptr;
}

extern "C" int tfhe_decrypt(TfheContext ctx, TfheSecretKey sk, TfheCiphertext ct) {
    if (!ctx || !sk || !ct) return -1;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        auto* ctPtr = static_cast<LWECiphertext*>(ct);
        LWEPlaintext result;
        internal->context.Decrypt(*skPtr, *ctPtr, &result);
        return result;
    } catch (...) {
        return -1;
    }
}

extern "C" int tfhe_decrypt_bit(TfheContext ctx, TfheSecretKey sk, TfheCiphertext ct) {
    return tfhe_decrypt(ctx, sk, ct);
}

extern "C" void tfhe_ciphertext_free(TfheCiphertext ct) {
    if (ct) {
        delete static_cast<LWECiphertext*>(ct);
    }
}

extern "C" TfheCiphertext tfhe_ciphertext_clone(TfheCiphertext ct) {
    if (!ct) return nullptr;
    try {
        auto* ctPtr = static_cast<LWECiphertext*>(ct);
        return static_cast<TfheCiphertext>(new LWECiphertext(*ctPtr));
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Boolean Gates
// =============================================================================

extern "C" TfheCiphertext tfhe_and(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(AND, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_or(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(OR, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_xor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(XOR, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_nand(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(NAND, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_nor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(NOR, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_xnor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);
        auto result = internal->context.EvalBinGate(XNOR, *ct1Ptr, *ct2Ptr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_not(TfheContext ctx, TfheCiphertext ct) {
    if (!ctx || !ct) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* ctPtr = static_cast<LWECiphertext*>(ct);
        auto result = internal->context.EvalNOT(*ctPtr);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_mux(TfheContext ctx, TfheCiphertext sel, TfheCiphertext ct1, TfheCiphertext ct2) {
    if (!ctx || !sel || !ct1 || !ct2) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* selPtr = static_cast<LWECiphertext*>(sel);
        auto* ct1Ptr = static_cast<LWECiphertext*>(ct1);
        auto* ct2Ptr = static_cast<LWECiphertext*>(ct2);

        // MUX(sel, ct1, ct2) = (sel AND ct1) OR ((NOT sel) AND ct2)
        auto notSel = internal->context.EvalNOT(*selPtr);
        auto branch1 = internal->context.EvalBinGate(AND, *selPtr, *ct1Ptr);
        auto branch2 = internal->context.EvalBinGate(AND, notSel, *ct2Ptr);
        auto result = internal->context.EvalBinGate(OR, branch1, branch2);
        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Integer Operations
// =============================================================================

extern "C" TfheInteger tfhe_encrypt_integer(TfheContext ctx, TfheSecretKey sk, int64_t value, int bitLen) {
    if (!ctx || !sk) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);

        auto* integer = new TfheIntegerInternal(bitLen);
        int numBits = integer->numBits();

        // Encrypt each bit
        uint64_t uval = static_cast<uint64_t>(value);
        for (int i = 0; i < numBits; i++) {
            int bit = (uval >> i) & 1;
            integer->bits[i] = internal->context.Encrypt(*skPtr, bit);
        }

        return static_cast<TfheInteger>(integer);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_encrypt_integer_public(TfheContext ctx, TfhePublicKey pk, int64_t value, int bitLen) {
    // BinFHE doesn't have public key encryption
    (void)ctx;
    (void)pk;
    (void)value;
    (void)bitLen;
    return nullptr;
}

extern "C" int64_t tfhe_decrypt_integer(TfheContext ctx, TfheSecretKey sk, TfheInteger ct) {
    if (!ctx || !sk || !ct) return 0;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        auto* integer = static_cast<TfheIntegerInternal*>(ct);

        uint64_t result = 0;
        for (size_t i = 0; i < integer->bits.size() && i < 64; i++) {
            LWEPlaintext bit;
            internal->context.Decrypt(*skPtr, integer->bits[i], &bit);
            if (bit != 0) {
                result |= (1ULL << i);
            }
        }

        return static_cast<int64_t>(result);
    } catch (...) {
        return 0;
    }
}

extern "C" void tfhe_integer_free(TfheInteger ct) {
    if (ct) {
        delete static_cast<TfheIntegerInternal*>(ct);
    }
}

extern "C" TfheInteger tfhe_integer_clone(TfheInteger ct) {
    if (!ct) return nullptr;
    try {
        auto* src = static_cast<TfheIntegerInternal*>(ct);
        auto* dst = new TfheIntegerInternal(src->itype);
        dst->bits = src->bits;
        return static_cast<TfheInteger>(dst);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheIntType tfhe_integer_type(TfheInteger ct) {
    if (!ct) return TFHE_UINT8;
    auto* integer = static_cast<TfheIntegerInternal*>(ct);
    return integer->itype;
}

// =============================================================================
// Integer Arithmetic (Full Adder / Subtractor circuits)
// =============================================================================

// Full adder: sum, carry = a + b + cin
static std::pair<LWECiphertext, LWECiphertext> fullAdder(
    TfheContextInternal* ctx,
    const LWECiphertext& a,
    const LWECiphertext& b,
    const LWECiphertext& cin
) {
    // sum = a XOR b XOR cin
    auto axorb = ctx->context.EvalBinGate(XOR, a, b);
    auto sum = ctx->context.EvalBinGate(XOR, axorb, cin);

    // carry = (a AND b) OR (cin AND (a XOR b))
    auto aandb = ctx->context.EvalBinGate(AND, a, b);
    auto cinandaxorb = ctx->context.EvalBinGate(AND, cin, axorb);
    auto carry = ctx->context.EvalBinGate(OR, aandb, cinandaxorb);

    return {sum, carry};
}

extern "C" TfheInteger tfhe_add(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        // Initialize carry to encrypted 0
        LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 0);

        for (int i = 0; i < numBits; i++) {
            auto [sum, newCarry] = fullAdder(internal, intA->bits[i], intB->bits[i], carry);
            result->bits[i] = sum;
            carry = newCarry;
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_sub(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        // a - b = a + (~b) + 1
        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        // Initialize carry to encrypted 1 (for two's complement)
        LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 1);

        for (int i = 0; i < numBits; i++) {
            // NOT b
            auto notB = internal->context.EvalNOT(intB->bits[i]);
            auto [sum, newCarry] = fullAdder(internal, intA->bits[i], notB, carry);
            result->bits[i] = sum;
            carry = newCarry;
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_neg(TfheContext ctx, TfheInteger a) {
    if (!ctx || !a) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        // -a = ~a + 1
        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 1);
        LWECiphertext zero = internal->context.Encrypt(internal->secretKey, 0);

        for (int i = 0; i < numBits; i++) {
            auto notA = internal->context.EvalNOT(intA->bits[i]);
            auto [sum, newCarry] = fullAdder(internal, notA, zero, carry);
            result->bits[i] = sum;
            carry = newCarry;
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_add_scalar(TfheContext ctx, TfheInteger a, int64_t scalar) {
    if (!ctx || !a) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 0);
        uint64_t uval = static_cast<uint64_t>(scalar);

        for (int i = 0; i < numBits; i++) {
            int bit = (uval >> i) & 1;
            auto scalarBit = internal->context.Encrypt(internal->secretKey, bit);
            auto [sum, newCarry] = fullAdder(internal, intA->bits[i], scalarBit, carry);
            result->bits[i] = sum;
            carry = newCarry;
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_sub_scalar(TfheContext ctx, TfheInteger a, int64_t scalar) {
    if (!ctx || !a) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        // a - scalar = a + (~scalar) + 1
        uint64_t uval = static_cast<uint64_t>(scalar);
        uint64_t notScalar = ~uval;
        LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 1);

        for (int i = 0; i < numBits; i++) {
            int bit = (notScalar >> i) & 1;
            auto scalarBit = internal->context.Encrypt(internal->secretKey, bit);
            auto [sum, newCarry] = fullAdder(internal, intA->bits[i], scalarBit, carry);
            result->bits[i] = sum;
            carry = newCarry;
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_mul_scalar(TfheContext ctx, TfheInteger a, int64_t scalar) {
    if (!ctx || !a) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();
        uint64_t uval = static_cast<uint64_t>(scalar);

        // Initialize result to 0
        for (int i = 0; i < numBits; i++) {
            result->bits[i] = internal->context.Encrypt(internal->secretKey, 0);
        }

        // Shift-and-add multiplication
        for (int i = 0; i < numBits && (uval >> i) != 0; i++) {
            if ((uval >> i) & 1) {
                // Add shifted a to result
                LWECiphertext carry = internal->context.Encrypt(internal->secretKey, 0);
                for (int j = i; j < numBits; j++) {
                    auto [sum, newCarry] = fullAdder(internal, result->bits[j], intA->bits[j-i], carry);
                    result->bits[j] = sum;
                    carry = newCarry;
                }
            }
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Integer Comparisons
// =============================================================================

extern "C" TfheCiphertext tfhe_eq(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        // eq = AND of all (a[i] XNOR b[i])
        LWECiphertext result = internal->context.Encrypt(internal->secretKey, 1);

        for (size_t i = 0; i < intA->bits.size(); i++) {
            auto xnor = internal->context.EvalBinGate(XNOR, intA->bits[i], intB->bits[i]);
            result = internal->context.EvalBinGate(AND, result, xnor);
        }

        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_ne(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto eq = tfhe_eq(ctx, a, b);
        if (!eq) return nullptr;

        auto* eqPtr = static_cast<LWECiphertext*>(eq);
        auto result = internal->context.EvalNOT(*eqPtr);
        delete eqPtr;

        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_lt(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        // Compute a < b using bit comparison from MSB to LSB
        // lt = 0, eq = 1
        LWECiphertext lt = internal->context.Encrypt(internal->secretKey, 0);
        LWECiphertext eq = internal->context.Encrypt(internal->secretKey, 1);

        for (int i = static_cast<int>(intA->bits.size()) - 1; i >= 0; i--) {
            // lt = lt OR (eq AND (NOT a[i]) AND b[i])
            auto notA = internal->context.EvalNOT(intA->bits[i]);
            auto notAandB = internal->context.EvalBinGate(AND, notA, intB->bits[i]);
            auto eqAndNotAandB = internal->context.EvalBinGate(AND, eq, notAandB);
            lt = internal->context.EvalBinGate(OR, lt, eqAndNotAandB);

            // eq = eq AND (a[i] XNOR b[i])
            auto xnor = internal->context.EvalBinGate(XNOR, intA->bits[i], intB->bits[i]);
            eq = internal->context.EvalBinGate(AND, eq, xnor);
        }

        return static_cast<TfheCiphertext>(new LWECiphertext(lt));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_le(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);

        // le = lt OR eq
        auto lt = tfhe_lt(ctx, a, b);
        auto eq = tfhe_eq(ctx, a, b);
        if (!lt || !eq) {
            if (lt) tfhe_ciphertext_free(lt);
            if (eq) tfhe_ciphertext_free(eq);
            return nullptr;
        }

        auto* ltPtr = static_cast<LWECiphertext*>(lt);
        auto* eqPtr = static_cast<LWECiphertext*>(eq);
        auto result = internal->context.EvalBinGate(OR, *ltPtr, *eqPtr);
        delete ltPtr;
        delete eqPtr;

        return static_cast<TfheCiphertext>(new LWECiphertext(result));
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_gt(TfheContext ctx, TfheInteger a, TfheInteger b) {
    return tfhe_lt(ctx, b, a);
}

extern "C" TfheCiphertext tfhe_ge(TfheContext ctx, TfheInteger a, TfheInteger b) {
    return tfhe_le(ctx, b, a);
}

extern "C" TfheInteger tfhe_min(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto lt = tfhe_lt(ctx, a, b);
        if (!lt) return nullptr;

        auto result = tfhe_select(ctx, lt, a, b);
        tfhe_ciphertext_free(lt);
        return result;
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_max(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto lt = tfhe_lt(ctx, a, b);
        if (!lt) return nullptr;

        auto result = tfhe_select(ctx, lt, b, a);
        tfhe_ciphertext_free(lt);
        return result;
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Integer Bitwise Operations
// =============================================================================

extern "C" TfheInteger tfhe_bitwise_and(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        auto* result = new TfheIntegerInternal(intA->itype);
        for (size_t i = 0; i < intA->bits.size(); i++) {
            result->bits[i] = internal->context.EvalBinGate(AND, intA->bits[i], intB->bits[i]);
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_bitwise_or(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        auto* result = new TfheIntegerInternal(intA->itype);
        for (size_t i = 0; i < intA->bits.size(); i++) {
            result->bits[i] = internal->context.EvalBinGate(OR, intA->bits[i], intB->bits[i]);
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_bitwise_xor(TfheContext ctx, TfheInteger a, TfheInteger b) {
    if (!ctx || !a || !b) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);
        auto* intB = static_cast<TfheIntegerInternal*>(b);

        if (intA->itype != intB->itype) return nullptr;

        auto* result = new TfheIntegerInternal(intA->itype);
        for (size_t i = 0; i < intA->bits.size(); i++) {
            result->bits[i] = internal->context.EvalBinGate(XOR, intA->bits[i], intB->bits[i]);
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_bitwise_not(TfheContext ctx, TfheInteger a) {
    if (!ctx || !a) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        for (size_t i = 0; i < intA->bits.size(); i++) {
            result->bits[i] = internal->context.EvalNOT(intA->bits[i]);
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_shl(TfheContext ctx, TfheInteger a, int bits) {
    if (!ctx || !a || bits < 0) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        for (int i = 0; i < numBits; i++) {
            if (i < bits) {
                result->bits[i] = internal->context.Encrypt(internal->secretKey, 0);
            } else {
                result->bits[i] = intA->bits[i - bits];
            }
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_shr(TfheContext ctx, TfheInteger a, int bits) {
    if (!ctx || !a || bits < 0) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(intA->itype);
        int numBits = result->numBits();

        for (int i = 0; i < numBits; i++) {
            if (i + bits >= numBits) {
                result->bits[i] = internal->context.Encrypt(internal->secretKey, 0);
            } else {
                result->bits[i] = intA->bits[i + bits];
            }
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Control Flow
// =============================================================================

extern "C" TfheInteger tfhe_select(TfheContext ctx, TfheCiphertext cond, TfheInteger if_true, TfheInteger if_false) {
    if (!ctx || !cond || !if_true || !if_false) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* condPtr = static_cast<LWECiphertext*>(cond);
        auto* intTrue = static_cast<TfheIntegerInternal*>(if_true);
        auto* intFalse = static_cast<TfheIntegerInternal*>(if_false);

        if (intTrue->itype != intFalse->itype) return nullptr;

        auto* result = new TfheIntegerInternal(intTrue->itype);
        auto notCond = internal->context.EvalNOT(*condPtr);

        for (size_t i = 0; i < intTrue->bits.size(); i++) {
            // result[i] = (cond AND true[i]) OR ((NOT cond) AND false[i])
            auto condAndTrue = internal->context.EvalBinGate(AND, *condPtr, intTrue->bits[i]);
            auto notCondAndFalse = internal->context.EvalBinGate(AND, notCond, intFalse->bits[i]);
            result->bits[i] = internal->context.EvalBinGate(OR, condAndTrue, notCondAndFalse);
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_cast_to(TfheContext ctx, TfheInteger a, int target_bitlen) {
    if (!ctx || !a || target_bitlen <= 0) return nullptr;

    try {
        auto* internal = static_cast<TfheContextInternal*>(ctx);
        auto* intA = static_cast<TfheIntegerInternal*>(a);

        auto* result = new TfheIntegerInternal(target_bitlen);
        int srcBits = intA->numBits();
        int dstBits = result->numBits();

        for (int i = 0; i < dstBits; i++) {
            if (i < srcBits) {
                result->bits[i] = intA->bits[i];
            } else {
                result->bits[i] = internal->context.Encrypt(internal->secretKey, 0);
            }
        }

        return static_cast<TfheInteger>(result);
    } catch (...) {
        return nullptr;
    }
}

// =============================================================================
// Serialization (using OpenFHE's serialization)
// =============================================================================

extern "C" uint8_t* tfhe_serialize_ciphertext(TfheContext ctx, TfheCiphertext ct, size_t* out_len) {
    if (!ctx || !ct || !out_len) return nullptr;

    try {
        auto* ctPtr = static_cast<LWECiphertext*>(ct);
        std::stringstream ss;

        // Use OpenFHE's serialization
        lbcrypto::Serial::Serialize(*ctPtr, ss, lbcrypto::SerType::BINARY);

        std::string data = ss.str();
        *out_len = data.size();
        uint8_t* out = static_cast<uint8_t*>(malloc(*out_len));
        if (out) {
            std::memcpy(out, data.data(), *out_len);
        }
        return out;
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheCiphertext tfhe_deserialize_ciphertext(TfheContext ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len == 0) return nullptr;

    try {
        std::stringstream ss(std::string(reinterpret_cast<const char*>(data), len));
        LWECiphertext ct;
        lbcrypto::Serial::Deserialize(ct, ss, lbcrypto::SerType::BINARY);
        return static_cast<TfheCiphertext>(new LWECiphertext(ct));
    } catch (...) {
        return nullptr;
    }
}

extern "C" uint8_t* tfhe_serialize_secret_key(TfheContext ctx, TfheSecretKey sk, size_t* out_len) {
    if (!ctx || !sk || !out_len) return nullptr;

    try {
        auto* skPtr = static_cast<LWEPrivateKey*>(sk);
        std::stringstream ss;
        lbcrypto::Serial::Serialize(*skPtr, ss, lbcrypto::SerType::BINARY);

        std::string data = ss.str();
        *out_len = data.size();
        uint8_t* out = static_cast<uint8_t*>(malloc(*out_len));
        if (out) {
            std::memcpy(out, data.data(), *out_len);
        }
        return out;
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheSecretKey tfhe_deserialize_secret_key(TfheContext ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len == 0) return nullptr;

    try {
        std::stringstream ss(std::string(reinterpret_cast<const char*>(data), len));
        LWEPrivateKey sk;
        lbcrypto::Serial::Deserialize(sk, ss, lbcrypto::SerType::BINARY);
        return static_cast<TfheSecretKey>(new LWEPrivateKey(sk));
    } catch (...) {
        return nullptr;
    }
}

extern "C" uint8_t* tfhe_serialize_public_key(TfheContext ctx, TfhePublicKey pk, size_t* out_len) {
    (void)ctx;
    (void)pk;
    (void)out_len;
    return nullptr; // Not implemented for BinFHE
}

extern "C" TfhePublicKey tfhe_deserialize_public_key(TfheContext ctx, const uint8_t* data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
    return nullptr; // Not implemented for BinFHE
}

extern "C" uint8_t* tfhe_serialize_integer(TfheContext ctx, TfheInteger ct, size_t* out_len) {
    if (!ctx || !ct || !out_len) return nullptr;

    try {
        auto* integer = static_cast<TfheIntegerInternal*>(ct);
        std::stringstream ss;

        // Write type
        int32_t itype = static_cast<int32_t>(integer->itype);
        ss.write(reinterpret_cast<const char*>(&itype), sizeof(itype));

        // Write number of bits
        uint32_t numBits = static_cast<uint32_t>(integer->bits.size());
        ss.write(reinterpret_cast<const char*>(&numBits), sizeof(numBits));

        // Serialize each bit
        for (const auto& bit : integer->bits) {
            lbcrypto::Serial::Serialize(bit, ss, lbcrypto::SerType::BINARY);
        }

        std::string data = ss.str();
        *out_len = data.size();
        uint8_t* out = static_cast<uint8_t*>(malloc(*out_len));
        if (out) {
            std::memcpy(out, data.data(), *out_len);
        }
        return out;
    } catch (...) {
        return nullptr;
    }
}

extern "C" TfheInteger tfhe_deserialize_integer(TfheContext ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len == 0) return nullptr;

    try {
        std::stringstream ss(std::string(reinterpret_cast<const char*>(data), len));

        // Read type
        int32_t itype;
        ss.read(reinterpret_cast<char*>(&itype), sizeof(itype));

        // Read number of bits
        uint32_t numBits;
        ss.read(reinterpret_cast<char*>(&numBits), sizeof(numBits));

        auto* integer = new TfheIntegerInternal(static_cast<TfheIntType>(itype));
        integer->bits.resize(numBits);

        // Deserialize each bit
        for (uint32_t i = 0; i < numBits; i++) {
            lbcrypto::Serial::Deserialize(integer->bits[i], ss, lbcrypto::SerType::BINARY);
        }

        return static_cast<TfheInteger>(integer);
    } catch (...) {
        return nullptr;
    }
}
