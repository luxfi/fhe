// Package main exports lux/fhe functions as a C shared library.
//
// Build:
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o dist/libluxfhe.so ./bindings/cabi/
//	CGO_ENABLED=1 go build -buildmode=c-shared -o dist/libluxfhe.dylib ./bindings/cabi/  # macOS
//	install_name_tool -id @rpath/libluxfhe.dylib dist/libluxfhe.dylib               # macOS rpath
//
// This produces libluxfhe.{so,dylib,dll} + libluxfhe.h
// which Python (ctypes/cffi), TypeScript (N-API/WASM), and Rust (FFI) can bind to.
//
// All stateful Go objects (parameters, keys, encryptors, etc.) are stored behind
// opaque uint64 handles. A global handle map prevents GC collection.
package main

import "C"
import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/luxfi/fhe"
)

// ═══════════════════════════════════════════════════════════════════════
// Handle map — opaque uint64 IDs prevent Go GC from collecting objects
// ═══════════════════════════════════════════════════════════════════════

var (
	handleMu   sync.RWMutex
	handleMap  = make(map[C.ulonglong]any)
	nextHandle atomic.Uint64
)

func storeHandle(obj any) C.ulonglong {
	h := C.ulonglong(nextHandle.Add(1))
	handleMu.Lock()
	handleMap[h] = obj
	handleMu.Unlock()
	return h
}

func loadHandle[T any](h C.ulonglong) (T, bool) {
	handleMu.RLock()
	obj, ok := handleMap[h]
	handleMu.RUnlock()
	if !ok {
		var zero T
		return zero, false
	}
	val, ok := obj.(T)
	return val, ok
}

func dropHandle(h C.ulonglong) {
	handleMu.Lock()
	delete(handleMap, h)
	handleMu.Unlock()
}

// ═══════════════════════════════════════════════════════════════════════
// Handle free
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_drop
func lux_fhe_drop(handle C.ulonglong) {
	dropHandle(handle)
}

// ═══════════════════════════════════════════════════════════════════════
// Parameters
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_params_pn10qp27
func lux_fhe_params_pn10qp27(out *C.ulonglong) C.int {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return -1
	}
	*out = storeHandle(params)
	return 0
}

// ═══════════════════════════════════════════════════════════════════════
// KeyGenerator
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_keygen_new
func lux_fhe_keygen_new(paramsH C.ulonglong, out *C.ulonglong) C.int {
	params, ok := loadHandle[fhe.Parameters](paramsH)
	if !ok {
		return -1
	}
	kg := fhe.NewKeyGenerator(params)
	*out = storeHandle(kg)
	return 0
}

//export lux_fhe_keygen_gen_secret_key
func lux_fhe_keygen_gen_secret_key(kgH C.ulonglong, out *C.ulonglong) C.int {
	kg, ok := loadHandle[*fhe.KeyGenerator](kgH)
	if !ok {
		return -1
	}
	sk := kg.GenSecretKey()
	*out = storeHandle(sk)
	return 0
}

//export lux_fhe_keygen_gen_public_key
func lux_fhe_keygen_gen_public_key(kgH C.ulonglong, skH C.ulonglong, out *C.ulonglong) C.int {
	kg, ok := loadHandle[*fhe.KeyGenerator](kgH)
	if !ok {
		return -1
	}
	sk, ok := loadHandle[*fhe.SecretKey](skH)
	if !ok {
		return -2
	}
	pk := kg.GenPublicKey(sk)
	*out = storeHandle(pk)
	return 0
}

//export lux_fhe_keygen_gen_keypair
func lux_fhe_keygen_gen_keypair(kgH C.ulonglong, skOut *C.ulonglong, pkOut *C.ulonglong) C.int {
	kg, ok := loadHandle[*fhe.KeyGenerator](kgH)
	if !ok {
		return -1
	}
	sk, pk := kg.GenKeyPair()
	*skOut = storeHandle(sk)
	*pkOut = storeHandle(pk)
	return 0
}

//export lux_fhe_keygen_gen_bootstrap_key
func lux_fhe_keygen_gen_bootstrap_key(kgH C.ulonglong, skH C.ulonglong, out *C.ulonglong) C.int {
	kg, ok := loadHandle[*fhe.KeyGenerator](kgH)
	if !ok {
		return -1
	}
	sk, ok := loadHandle[*fhe.SecretKey](skH)
	if !ok {
		return -2
	}
	bsk := kg.GenBootstrapKey(sk)
	*out = storeHandle(bsk)
	return 0
}

// ═══════════════════════════════════════════════════════════════════════
// Encryptor
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_encryptor_new
func lux_fhe_encryptor_new(paramsH C.ulonglong, skH C.ulonglong, out *C.ulonglong) C.int {
	params, ok := loadHandle[fhe.Parameters](paramsH)
	if !ok {
		return -1
	}
	sk, ok := loadHandle[*fhe.SecretKey](skH)
	if !ok {
		return -2
	}
	enc := fhe.NewEncryptor(params, sk)
	*out = storeHandle(enc)
	return 0
}

//export lux_fhe_encrypt
func lux_fhe_encrypt(encH C.ulonglong, value C.int, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	ct := enc.Encrypt(value != 0)
	*out = storeHandle(ct)
	return 0
}

//export lux_fhe_encrypt_bit
func lux_fhe_encrypt_bit(encH C.ulonglong, bit C.int, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	ct := enc.EncryptBit(int(bit))
	*out = storeHandle(ct)
	return 0
}

//export lux_fhe_encrypt_byte
func lux_fhe_encrypt_byte(encH C.ulonglong, b C.uchar, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	cts := enc.EncryptByte(byte(b))
	for i := 0; i < 8; i++ {
		out_i := (*C.ulonglong)(pointerOffset(out, i))
		*out_i = storeHandle(cts[i])
	}
	return 0
}

//export lux_fhe_encrypt_uint32
func lux_fhe_encrypt_uint32(encH C.ulonglong, v C.uint, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	cts := enc.EncryptUint32(uint32(v))
	for i := 0; i < 32; i++ {
		out_i := (*C.ulonglong)(pointerOffset(out, i))
		*out_i = storeHandle(cts[i])
	}
	return 0
}

//export lux_fhe_encrypt_uint64
func lux_fhe_encrypt_uint64(encH C.ulonglong, v C.ulonglong, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	cts := enc.EncryptUint64(uint64(v))
	for i := 0; i < 64; i++ {
		out_i := (*C.ulonglong)(pointerOffset(out, i))
		*out_i = storeHandle(cts[i])
	}
	return 0
}

//export lux_fhe_encrypt_uint256
func lux_fhe_encrypt_uint256(encH C.ulonglong, limbs *C.ulonglong, out *C.ulonglong) C.int {
	enc, ok := loadHandle[*fhe.Encryptor](encH)
	if !ok {
		return -1
	}
	var v [4]uint64
	for i := 0; i < 4; i++ {
		v[i] = uint64(*(*C.ulonglong)(pointerOffset(limbs, i)))
	}
	cts := enc.EncryptUint256(v)
	for i := 0; i < 256; i++ {
		out_i := (*C.ulonglong)(pointerOffset(out, i))
		*out_i = storeHandle(cts[i])
	}
	return 0
}

// ═══════════════════════════════════════════════════════════════════════
// Decryptor
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_decryptor_new
func lux_fhe_decryptor_new(paramsH C.ulonglong, skH C.ulonglong, out *C.ulonglong) C.int {
	params, ok := loadHandle[fhe.Parameters](paramsH)
	if !ok {
		return -1
	}
	sk, ok := loadHandle[*fhe.SecretKey](skH)
	if !ok {
		return -2
	}
	dec := fhe.NewDecryptor(params, sk)
	*out = storeHandle(dec)
	return 0
}

//export lux_fhe_decrypt
func lux_fhe_decrypt(decH C.ulonglong, ctH C.ulonglong, out *C.int) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	ct, ok := loadHandle[*fhe.Ciphertext](ctH)
	if !ok {
		return -2
	}
	if dec.Decrypt(ct) {
		*out = 1
	} else {
		*out = 0
	}
	return 0
}

//export lux_fhe_decrypt_bit
func lux_fhe_decrypt_bit(decH C.ulonglong, ctH C.ulonglong, out *C.int) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	ct, ok := loadHandle[*fhe.Ciphertext](ctH)
	if !ok {
		return -2
	}
	*out = C.int(dec.DecryptBit(ct))
	return 0
}

//export lux_fhe_decrypt_byte
func lux_fhe_decrypt_byte(decH C.ulonglong, handles *C.ulonglong, out *C.uchar) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	var cts [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		h := *(*C.ulonglong)(pointerOffset(handles, i))
		ct, ok := loadHandle[*fhe.Ciphertext](h)
		if !ok {
			return -2
		}
		cts[i] = ct
	}
	*out = C.uchar(dec.DecryptByte(cts))
	return 0
}

//export lux_fhe_decrypt_uint32
func lux_fhe_decrypt_uint32(decH C.ulonglong, handles *C.ulonglong, out *C.uint) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	var cts [32]*fhe.Ciphertext
	for i := 0; i < 32; i++ {
		h := *(*C.ulonglong)(pointerOffset(handles, i))
		ct, ok := loadHandle[*fhe.Ciphertext](h)
		if !ok {
			return -2
		}
		cts[i] = ct
	}
	*out = C.uint(dec.DecryptUint32(cts))
	return 0
}

//export lux_fhe_decrypt_uint64
func lux_fhe_decrypt_uint64(decH C.ulonglong, handles *C.ulonglong, out *C.ulonglong) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	var cts [64]*fhe.Ciphertext
	for i := 0; i < 64; i++ {
		h := *(*C.ulonglong)(pointerOffset(handles, i))
		ct, ok := loadHandle[*fhe.Ciphertext](h)
		if !ok {
			return -2
		}
		cts[i] = ct
	}
	*out = C.ulonglong(dec.DecryptUint64(cts))
	return 0
}

//export lux_fhe_decrypt_uint256
func lux_fhe_decrypt_uint256(decH C.ulonglong, handles *C.ulonglong, out *C.ulonglong) C.int {
	dec, ok := loadHandle[*fhe.Decryptor](decH)
	if !ok {
		return -1
	}
	var cts [256]*fhe.Ciphertext
	for i := 0; i < 256; i++ {
		h := *(*C.ulonglong)(pointerOffset(handles, i))
		ct, ok := loadHandle[*fhe.Ciphertext](h)
		if !ok {
			return -2
		}
		cts[i] = ct
	}
	v := dec.DecryptUint256(cts)
	for i := 0; i < 4; i++ {
		out_i := (*C.ulonglong)(pointerOffset(out, i))
		*out_i = C.ulonglong(v[i])
	}
	return 0
}

// ═══════════════════════════════════════════════════════════════════════
// Evaluator (boolean gates)
// ═══════════════════════════════════════════════════════════════════════

//export lux_fhe_evaluator_new
func lux_fhe_evaluator_new(paramsH C.ulonglong, bskH C.ulonglong, out *C.ulonglong) C.int {
	params, ok := loadHandle[fhe.Parameters](paramsH)
	if !ok {
		return -1
	}
	bsk, ok := loadHandle[*fhe.BootstrapKey](bskH)
	if !ok {
		return -2
	}
	eval := fhe.NewEvaluator(params, bsk)
	*out = storeHandle(eval)
	return 0
}

//export lux_fhe_eval_and
func lux_fhe_eval_and(evalH C.ulonglong, ct1H C.ulonglong, ct2H C.ulonglong, out *C.ulonglong) C.int {
	eval, ok := loadHandle[*fhe.Evaluator](evalH)
	if !ok {
		return -1
	}
	ct1, ok := loadHandle[*fhe.Ciphertext](ct1H)
	if !ok {
		return -2
	}
	ct2, ok := loadHandle[*fhe.Ciphertext](ct2H)
	if !ok {
		return -3
	}
	result, err := eval.AND(ct1, ct2)
	if err != nil {
		return -10
	}
	*out = storeHandle(result)
	return 0
}

//export lux_fhe_eval_or
func lux_fhe_eval_or(evalH C.ulonglong, ct1H C.ulonglong, ct2H C.ulonglong, out *C.ulonglong) C.int {
	eval, ok := loadHandle[*fhe.Evaluator](evalH)
	if !ok {
		return -1
	}
	ct1, ok := loadHandle[*fhe.Ciphertext](ct1H)
	if !ok {
		return -2
	}
	ct2, ok := loadHandle[*fhe.Ciphertext](ct2H)
	if !ok {
		return -3
	}
	result, err := eval.OR(ct1, ct2)
	if err != nil {
		return -10
	}
	*out = storeHandle(result)
	return 0
}

//export lux_fhe_eval_xor
func lux_fhe_eval_xor(evalH C.ulonglong, ct1H C.ulonglong, ct2H C.ulonglong, out *C.ulonglong) C.int {
	eval, ok := loadHandle[*fhe.Evaluator](evalH)
	if !ok {
		return -1
	}
	ct1, ok := loadHandle[*fhe.Ciphertext](ct1H)
	if !ok {
		return -2
	}
	ct2, ok := loadHandle[*fhe.Ciphertext](ct2H)
	if !ok {
		return -3
	}
	result, err := eval.XOR(ct1, ct2)
	if err != nil {
		return -10
	}
	*out = storeHandle(result)
	return 0
}

//export lux_fhe_eval_not
func lux_fhe_eval_not(evalH C.ulonglong, ctH C.ulonglong, out *C.ulonglong) C.int {
	eval, ok := loadHandle[*fhe.Evaluator](evalH)
	if !ok {
		return -1
	}
	ct, ok := loadHandle[*fhe.Ciphertext](ctH)
	if !ok {
		return -2
	}
	result := eval.NOT(ct)
	*out = storeHandle(result)
	return 0
}

//export lux_fhe_eval_nand
func lux_fhe_eval_nand(evalH C.ulonglong, ct1H C.ulonglong, ct2H C.ulonglong, out *C.ulonglong) C.int {
	eval, ok := loadHandle[*fhe.Evaluator](evalH)
	if !ok {
		return -1
	}
	ct1, ok := loadHandle[*fhe.Ciphertext](ct1H)
	if !ok {
		return -2
	}
	ct2, ok := loadHandle[*fhe.Ciphertext](ct2H)
	if !ok {
		return -3
	}
	result, err := eval.NAND(ct1, ct2)
	if err != nil {
		return -10
	}
	*out = storeHandle(result)
	return 0
}

// ═══════════════════════════════════════════════════════════════════════
// Pointer arithmetic helper for array access across CGo boundary
// ═══════════════════════════════════════════════════════════════════════

func pointerOffset(base *C.ulonglong, index int) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(base), index*8) // 8 bytes per uint64
}

func main() {}
