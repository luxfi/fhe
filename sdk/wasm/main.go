//go:build js && wasm

// Package main provides WASM bindings for Lux TFHE
//
// Exports FHE operations to JavaScript:
// - generateKeys() -> {publicKey, secretKey}
// - encrypt(value, bitWidth, publicKey) -> ciphertext
// - decrypt(ciphertext, secretKey) -> value
// - add(ct1, ct2) -> result
// - sub(ct1, ct2) -> result
// - eq(ct1, ct2) -> result
// - lt(ct1, ct2) -> result
package main

import (
	"encoding/base64"
	"syscall/js"

	"github.com/luxfi/tfhe"
)

var (
	params tfhe.Parameters
	kgen   *tfhe.KeyGenerator
)

func init() {
	var err error
	params, err = tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		panic("failed to init TFHE params: " + err.Error())
	}
	kgen = tfhe.NewKeyGenerator(params)
}

// generateKeys creates a new key pair
// Returns: {publicKey: base64, secretKey: base64, bootstrapKey: base64}
func generateKeys(this js.Value, args []js.Value) interface{} {
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)
	bsk := kgen.GenBootstrapKey(sk)

	skBytes, _ := sk.MarshalBinary()
	pkBytes, _ := pk.MarshalBinary()
	bskBytes, _ := bsk.MarshalBinary()

	return map[string]interface{}{
		"secretKey":    base64.StdEncoding.EncodeToString(skBytes),
		"publicKey":    base64.StdEncoding.EncodeToString(pkBytes),
		"bootstrapKey": base64.StdEncoding.EncodeToString(bskBytes),
	}
}

// encrypt encrypts a value using the public key
// Args: value (number), bitWidth (number), publicKeyB64 (string)
// Returns: base64 encoded ciphertext
func encrypt(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf("error: requires (value, bitWidth, publicKey)")
	}

	value := uint64(args[0].Int())
	bitWidth := args[1].Int()
	pkB64 := args[2].String()

	// Decode public key
	pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		return js.ValueOf("error: invalid public key")
	}

	pk := new(tfhe.PublicKey)
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return js.ValueOf("error: failed to parse public key")
	}

	// Encrypt
	enc := tfhe.NewBitwisePublicEncryptor(params, pk)
	fheType := bitWidthToType(bitWidth)
	ct := enc.EncryptUint64(value, fheType)

	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return js.ValueOf("error: failed to serialize ciphertext")
	}

	return js.ValueOf(base64.StdEncoding.EncodeToString(ctBytes))
}

// decrypt decrypts a ciphertext using the secret key
// Args: ciphertextB64 (string), secretKeyB64 (string)
// Returns: decrypted value as number
func decrypt(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf("error: requires (ciphertext, secretKey)")
	}

	ctB64 := args[0].String()
	skB64 := args[1].String()

	// Decode
	ctBytes, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return js.ValueOf("error: invalid ciphertext")
	}

	skBytes, err := base64.StdEncoding.DecodeString(skB64)
	if err != nil {
		return js.ValueOf("error: invalid secret key")
	}

	ct := new(tfhe.BitCiphertext)
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return js.ValueOf("error: failed to parse ciphertext")
	}

	sk := new(tfhe.SecretKey)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return js.ValueOf("error: failed to parse secret key")
	}

	// Decrypt
	dec := tfhe.NewBitwiseDecryptor(params, sk)
	result := dec.DecryptUint64(ct)

	return js.ValueOf(int64(result))
}

// fheAdd adds two encrypted values
// Args: ct1B64, ct2B64, bootstrapKeyB64, secretKeyB64
// Returns: base64 encoded result ciphertext
func fheAdd(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.ValueOf("error: requires (ct1, ct2, bootstrapKey, secretKey)")
	}

	ct1B64 := args[0].String()
	ct2B64 := args[1].String()
	bskB64 := args[2].String()
	skB64 := args[3].String()

	ct1Bytes, _ := base64.StdEncoding.DecodeString(ct1B64)
	ct2Bytes, _ := base64.StdEncoding.DecodeString(ct2B64)
	bskBytes, _ := base64.StdEncoding.DecodeString(bskB64)
	skBytes, _ := base64.StdEncoding.DecodeString(skB64)

	ct1 := new(tfhe.BitCiphertext)
	ct1.UnmarshalBinary(ct1Bytes)

	ct2 := new(tfhe.BitCiphertext)
	ct2.UnmarshalBinary(ct2Bytes)

	bsk := new(tfhe.BootstrapKey)
	bsk.UnmarshalBinary(bskBytes)

	sk := new(tfhe.SecretKey)
	sk.UnmarshalBinary(skBytes)

	// Evaluate
	eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
	result, err := eval.Add(ct1, ct2)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	resultBytes, _ := result.MarshalBinary()
	return js.ValueOf(base64.StdEncoding.EncodeToString(resultBytes))
}

// fheSub subtracts two encrypted values
func fheSub(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.ValueOf("error: requires (ct1, ct2, bootstrapKey, secretKey)")
	}

	ct1B64 := args[0].String()
	ct2B64 := args[1].String()
	bskB64 := args[2].String()
	skB64 := args[3].String()

	ct1Bytes, _ := base64.StdEncoding.DecodeString(ct1B64)
	ct2Bytes, _ := base64.StdEncoding.DecodeString(ct2B64)
	bskBytes, _ := base64.StdEncoding.DecodeString(bskB64)
	skBytes, _ := base64.StdEncoding.DecodeString(skB64)

	ct1 := new(tfhe.BitCiphertext)
	ct1.UnmarshalBinary(ct1Bytes)

	ct2 := new(tfhe.BitCiphertext)
	ct2.UnmarshalBinary(ct2Bytes)

	bsk := new(tfhe.BootstrapKey)
	bsk.UnmarshalBinary(bskBytes)

	sk := new(tfhe.SecretKey)
	sk.UnmarshalBinary(skBytes)

	eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
	result, err := eval.Sub(ct1, ct2)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	resultBytes, _ := result.MarshalBinary()
	return js.ValueOf(base64.StdEncoding.EncodeToString(resultBytes))
}

// fheEq compares two encrypted values for equality
func fheEq(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.ValueOf("error: requires (ct1, ct2, bootstrapKey, secretKey)")
	}

	ct1B64 := args[0].String()
	ct2B64 := args[1].String()
	bskB64 := args[2].String()
	skB64 := args[3].String()

	ct1Bytes, _ := base64.StdEncoding.DecodeString(ct1B64)
	ct2Bytes, _ := base64.StdEncoding.DecodeString(ct2B64)
	bskBytes, _ := base64.StdEncoding.DecodeString(bskB64)
	skBytes, _ := base64.StdEncoding.DecodeString(skB64)

	ct1 := new(tfhe.BitCiphertext)
	ct1.UnmarshalBinary(ct1Bytes)

	ct2 := new(tfhe.BitCiphertext)
	ct2.UnmarshalBinary(ct2Bytes)

	bsk := new(tfhe.BootstrapKey)
	bsk.UnmarshalBinary(bskBytes)

	sk := new(tfhe.SecretKey)
	sk.UnmarshalBinary(skBytes)

	eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
	result, err := eval.Eq(ct1, ct2)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	resultBytes, _ := tfhe.WrapBoolCiphertext(result).MarshalBinary()
	return js.ValueOf(base64.StdEncoding.EncodeToString(resultBytes))
}

// fheLt compares ct1 < ct2
func fheLt(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.ValueOf("error: requires (ct1, ct2, bootstrapKey, secretKey)")
	}

	ct1B64 := args[0].String()
	ct2B64 := args[1].String()
	bskB64 := args[2].String()
	skB64 := args[3].String()

	ct1Bytes, _ := base64.StdEncoding.DecodeString(ct1B64)
	ct2Bytes, _ := base64.StdEncoding.DecodeString(ct2B64)
	bskBytes, _ := base64.StdEncoding.DecodeString(bskB64)
	skBytes, _ := base64.StdEncoding.DecodeString(skB64)

	ct1 := new(tfhe.BitCiphertext)
	ct1.UnmarshalBinary(ct1Bytes)

	ct2 := new(tfhe.BitCiphertext)
	ct2.UnmarshalBinary(ct2Bytes)

	bsk := new(tfhe.BootstrapKey)
	bsk.UnmarshalBinary(bskBytes)

	sk := new(tfhe.SecretKey)
	sk.UnmarshalBinary(skBytes)

	eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
	result, err := eval.Lt(ct1, ct2)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}

	resultBytes, _ := tfhe.WrapBoolCiphertext(result).MarshalBinary()
	return js.ValueOf(base64.StdEncoding.EncodeToString(resultBytes))
}

// getVersion returns the TFHE version
func getVersion(this js.Value, args []js.Value) interface{} {
	return js.ValueOf("1.0.0")
}

func bitWidthToType(bits int) tfhe.FheUintType {
	switch bits {
	case 4:
		return tfhe.FheUint4
	case 8:
		return tfhe.FheUint8
	case 16:
		return tfhe.FheUint16
	case 32:
		return tfhe.FheUint32
	case 64:
		return tfhe.FheUint64
	case 128:
		return tfhe.FheUint128
	case 160:
		return tfhe.FheUint160
	case 256:
		return tfhe.FheUint256
	default:
		return tfhe.FheUint32
	}
}

func main() {
	// Export functions to JavaScript global scope
	js.Global().Set("luxfhe", map[string]interface{}{
		"version":      js.FuncOf(getVersion),
		"generateKeys": js.FuncOf(generateKeys),
		"encrypt":      js.FuncOf(encrypt),
		"decrypt":      js.FuncOf(decrypt),
		"add":          js.FuncOf(fheAdd),
		"sub":          js.FuncOf(fheSub),
		"eq":           js.FuncOf(fheEq),
		"lt":           js.FuncOf(fheLt),
	})

	// Keep the Go runtime alive
	select {}
}
