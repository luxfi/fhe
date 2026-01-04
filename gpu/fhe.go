// Package gpu provides FHE operations with optional GPU acceleration.
// When CGO is disabled, this package delegates to the pure Go fhe package.
package gpu

import (
	"errors"
	"sync"

	"github.com/luxfi/fhe"
)

// SecurityLevel represents the security strength
type SecurityLevel int

const (
	SecuritySTD128 SecurityLevel = iota
	SecuritySTD192
	SecuritySTD256
)

// Method represents the FHE method/variant
type Method int

const (
	MethodAP      Method = iota // Alperin-Sheriff-Peikert
	MethodGINX                  // GINX bootstrapping
	MethodLMKCDEY               // LMKCDEY bootstrapping
)

// Context wraps the pure Go FHE context
type Context struct {
	params    fhe.Parameters
	kgen      *fhe.KeyGenerator
	evaluator *fhe.Evaluator
	mu        sync.RWMutex
}

// SecretKey wraps the pure Go secret key
type SecretKey struct {
	key *fhe.SecretKey
	ctx *Context
}

// PublicKey wraps the pure Go bootstrap key
type PublicKey struct {
	bsk *fhe.BootstrapKey
	ctx *Context
}

// Ciphertext wraps the pure Go ciphertext
type Ciphertext struct {
	ct  *fhe.Ciphertext
	ctx *Context
}

// Integer wraps encrypted integer bits
type Integer struct {
	bits   []*fhe.Ciphertext
	ctx    *Context
	bitLen int
}

// getParamsLiteral maps security level to parameter literal
func getParamsLiteral(level SecurityLevel) fhe.ParametersLiteral {
	switch level {
	case SecuritySTD192, SecuritySTD256:
		return fhe.PN11QP54
	default:
		return fhe.PN10QP27
	}
}

// NewContext creates a new FHE context using pure Go implementation
func NewContext(level SecurityLevel, method Method) (*Context, error) {
	literal := getParamsLiteral(level)
	params, err := fhe.NewParametersFromLiteral(literal)
	if err != nil {
		return nil, err
	}

	ctx := &Context{
		params: params,
		kgen:   fhe.NewKeyGenerator(params),
	}
	return ctx, nil
}

// Free releases the context resources
func (c *Context) Free() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evaluator = nil
	c.kgen = nil
}

// GenerateSecretKey generates a new secret key
func (c *Context) GenerateSecretKey() (*SecretKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.kgen == nil {
		return nil, errors.New("context not initialized")
	}

	sk := c.kgen.GenSecretKey()
	return &SecretKey{
		key: sk,
		ctx: c,
	}, nil
}

// Free releases the secret key
func (sk *SecretKey) Free() {
	sk.key = nil
}

// GenerateBootstrapKey generates the bootstrapping key
func (c *Context) GenerateBootstrapKey(sk *SecretKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.kgen == nil {
		return errors.New("context not initialized")
	}
	if sk.key == nil {
		return errors.New("secret key is nil")
	}

	bsk := c.kgen.GenBootstrapKey(sk.key)
	c.evaluator = fhe.NewEvaluator(c.params, bsk)
	return nil
}

// GeneratePublicKey generates a public key from secret key
func (c *Context) GeneratePublicKey(sk *SecretKey) (*PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.kgen == nil {
		return nil, errors.New("context not initialized")
	}
	if sk.key == nil {
		return nil, errors.New("secret key is nil")
	}

	bsk := c.kgen.GenBootstrapKey(sk.key)
	return &PublicKey{
		bsk: bsk,
		ctx: c,
	}, nil
}

// Free releases the public key
func (pk *PublicKey) Free() {
	pk.bsk = nil
}

// EncryptBit encrypts a single bit using secret key
func (c *Context) EncryptBit(sk *SecretKey, value bool) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if sk.key == nil {
		return nil, errors.New("secret key is nil")
	}

	enc := fhe.NewEncryptor(c.params, sk.key)
	var bit int
	if value {
		bit = 1
	}
	ct := enc.EncryptBit(bit)

	return &Ciphertext{
		ct:  ct,
		ctx: c,
	}, nil
}

// DecryptBit decrypts a ciphertext to a boolean
func (c *Context) DecryptBit(sk *SecretKey, ct *Ciphertext) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if sk.key == nil {
		return false, errors.New("secret key is nil")
	}

	dec := fhe.NewDecryptor(c.params, sk.key)
	bit := dec.DecryptBit(ct.ct)
	return bit == 1, nil
}

// AND performs homomorphic AND on two ciphertexts
func (c *Context) AND(a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.AND(a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// OR performs homomorphic OR on two ciphertexts
func (c *Context) OR(a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.OR(a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// XOR performs homomorphic XOR on two ciphertexts
func (c *Context) XOR(a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.XOR(a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// NOT performs homomorphic NOT on a ciphertext
func (c *Context) NOT(a *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := c.evaluator.NOT(a.ct)
	return &Ciphertext{ct: result, ctx: c}, nil
}

// NAND performs homomorphic NAND on two ciphertexts
func (c *Context) NAND(a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.NAND(a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// GPUAvailable returns false when CGO is disabled
func GPUAvailable() bool {
	return false
}

// GetBackend returns "CPU (pure Go)" when CGO is disabled
func GetBackend() string {
	return "CPU (pure Go)"
}

// ErrNoBootstrapKey is returned when operations are attempted without a bootstrap key
var ErrNoBootstrapKey = errors.New("bootstrap key not generated - call GenerateBootstrapKey first")
