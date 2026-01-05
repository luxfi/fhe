// Package gpu provides FHE operations with optional GPU acceleration.
// When CGO is disabled, this package delegates to the pure Go fhe package.
package gpu

import (
	"errors"
	"fmt"
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

// Free releases ciphertext resources (no-op in pure Go)
func (ct *Ciphertext) Free() {
	ct.ct = nil
}

// Clone creates a copy of the ciphertext
func (ct *Ciphertext) Clone() (*Ciphertext, error) {
	return &Ciphertext{
		ct:  ct.ct,
		ctx: ct.ctx,
	}, nil
}

// Integer wraps encrypted integer bits
type Integer struct {
	bits   []*fhe.Ciphertext
	ctx    *Context
	bitLen int
}

// Free releases integer resources
func (i *Integer) Free() {
	i.bits = nil
}

// BitLen returns the number of bits in the integer
func (i *Integer) BitLen() int {
	return i.bitLen
}

// Clone creates a copy of the integer
func (i *Integer) Clone() (*Integer, error) {
	newBits := make([]*fhe.Ciphertext, len(i.bits))
	copy(newBits, i.bits)
	return &Integer{
		bits:   newBits,
		ctx:    i.ctx,
		bitLen: i.bitLen,
	}, nil
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

// ErrNoBootstrapKey is returned when operations are attempted without a bootstrap key
var ErrNoBootstrapKey = errors.New("bootstrap key not generated - call GenerateBootstrapKey first")

// Lowercase aliases for gate operations (for API compatibility)

// And is an alias for AND
func (c *Context) And(a, b *Ciphertext) (*Ciphertext, error) { return c.AND(a, b) }

// Or is an alias for OR
func (c *Context) Or(a, b *Ciphertext) (*Ciphertext, error) { return c.OR(a, b) }

// Xor is an alias for XOR
func (c *Context) Xor(a, b *Ciphertext) (*Ciphertext, error) { return c.XOR(a, b) }

// Not is an alias for NOT
func (c *Context) Not(a *Ciphertext) (*Ciphertext, error) { return c.NOT(a) }

// Nand is an alias for NAND
func (c *Context) Nand(a, b *Ciphertext) (*Ciphertext, error) { return c.NAND(a, b) }

// Nor performs homomorphic NOR on two ciphertexts
func (c *Context) Nor(a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.NOR(a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// Mux performs homomorphic multiplexer: sel ? a : b
func (c *Context) Mux(sel, a, b *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result, err := c.evaluator.MUX(sel.ct, a.ct, b.ct)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{ct: result, ctx: c}, nil
}

// Integer encryption and operations

// EncryptInteger encrypts an integer value
func (c *Context) EncryptInteger(sk *SecretKey, value int64, bitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if sk.key == nil {
		return nil, errors.New("secret key is nil")
	}

	enc := fhe.NewEncryptor(c.params, sk.key)
	bits := make([]*fhe.Ciphertext, bitLen)
	for i := 0; i < bitLen; i++ {
		bit := int((value >> i) & 1)
		bits[i] = enc.EncryptBit(bit)
	}

	return &Integer{
		bits:   bits,
		ctx:    c,
		bitLen: bitLen,
	}, nil
}

// DecryptInteger decrypts an encrypted integer
func (c *Context) DecryptInteger(sk *SecretKey, ct *Integer) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if sk.key == nil {
		return 0, errors.New("secret key is nil")
	}

	dec := fhe.NewDecryptor(c.params, sk.key)
	var value int64
	for i := 0; i < ct.bitLen; i++ {
		bit := dec.DecryptBit(ct.bits[i])
		if bit == 1 {
			value |= 1 << i
		}
	}

	return value, nil
}

// Add performs homomorphic addition of two integers
func (c *Context) Add(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	// Ripple-carry adder
	result := make([]*fhe.Ciphertext, a.bitLen)
	var carry *fhe.Ciphertext

	for i := 0; i < a.bitLen; i++ {
		// Sum = a XOR b XOR carry
		sum, err := c.evaluator.XOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}

		if carry != nil {
			sum, err = c.evaluator.XOR(sum, carry)
			if err != nil {
				return nil, err
			}
		}
		result[i] = sum

		// Carry = (a AND b) OR (carry AND (a XOR b))
		ab, err := c.evaluator.AND(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}

		if carry != nil {
			axorb, err := c.evaluator.XOR(a.bits[i], b.bits[i])
			if err != nil {
				return nil, err
			}
			carryAndXor, err := c.evaluator.AND(carry, axorb)
			if err != nil {
				return nil, err
			}
			carry, err = c.evaluator.OR(ab, carryAndXor)
			if err != nil {
				return nil, err
			}
		} else {
			carry = ab
		}
	}

	return &Integer{
		bits:   result,
		ctx:    c,
		bitLen: a.bitLen,
	}, nil
}

// Sub performs homomorphic subtraction of two integers
func (c *Context) Sub(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	// Two's complement subtraction: a - b = a + NOT(b) + 1
	// Implemented as ripple-borrow subtractor
	result := make([]*fhe.Ciphertext, a.bitLen)
	var borrow *fhe.Ciphertext

	for i := 0; i < a.bitLen; i++ {
		// diff = a XOR b XOR borrow
		diff, err := c.evaluator.XOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}

		if borrow != nil {
			diff, err = c.evaluator.XOR(diff, borrow)
			if err != nil {
				return nil, err
			}
		}
		result[i] = diff

		// borrow = (NOT a AND b) OR (borrow AND NOT(a XOR b))
		notA := c.evaluator.NOT(a.bits[i])
		notAandB, err := c.evaluator.AND(notA, b.bits[i])
		if err != nil {
			return nil, err
		}

		if borrow != nil {
			axorb, err := c.evaluator.XOR(a.bits[i], b.bits[i])
			if err != nil {
				return nil, err
			}
			notAxorb := c.evaluator.NOT(axorb)
			borrowAndNotXor, err := c.evaluator.AND(borrow, notAxorb)
			if err != nil {
				return nil, err
			}
			borrow, err = c.evaluator.OR(notAandB, borrowAndNotXor)
			if err != nil {
				return nil, err
			}
		} else {
			borrow = notAandB
		}
	}

	return &Integer{
		bits:   result,
		ctx:    c,
		bitLen: a.bitLen,
	}, nil
}

// Comparison operations

// Eq checks if a equals b (encrypted equality comparison)
func (c *Context) Eq(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	// a == b iff all bits are equal: AND of (NOT (a_i XOR b_i))
	result, err := c.evaluator.XOR(a.bits[0], b.bits[0])
	if err != nil {
		return nil, err
	}
	result = c.evaluator.NOT(result)

	for i := 1; i < a.bitLen; i++ {
		xorBit, err := c.evaluator.XOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		notXor := c.evaluator.NOT(xorBit)
		result, err = c.evaluator.AND(result, notXor)
		if err != nil {
			return nil, err
		}
	}

	return &Ciphertext{ct: result, ctx: c}, nil
}

// Ne checks if a is not equal to b
func (c *Context) Ne(a, b *Integer) (*Ciphertext, error) {
	eq, err := c.Eq(a, b)
	if err != nil {
		return nil, err
	}
	result := c.evaluator.NOT(eq.ct)
	return &Ciphertext{ct: result, ctx: c}, nil
}

// Lt checks if a < b (less than)
func (c *Context) Lt(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	// Compare from MSB to LSB
	var result *fhe.Ciphertext
	var decided *fhe.Ciphertext

	for i := a.bitLen - 1; i >= 0; i-- {
		// a < b at this bit: NOT a AND b
		notA := c.evaluator.NOT(a.bits[i])
		ltBit, err := c.evaluator.AND(notA, b.bits[i])
		if err != nil {
			return nil, err
		}

		if result == nil {
			result = ltBit
			// decided = a XOR b (bits differ)
			decided, err = c.evaluator.XOR(a.bits[i], b.bits[i])
			if err != nil {
				return nil, err
			}
		} else {
			// Update only if not yet decided
			notDecided := c.evaluator.NOT(decided)
			ltMasked, err := c.evaluator.AND(ltBit, notDecided)
			if err != nil {
				return nil, err
			}
			result, err = c.evaluator.OR(result, ltMasked)
			if err != nil {
				return nil, err
			}

			// Update decided
			bitsDiffer, err := c.evaluator.XOR(a.bits[i], b.bits[i])
			if err != nil {
				return nil, err
			}
			decidedMasked, err := c.evaluator.AND(bitsDiffer, notDecided)
			if err != nil {
				return nil, err
			}
			decided, err = c.evaluator.OR(decided, decidedMasked)
			if err != nil {
				return nil, err
			}
		}
	}

	return &Ciphertext{ct: result, ctx: c}, nil
}

// Le checks if a <= b (less than or equal)
func (c *Context) Le(a, b *Integer) (*Ciphertext, error) {
	gt, err := c.Gt(a, b)
	if err != nil {
		return nil, err
	}
	result := c.evaluator.NOT(gt.ct)
	return &Ciphertext{ct: result, ctx: c}, nil
}

// Gt checks if a > b (greater than)
func (c *Context) Gt(a, b *Integer) (*Ciphertext, error) {
	return c.Lt(b, a)
}

// Ge checks if a >= b (greater than or equal)
func (c *Context) Ge(a, b *Integer) (*Ciphertext, error) {
	lt, err := c.Lt(a, b)
	if err != nil {
		return nil, err
	}
	result := c.evaluator.NOT(lt.ct)
	return &Ciphertext{ct: result, ctx: c}, nil
}

// Bitwise operations on integers

// BitwiseAnd performs bitwise AND on two integers
func (c *Context) BitwiseAnd(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)
	for i := 0; i < a.bitLen; i++ {
		res, err := c.evaluator.AND(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = res
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// BitwiseOr performs bitwise OR on two integers
func (c *Context) BitwiseOr(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)
	for i := 0; i < a.bitLen; i++ {
		res, err := c.evaluator.OR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = res
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// BitwiseXor performs bitwise XOR on two integers
func (c *Context) BitwiseXor(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)
	for i := 0; i < a.bitLen; i++ {
		res, err := c.evaluator.XOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = res
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// Shift operations

// Shl performs left shift by n bits (requires bootstrap key for zero padding)
func (c *Context) Shl(a *Integer, n int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)

	// Fill lower n bits with trivial encryptions of zero
	// We use NOT(a AND NOT(a)) = 0 to create encrypted zeros
	for i := 0; i < n && i < a.bitLen; i++ {
		// Create a zero by XORing any bit with itself
		zeroBit, err := c.evaluator.XOR(a.bits[0], a.bits[0])
		if err != nil {
			return nil, err
		}
		// XOR(x, x) = 0, so zeroBit is encrypted zero
		result[i] = zeroBit
	}

	// Shift remaining bits
	for i := n; i < a.bitLen; i++ {
		result[i] = a.bits[i-n]
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// Shr performs right shift by n bits (requires bootstrap key for zero padding)
func (c *Context) Shr(a *Integer, n int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)

	// Shift bits right
	for i := 0; i < a.bitLen-n; i++ {
		result[i] = a.bits[i+n]
	}

	// Fill upper n bits with encrypted zeros
	for i := a.bitLen - n; i < a.bitLen; i++ {
		// Create a zero by XORing any bit with itself
		zeroBit, err := c.evaluator.XOR(a.bits[0], a.bits[0])
		if err != nil {
			return nil, err
		}
		result[i] = zeroBit
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// Min/Max operations

// Min returns the minimum of two integers
func (c *Context) Min(a, b *Integer) (*Integer, error) {
	lt, err := c.Lt(a, b)
	if err != nil {
		return nil, err
	}
	return c.Select(lt, a, b)
}

// Max returns the maximum of two integers
func (c *Context) Max(a, b *Integer) (*Integer, error) {
	gt, err := c.Gt(a, b)
	if err != nil {
		return nil, err
	}
	return c.Select(gt, a, b)
}

// Select returns a if cond is true, else b
func (c *Context) Select(cond *Ciphertext, a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)
	for i := 0; i < a.bitLen; i++ {
		res, err := c.evaluator.MUX(cond.ct, a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = res
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// CastTo changes the bit width of an integer
func (c *Context) CastTo(a *Integer, newBitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*fhe.Ciphertext, newBitLen)

	// Copy existing bits
	for i := 0; i < newBitLen && i < a.bitLen; i++ {
		result[i] = a.bits[i]
	}

	// Zero-extend if needed using XOR trick: XOR(x,x) = 0
	if newBitLen > a.bitLen && a.bitLen > 0 {
		for i := a.bitLen; i < newBitLen; i++ {
			// Create encrypted zero by XORing any bit with itself
			zeroBit, err := c.evaluator.XOR(a.bits[0], a.bits[0])
			if err != nil {
				return nil, fmt.Errorf("failed to create zero bit: %w", err)
			}
			result[i] = zeroBit
		}
	}

	return &Integer{bits: result, ctx: c, bitLen: newBitLen}, nil
}

// BitwiseNot performs bitwise NOT on an integer
func (c *Context) BitwiseNot(a *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	result := make([]*fhe.Ciphertext, a.bitLen)
	for i := 0; i < a.bitLen; i++ {
		res := c.evaluator.NOT(a.bits[i])
		result[i] = res
	}

	return &Integer{bits: result, ctx: c, bitLen: a.bitLen}, nil
}

// Neg performs arithmetic negation on an integer (two's complement: -x = ~x + 1)
func (c *Context) Neg(a *Integer) (*Integer, error) {
	if len(a.bits) == 0 {
		return nil, errors.New("cannot negate empty integer")
	}

	// First compute bitwise NOT
	notA, err := c.BitwiseNot(a)
	if err != nil {
		return nil, err
	}

	// Create encrypted one (1 in two's complement)
	// Use a.bits[0] as reference to derive zeros via XOR(x,x)
	one, err := c.encryptedOneFrom(a.bitLen, a.bits[0])
	if err != nil {
		return nil, err
	}

	// Add 1 to get two's complement negation
	return c.Add(notA, one)
}

// encryptedOneFrom creates an encrypted integer with value 1, using refBit to derive zeros
func (c *Context) encryptedOneFrom(bitLen int, refBit *fhe.Ciphertext) (*Integer, error) {
	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	bits := make([]*fhe.Ciphertext, bitLen)
	for i := 0; i < bitLen; i++ {
		if i == 0 {
			// First bit is 1 - we need NOT(0)
			// XOR(x,x) = 0, then NOT(0) = 1
			zeroBit, err := c.evaluator.XOR(refBit, refBit)
			if err != nil {
				return nil, fmt.Errorf("cannot create zero bit: %w", err)
			}
			oneBit := c.evaluator.NOT(zeroBit)
			bits[i] = oneBit
		} else {
			// Other bits are 0
			zeroBit, err := c.evaluator.XOR(refBit, refBit)
			if err != nil {
				return nil, err
			}
			bits[i] = zeroBit
		}
	}

	return &Integer{bits: bits, ctx: c, bitLen: bitLen}, nil
}

// MulScalar multiplies an integer by a scalar constant
func (c *Context) MulScalar(a *Integer, scalar int64) (*Integer, error) {
	if len(a.bits) == 0 {
		return nil, errors.New("cannot multiply empty integer")
	}

	if scalar == 0 {
		// Return encrypted zero
		return c.encryptedZeroFrom(a.bitLen, a.bits[0])
	}
	if scalar == 1 {
		// Return a copy of a
		return c.CastTo(a, a.bitLen)
	}
	if scalar == -1 {
		return c.Neg(a)
	}

	// For other scalars, use addition-based multiplication
	// This is expensive but correct for TFHE
	isNeg := scalar < 0
	if isNeg {
		scalar = -scalar
	}

	var result *Integer
	var err error
	current := a

	for scalar > 0 {
		if scalar&1 == 1 {
			if result == nil {
				result, err = c.CastTo(current, current.bitLen)
				if err != nil {
					return nil, err
				}
			} else {
				result, err = c.Add(result, current)
				if err != nil {
					return nil, err
				}
			}
		}
		scalar >>= 1
		if scalar > 0 {
			current, err = c.Add(current, current) // current *= 2
			if err != nil {
				return nil, err
			}
		}
	}

	if isNeg && result != nil {
		return c.Neg(result)
	}

	return result, nil
}

// AddScalar adds a scalar constant to an integer
func (c *Context) AddScalar(a *Integer, scalar int64) (*Integer, error) {
	if len(a.bits) == 0 {
		return nil, errors.New("cannot add to empty integer")
	}

	if scalar == 0 {
		return c.CastTo(a, a.bitLen)
	}

	// Create encrypted scalar
	scalarEnc, err := c.encryptScalar(a.bitLen, scalar, a.bits[0])
	if err != nil {
		return nil, err
	}

	return c.Add(a, scalarEnc)
}

// SubScalar subtracts a scalar constant from an integer
func (c *Context) SubScalar(a *Integer, scalar int64) (*Integer, error) {
	return c.AddScalar(a, -scalar)
}

// encryptScalar creates an encrypted integer from a scalar constant
func (c *Context) encryptScalar(bitLen int, scalar int64, refBit *fhe.Ciphertext) (*Integer, error) {
	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	bits := make([]*fhe.Ciphertext, bitLen)
	for i := 0; i < bitLen; i++ {
		if (scalar>>i)&1 == 1 {
			// Create encrypted 1
			zeroBit, err := c.evaluator.XOR(refBit, refBit)
			if err != nil {
				return nil, err
			}
			bits[i] = c.evaluator.NOT(zeroBit)
		} else {
			// Create encrypted 0
			zeroBit, err := c.evaluator.XOR(refBit, refBit)
			if err != nil {
				return nil, err
			}
			bits[i] = zeroBit
		}
	}

	return &Integer{bits: bits, ctx: c, bitLen: bitLen}, nil
}

// encryptedZeroFrom creates an encrypted integer with value 0, using refBit to derive zeros
func (c *Context) encryptedZeroFrom(bitLen int, refBit *fhe.Ciphertext) (*Integer, error) {
	if c.evaluator == nil {
		return nil, ErrNoBootstrapKey
	}

	bits := make([]*fhe.Ciphertext, bitLen)
	for i := 0; i < bitLen; i++ {
		zeroBit, err := c.evaluator.XOR(refBit, refBit)
		if err != nil {
			return nil, err
		}
		bits[i] = zeroBit
	}

	return &Integer{bits: bits, ctx: c, bitLen: bitLen}, nil
}

// Public key encryption

// ErrPublicKeyEncryptionNotSupported is returned when public key encryption is attempted
var ErrPublicKeyEncryptionNotSupported = errors.New("public key encryption not supported - use secret key encryption instead")

// EncryptBitPublic encrypts a bit using the public key
// Note: TFHE doesn't support traditional public key encryption. Use EncryptBit with secret key.
func (c *Context) EncryptBitPublic(pk *PublicKey, value bool) (*Ciphertext, error) {
	// TFHE uses secret key encryption. "Public key" in TFHE context refers to
	// the bootstrap key which is used for homomorphic operations, not encryption.
	// For now, we return an error as this isn't properly supported.
	return nil, ErrPublicKeyEncryptionNotSupported
}

// EncryptIntegerPublic encrypts an integer using the public key
// Note: TFHE doesn't support traditional public key encryption. Use EncryptInteger with secret key.
func (c *Context) EncryptIntegerPublic(pk *PublicKey, value int64, bitLen int) (*Integer, error) {
	// TFHE uses secret key encryption. "Public key" in TFHE context refers to
	// the bootstrap key which is used for homomorphic operations, not encryption.
	return nil, ErrPublicKeyEncryptionNotSupported
}

// Serialization

// SerializeCiphertext serializes a ciphertext to bytes
func (c *Context) SerializeCiphertext(ct *Ciphertext) ([]byte, error) {
	if ct.ct == nil {
		return nil, errors.New("ciphertext is nil")
	}
	return ct.ct.MarshalBinary()
}

// DeserializeCiphertext deserializes bytes to a ciphertext
func (c *Context) DeserializeCiphertext(data []byte) (*Ciphertext, error) {
	ct := &fhe.Ciphertext{}
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &Ciphertext{ct: ct, ctx: c}, nil
}

// SerializeInteger serializes an integer to bytes
func (c *Context) SerializeInteger(ct *Integer) ([]byte, error) {
	var result []byte
	for _, bit := range ct.bits {
		data, err := bit.MarshalBinary()
		if err != nil {
			return nil, err
		}
		// Prepend length
		lenBytes := make([]byte, 4)
		lenBytes[0] = byte(len(data))
		lenBytes[1] = byte(len(data) >> 8)
		lenBytes[2] = byte(len(data) >> 16)
		lenBytes[3] = byte(len(data) >> 24)
		result = append(result, lenBytes...)
		result = append(result, data...)
	}
	return result, nil
}

// DeserializeInteger deserializes bytes to an integer
func (c *Context) DeserializeInteger(data []byte, bitLen int) (*Integer, error) {
	bits := make([]*fhe.Ciphertext, bitLen)
	offset := 0
	for i := 0; i < bitLen; i++ {
		if offset+4 > len(data) {
			return nil, errors.New("invalid data length")
		}
		length := int(data[offset]) | int(data[offset+1])<<8 | int(data[offset+2])<<16 | int(data[offset+3])<<24
		offset += 4
		if offset+length > len(data) {
			return nil, errors.New("invalid data length")
		}
		ct := &fhe.Ciphertext{}
		if err := ct.UnmarshalBinary(data[offset : offset+length]); err != nil {
			return nil, err
		}
		bits[i] = ct
		offset += length
	}
	return &Integer{bits: bits, ctx: c, bitLen: bitLen}, nil
}

// SerializeSecretKey serializes a secret key
func (c *Context) SerializeSecretKey(sk *SecretKey) ([]byte, error) {
	if sk.key == nil {
		return nil, errors.New("secret key is nil")
	}
	return sk.key.MarshalBinary()
}

// DeserializeSecretKey deserializes bytes to a secret key
func (c *Context) DeserializeSecretKey(data []byte) (*SecretKey, error) {
	sk := &fhe.SecretKey{}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &SecretKey{key: sk, ctx: c}, nil
}

// SerializePublicKey serializes a public key (bootstrap key)
// Note: In TFHE, this serializes the bootstrap key which is used for homomorphic operations
func (c *Context) SerializePublicKey(pk *PublicKey) ([]byte, error) {
	if pk.bsk == nil {
		return nil, errors.New("public key is nil")
	}
	return pk.bsk.MarshalBinary()
}

// DeserializePublicKey deserializes bytes to a public key (bootstrap key)
func (c *Context) DeserializePublicKey(data []byte) (*PublicKey, error) {
	bsk := &fhe.BootstrapKey{}
	if err := bsk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &PublicKey{bsk: bsk, ctx: c}, nil
}
