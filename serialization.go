// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/luxfi/lattice/v7/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/ring"
)

// ========== Secret Key Serialization ==========

// MarshalBinary serializes the secret key to binary format
func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Serialize SKLWE
	if err := serializeSecretKey(&buf, sk.SKLWE); err != nil {
		return nil, fmt.Errorf("serialize SKLWE: %w", err)
	}

	// Serialize SKBR
	if err := serializeSecretKey(&buf, sk.SKBR); err != nil {
		return nil, fmt.Errorf("serialize SKBR: %w", err)
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the secret key from binary format
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Deserialize SKLWE
	sklwe, err := deserializeSecretKey(buf)
	if err != nil {
		return fmt.Errorf("deserialize SKLWE: %w", err)
	}
	sk.SKLWE = sklwe

	// Deserialize SKBR
	skbr, err := deserializeSecretKey(buf)
	if err != nil {
		return fmt.Errorf("deserialize SKBR: %w", err)
	}
	sk.SKBR = skbr

	return nil
}

func serializeSecretKey(w io.Writer, sk *rlwe.SecretKey) error {
	enc := gob.NewEncoder(w)
	return enc.Encode(sk)
}

func deserializeSecretKey(r io.Reader) (*rlwe.SecretKey, error) {
	dec := gob.NewDecoder(r)
	var sk rlwe.SecretKey
	if err := dec.Decode(&sk); err != nil {
		return nil, err
	}
	return &sk, nil
}

// ========== Public Key Serialization ==========

// MarshalBinary serializes the public key to binary format
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Serialize PKLWE using gob
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(pk.PKLWE); err != nil {
		return nil, fmt.Errorf("serialize PKLWE: %w", err)
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the public key from binary format
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	dec := gob.NewDecoder(buf)
	var pklwe rlwe.PublicKey
	if err := dec.Decode(&pklwe); err != nil {
		return fmt.Errorf("deserialize PKLWE: %w", err)
	}
	pk.PKLWE = &pklwe

	return nil
}

// ========== Bootstrap Key Serialization ==========

// BootstrapKeyData holds serializable bootstrap key data
type BootstrapKeyData struct {
	BRKData      []byte
	TestPolyAND  []byte
	TestPolyOR   []byte
	TestPolyNAND []byte
	TestPolyNOR  []byte
}

// bskTestPolyOrder is the canonical wire order for the bootstrap key's test
// polynomials. Marshal and Unmarshal iterate it identically so the set stays in
// lock-step; adding a gate means appending here (and never reordering).
func (bsk *BootstrapKey) bskTestPolyPtrs() []**ring.Poly {
	return []**ring.Poly{
		&bsk.TestPolyAND, &bsk.TestPolyOR, &bsk.TestPolyXOR, &bsk.TestPolyNAND,
		&bsk.TestPolyNOR, &bsk.TestPolyXNOR, &bsk.TestPolyID, &bsk.TestPolyMAJORITY,
		&bsk.TestPolyCMPCOMBINE,
	}
}

// MarshalBinary serializes the bootstrap key to binary format. It serializes
// every field required to bootstrap from the deserialized key: BRK, the
// key-switching key KSK, and all test polynomials.
func (bsk *BootstrapKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Serialize BRK as its concrete type. BRK is the
	// blindrot.BlindRotationEvaluationKeySet interface; gob cannot round-trip a
	// value encoded through an interface back into an interface field without
	// matching concrete registration. Encoding/decoding the concrete
	// MemBlindRotationEvaluationKeySet on both sides is symmetric and avoids
	// that asymmetry. GenEvaluationKeyNew always produces this concrete type.
	concreteBRK, ok := bsk.BRK.(blindrot.MemBlindRotationEvaluationKeySet)
	if !ok {
		return nil, fmt.Errorf("serialize BRK: unsupported concrete type %T", bsk.BRK)
	}
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(concreteBRK); err != nil {
		return nil, fmt.Errorf("serialize BRK: %w", err)
	}

	// Serialize KSK (key-switching key) with a presence flag. Without it the
	// deserialized key cannot perform sample extraction / bootstrapping.
	if err := serializeEvalKey(&buf, bsk.KSK); err != nil {
		return nil, fmt.Errorf("serialize KSK: %w", err)
	}

	// Serialize all test polynomials in canonical order, each with a presence
	// flag (some gates may be unset depending on how the key was generated).
	for i, p := range bsk.bskTestPolyPtrs() {
		if err := serializeOptionalPoly(&buf, *p); err != nil {
			return nil, fmt.Errorf("serialize test poly %d: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the bootstrap key from binary format.
func (bsk *BootstrapKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Deserialize BRK into the concrete type, then store it in the interface
	// field (symmetric with MarshalBinary).
	var concreteBRK blindrot.MemBlindRotationEvaluationKeySet
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&concreteBRK); err != nil {
		return fmt.Errorf("deserialize BRK: %w", err)
	}
	bsk.BRK = concreteBRK

	// Deserialize KSK.
	ksk, err := deserializeEvalKey(buf)
	if err != nil {
		return fmt.Errorf("deserialize KSK: %w", err)
	}
	bsk.KSK = ksk

	// Deserialize all test polynomials in the same canonical order.
	for i, p := range bsk.bskTestPolyPtrs() {
		poly, err := deserializeOptionalPoly(buf)
		if err != nil {
			return fmt.Errorf("deserialize test poly %d: %w", i, err)
		}
		*p = poly
	}

	return nil
}

// serializeEvalKey writes an rlwe.EvaluationKey with a presence flag and a
// length prefix, reusing the key's own MarshalBinary.
func serializeEvalKey(w io.Writer, ek *rlwe.EvaluationKey) error {
	if ek == nil {
		return binary.Write(w, binary.LittleEndian, uint8(0))
	}
	if err := binary.Write(w, binary.LittleEndian, uint8(1)); err != nil {
		return err
	}
	data, err := ek.MarshalBinary()
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// deserializeEvalKey reads an rlwe.EvaluationKey written by serializeEvalKey.
func deserializeEvalKey(r io.Reader) (*rlwe.EvaluationKey, error) {
	var present uint8
	if err := binary.Read(r, binary.LittleEndian, &present); err != nil {
		return nil, err
	}
	if present == 0 {
		return nil, nil
	}
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	ek := new(rlwe.EvaluationKey)
	if err := ek.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return ek, nil
}

// serializeOptionalPoly writes a *ring.Poly preceded by a presence flag so nil
// polynomials round-trip as nil rather than panicking in serializePoly.
func serializeOptionalPoly(w io.Writer, poly *ring.Poly) error {
	if poly == nil {
		return binary.Write(w, binary.LittleEndian, uint8(0))
	}
	if err := binary.Write(w, binary.LittleEndian, uint8(1)); err != nil {
		return err
	}
	return serializePoly(w, poly)
}

// deserializeOptionalPoly reads a *ring.Poly written by serializeOptionalPoly.
func deserializeOptionalPoly(r io.Reader) (*ring.Poly, error) {
	var present uint8
	if err := binary.Read(r, binary.LittleEndian, &present); err != nil {
		return nil, err
	}
	if present == 0 {
		return nil, nil
	}
	return deserializePoly(r)
}

func serializePoly(w io.Writer, poly *ring.Poly) error {
	// Write number of levels
	numLevels := len(poly.Coeffs)
	if err := binary.Write(w, binary.LittleEndian, uint32(numLevels)); err != nil {
		return err
	}

	for _, coeffs := range poly.Coeffs {
		// Write number of coefficients
		if err := binary.Write(w, binary.LittleEndian, uint32(len(coeffs))); err != nil {
			return err
		}
		// Write coefficients
		for _, c := range coeffs {
			if err := binary.Write(w, binary.LittleEndian, c); err != nil {
				return err
			}
		}
	}

	return nil
}

func deserializePoly(r io.Reader) (*ring.Poly, error) {
	var numLevels uint32
	if err := binary.Read(r, binary.LittleEndian, &numLevels); err != nil {
		return nil, err
	}

	coeffs := make([][]uint64, numLevels)
	for i := range coeffs {
		var numCoeffs uint32
		if err := binary.Read(r, binary.LittleEndian, &numCoeffs); err != nil {
			return nil, err
		}

		coeffs[i] = make([]uint64, numCoeffs)
		for j := range coeffs[i] {
			if err := binary.Read(r, binary.LittleEndian, &coeffs[i][j]); err != nil {
				return nil, err
			}
		}
	}

	return &ring.Poly{Coeffs: coeffs}, nil
}

// ========== Ciphertext Serialization ==========

// MarshalBinary serializes a ciphertext to binary format
func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(ct.Ciphertext); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a ciphertext from binary format
func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(data))
	ct.Ciphertext = new(rlwe.Ciphertext)
	return dec.Decode(ct.Ciphertext)
}

// ========== RadixCiphertext Serialization ==========

// radixSerializeVersion tags the RadixCiphertext wire format so the layout can
// evolve without silently misreading older blobs.
const radixSerializeVersion uint8 = 1

// MarshalBinary serializes a RadixCiphertext to binary format.
//
// Layout: version | fheType | blockBits(int32) | numBlocks(int32) | blocks...
// Each block is: msgBits(int32) | msgSpace(int32) | len(int32) | gob(rlwe.Ciphertext).
// The per-block gob payload reuses the Ciphertext wrapper so the radix format
// stays in lock-step with single-ciphertext serialization.
func (rc *RadixCiphertext) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	if err := buf.WriteByte(radixSerializeVersion); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(uint8(rc.fheType)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, int32(rc.blockBits)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, int32(len(rc.blocks))); err != nil {
		return nil, err
	}

	for i, block := range rc.blocks {
		if block == nil || block.ct == nil {
			return nil, fmt.Errorf("radix block %d: nil ciphertext", i)
		}
		if err := binary.Write(&buf, binary.LittleEndian, int32(block.msgBits)); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, binary.LittleEndian, int32(block.msgSpace)); err != nil {
			return nil, err
		}

		blockData, err := (&Ciphertext{Ciphertext: block.ct}).MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("radix block %d: %w", i, err)
		}
		if err := binary.Write(&buf, binary.LittleEndian, int32(len(blockData))); err != nil {
			return nil, err
		}
		if _, err := buf.Write(blockData); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a RadixCiphertext from binary format produced by
// MarshalBinary. numBlocks is recovered from the wire data, not assumed.
func (rc *RadixCiphertext) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	version, err := buf.ReadByte()
	if err != nil {
		return err
	}
	if version != radixSerializeVersion {
		return fmt.Errorf("radix ciphertext: unsupported version %d", version)
	}

	fheType, err := buf.ReadByte()
	if err != nil {
		return err
	}
	rc.fheType = FheUintType(fheType)

	var blockBits, numBlocks int32
	if err := binary.Read(buf, binary.LittleEndian, &blockBits); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, &numBlocks); err != nil {
		return err
	}
	if numBlocks < 0 {
		return fmt.Errorf("radix ciphertext: invalid block count %d", numBlocks)
	}
	rc.blockBits = int(blockBits)
	rc.numBlocks = int(numBlocks)

	rc.blocks = make([]*ShortInt, numBlocks)
	for i := int32(0); i < numBlocks; i++ {
		var msgBits, msgSpace, blockLen int32
		if err := binary.Read(buf, binary.LittleEndian, &msgBits); err != nil {
			return err
		}
		if err := binary.Read(buf, binary.LittleEndian, &msgSpace); err != nil {
			return err
		}
		if err := binary.Read(buf, binary.LittleEndian, &blockLen); err != nil {
			return err
		}
		if blockLen < 0 {
			return fmt.Errorf("radix block %d: invalid length %d", i, blockLen)
		}

		blockData := make([]byte, blockLen)
		if _, err := io.ReadFull(buf, blockData); err != nil {
			return err
		}

		wrapped := new(Ciphertext)
		if err := wrapped.UnmarshalBinary(blockData); err != nil {
			return fmt.Errorf("radix block %d: %w", i, err)
		}
		rc.blocks[i] = &ShortInt{
			ct:       wrapped.Ciphertext,
			msgBits:  int(msgBits),
			msgSpace: int(msgSpace),
		}
	}

	return nil
}

// ========== BitCiphertext Serialization ==========

// MarshalBinary serializes a BitCiphertext to binary format
func (bc *BitCiphertext) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write metadata
	if err := binary.Write(&buf, binary.LittleEndian, uint32(bc.numBits)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint8(bc.fheType)); err != nil {
		return nil, err
	}

	// Write each bit ciphertext
	for i, bit := range bc.bits {
		bitData, err := bit.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("bit %d: %w", i, err)
		}
		// Write length prefix
		if err := binary.Write(&buf, binary.LittleEndian, uint32(len(bitData))); err != nil {
			return nil, err
		}
		if _, err := buf.Write(bitData); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a BitCiphertext from binary format
func (bc *BitCiphertext) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Read metadata
	var numBits uint32
	if err := binary.Read(buf, binary.LittleEndian, &numBits); err != nil {
		return err
	}
	bc.numBits = int(numBits)

	var fheType uint8
	if err := binary.Read(buf, binary.LittleEndian, &fheType); err != nil {
		return err
	}
	bc.fheType = FheUintType(fheType)

	// Read each bit ciphertext
	bc.bits = make([]*Ciphertext, bc.numBits)
	for i := 0; i < bc.numBits; i++ {
		var bitLen uint32
		if err := binary.Read(buf, binary.LittleEndian, &bitLen); err != nil {
			return err
		}

		bitData := make([]byte, bitLen)
		if _, err := io.ReadFull(buf, bitData); err != nil {
			return err
		}

		bc.bits[i] = new(Ciphertext)
		if err := bc.bits[i].UnmarshalBinary(bitData); err != nil {
			return fmt.Errorf("bit %d: %w", i, err)
		}
	}

	return nil
}

// ========== Compact Serialization for Network Transfer ==========

// CompactCiphertext is a space-efficient representation for network transfer
type CompactCiphertext struct {
	Data    []byte
	NumBits int
	Type    FheUintType
}

// ToCompact converts a BitCiphertext to a compact format
func (bc *BitCiphertext) ToCompact() (*CompactCiphertext, error) {
	data, err := bc.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &CompactCiphertext{
		Data:    data,
		NumBits: bc.numBits,
		Type:    bc.fheType,
	}, nil
}

// FromCompact creates a BitCiphertext from compact format
func FromCompact(cc *CompactCiphertext) (*BitCiphertext, error) {
	bc := new(BitCiphertext)
	if err := bc.UnmarshalBinary(cc.Data); err != nil {
		return nil, err
	}
	return bc, nil
}
