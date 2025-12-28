// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/luxfi/lattice/v6/core/rlwe"
	"github.com/luxfi/lattice/v6/ring"
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

// MarshalBinary serializes the bootstrap key to binary format
func (bsk *BootstrapKey) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Serialize BRK using gob
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(bsk.BRK); err != nil {
		return nil, fmt.Errorf("serialize BRK: %w", err)
	}

	// Serialize test polynomials
	if err := serializePoly(&buf, bsk.TestPolyAND); err != nil {
		return nil, fmt.Errorf("serialize TestPolyAND: %w", err)
	}
	if err := serializePoly(&buf, bsk.TestPolyOR); err != nil {
		return nil, fmt.Errorf("serialize TestPolyOR: %w", err)
	}
	if err := serializePoly(&buf, bsk.TestPolyNAND); err != nil {
		return nil, fmt.Errorf("serialize TestPolyNAND: %w", err)
	}
	if err := serializePoly(&buf, bsk.TestPolyNOR); err != nil {
		return nil, fmt.Errorf("serialize TestPolyNOR: %w", err)
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes the bootstrap key from binary format
func (bsk *BootstrapKey) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Deserialize BRK
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&bsk.BRK); err != nil {
		return fmt.Errorf("deserialize BRK: %w", err)
	}

	// Deserialize test polynomials
	var err error
	bsk.TestPolyAND, err = deserializePoly(buf)
	if err != nil {
		return fmt.Errorf("deserialize TestPolyAND: %w", err)
	}
	bsk.TestPolyOR, err = deserializePoly(buf)
	if err != nil {
		return fmt.Errorf("deserialize TestPolyOR: %w", err)
	}
	bsk.TestPolyNAND, err = deserializePoly(buf)
	if err != nil {
		return fmt.Errorf("deserialize TestPolyNAND: %w", err)
	}
	bsk.TestPolyNOR, err = deserializePoly(buf)
	if err != nil {
		return fmt.Errorf("deserialize TestPolyNOR: %w", err)
	}

	return nil
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
