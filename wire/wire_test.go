// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/math/codec"
)

func encodeUvarint(out *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		out.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	out.WriteByte(byte(v))
}

func TestValidateCiphertextFrame_RejectsHugeLength(t *testing.T) {
	const huge = uint64(70_368_955_777_453)
	var buf bytes.Buffer
	encodeUvarint(&buf, huge)
	err := ValidateCiphertextFrame(buf.Bytes())
	if err == nil {
		t.Fatal("ValidateCiphertextFrame returned nil for huge length")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}

func TestValidateCiphertextFrame_OverCap(t *testing.T) {
	var buf bytes.Buffer
	encodeUvarint(&buf, uint64(MaxFHESliceLen+1))
	err := ValidateCiphertextFrame(buf.Bytes())
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}
