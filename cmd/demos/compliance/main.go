// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command compliance demonstrates programmable compliance checks on encrypted portfolios.
//
// A portfolio of positions is encrypted. The system verifies SEC diversification
// rules (no single position > 25% of total, total exposure < 80%) entirely on
// encrypted data using boolean circuit comparisons. Only the boolean results are
// decrypted.
//
// Usage:
//
//	go run ./cmd/demos/compliance serve
package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/fhe"
)

const valueBits = 8

type encPosition struct {
	Name      string
	EncWeight [8]*fhe.Ciphertext
}

type fheState struct {
	mu        sync.Mutex
	enc       *fhe.Encryptor
	dec       *fhe.Decryptor
	eval      *fhe.Evaluator
	portfolio []encPosition
	result    *complianceResult
}

type complianceResult struct {
	Diversification bool `json:"diversification"`
	ExposureUnder80 bool `json:"exposure_under_80"`
	Overall         bool `json:"overall"`
}

func main() {
	app := base.New()

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		st, err := initFHE()
		if err != nil {
			return fmt.Errorf("fhe init: %w", err)
		}
		registerRoutes(se, st)
		return se.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

func initFHE() (*fheState, error) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return nil, err
	}
	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	return &fheState{
		enc:  fhe.NewEncryptor(params, sk),
		dec:  fhe.NewDecryptor(params, sk),
		eval: fhe.NewEvaluator(params, bsk),
	}, nil
}

func registerRoutes(se *core.ServeEvent, st *fheState) {
	g := se.Router.Group("/v1")

	// POST /v1/portfolio — submit encrypted holdings
	g.POST("/portfolio", func(re *core.RequestEvent) error {
		var req struct {
			Positions []struct {
				Name   string `json:"name"`
				Weight uint8  `json:"weight"`
			} `json:"positions"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}
		if len(req.Positions) == 0 {
			return re.JSON(400, map[string]string{"error": "positions required"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		st.portfolio = nil
		st.result = nil
		for _, p := range req.Positions {
			st.portfolio = append(st.portfolio, encPosition{
				Name:      p.Name,
				EncWeight: encryptByte(st.enc, p.Weight),
			})
		}

		return re.JSON(201, map[string]any{
			"count":   len(st.portfolio),
			"message": "portfolio encrypted",
		})
	})

	// POST /v1/check — run SEC diversification check homomorphically
	g.POST("/check", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.portfolio) == 0 {
			return re.JSON(400, map[string]string{"error": "no portfolio loaded"})
		}

		// Check 1: no single position > 25%
		encThreshold := encryptByte(st.enc, 25)
		allCompliant := st.enc.Encrypt(true)
		for _, p := range st.portfolio {
			leResult, err := leEncrypted(st.eval, p.EncWeight, encThreshold)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
			allCompliant, err = st.eval.AND(allCompliant, leResult)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
		}
		check1 := st.dec.Decrypt(allCompliant)

		// Check 2: total exposure < 80%
		encTotal := st.portfolio[0].EncWeight
		var err error
		for i := 1; i < len(st.portfolio); i++ {
			encTotal, err = addBytes(st.eval, st.enc, encTotal, st.portfolio[i].EncWeight)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
		}
		encMaxExposure := encryptByte(st.enc, 80)
		ltResult, err := ltEncrypted(st.eval, encTotal, encMaxExposure)
		if err != nil {
			return re.JSON(500, map[string]string{"error": err.Error()})
		}
		check2 := st.dec.Decrypt(ltResult)

		st.result = &complianceResult{
			Diversification: check1,
			ExposureUnder80: check2,
			Overall:         check1 && check2,
		}

		return re.JSON(200, st.result)
	})

	// GET /v1/result — get compliance result (boolean, not holdings)
	g.GET("/result", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.result == nil {
			return re.JSON(404, map[string]string{"error": "no check run yet"})
		}

		return re.JSON(200, st.result)
	})
}

func encryptByte(enc *fhe.Encryptor, v uint8) [8]*fhe.Ciphertext {
	var bits [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		bits[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return bits
}

func addBytes(eval *fhe.Evaluator, enc *fhe.Encryptor, a, b [8]*fhe.Ciphertext) ([8]*fhe.Ciphertext, error) {
	carry := enc.Encrypt(false)
	var result [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		abXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return result, err
		}
		sum, err := eval.XOR(abXor, carry)
		if err != nil {
			return result, err
		}
		carry, err = eval.MAJORITY(a[i], b[i], carry)
		if err != nil {
			return result, err
		}
		result[i] = sum
	}
	return result, nil
}

func ltEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := valueBits - 1; i >= 0; i-- {
		bitLt, err := eval.ANDNY(a[i], b[i])
		if err != nil {
			return nil, err
		}
		bitXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, err
		}
		bitEq := eval.NOT(bitXor)
		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
		} else {
			eqAndLt, err := eval.AND(isEqual, bitLt)
			if err != nil {
				return nil, err
			}
			isLess, err = eval.OR(isLess, eqAndLt)
			if err != nil {
				return nil, err
			}
			isEqual, err = eval.AND(isEqual, bitEq)
			if err != nil {
				return nil, err
			}
		}
	}
	return isLess, nil
}

func leEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	bLtA, err := ltEncrypted(eval, b, a)
	if err != nil {
		return nil, err
	}
	return eval.NOT(bLtA), nil
}
