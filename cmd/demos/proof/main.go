//go:build demos

// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command proof demonstrates compliance proofs on encrypted portfolios using FHE.
//
// A portfolio is encrypted. The system proves two compliance conditions:
//   - No single position exceeds 25% of total
//   - No position matches a sanctioned counterparty ID
//
// Only the boolean proof results are decrypted. Portfolio data stays encrypted.
//
// Usage:
//
//	go run ./cmd/demos/proof serve
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
	EncEntity [8]*fhe.Ciphertext
}

type proofResult struct {
	Diversification bool `json:"diversification"`
	Sanctions       bool `json:"sanctions"`
	Overall         bool `json:"overall"`
}

type fheState struct {
	mu            sync.Mutex
	enc           *fhe.Encryptor
	dec           *fhe.Decryptor
	eval          *fhe.Evaluator
	portfolio     []encPosition
	sanctionedIDs []uint8
	result        *proofResult
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

	// POST /v1/positions — submit encrypted positions
	g.POST("/positions", func(re *core.RequestEvent) error {
		var req struct {
			SanctionedIDs []uint8 `json:"sanctioned_ids"`
			Positions     []struct {
				Name     string `json:"name"`
				Weight   uint8  `json:"weight"`
				EntityID uint8  `json:"entity_id"`
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
		st.sanctionedIDs = req.SanctionedIDs

		for _, p := range req.Positions {
			st.portfolio = append(st.portfolio, encPosition{
				Name:      p.Name,
				EncWeight: encryptByte(st.enc, p.Weight),
				EncEntity: encryptByte(st.enc, p.EntityID),
			})
		}

		return re.JSON(201, map[string]any{
			"count":         len(st.portfolio),
			"sanctioned":    len(st.sanctionedIDs),
			"message":       "portfolio encrypted",
		})
	})

	// POST /v1/prove — generate compliance proof (boolean output)
	g.POST("/prove", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.portfolio) == 0 {
			return re.JSON(400, map[string]string{"error": "no portfolio loaded"})
		}

		// Proof 1: no position > 25%
		encThreshold := encryptByte(st.enc, 25)
		allUnder := st.enc.Encrypt(true)
		for _, p := range st.portfolio {
			threshLtWeight, err := ltEncrypted(st.eval, encThreshold, p.EncWeight)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
			withinLimit := st.eval.NOT(threshLtWeight)
			allUnder, err = st.eval.AND(allUnder, withinLimit)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
		}
		diversificationOk := st.dec.Decrypt(allUnder)

		// Proof 2: no sanctioned counterparty
		noSanctioned := st.enc.Encrypt(true)
		for _, sid := range st.sanctionedIDs {
			encSanctioned := encryptByte(st.enc, sid)
			for _, p := range st.portfolio {
				isEqual := st.enc.Encrypt(true)
				for bit := 0; bit < valueBits; bit++ {
					bitXor, err := st.eval.XOR(p.EncEntity[bit], encSanctioned[bit])
					if err != nil {
						return re.JSON(500, map[string]string{"error": err.Error()})
					}
					bitsMatch := st.eval.NOT(bitXor)
					isEqual, err = st.eval.AND(isEqual, bitsMatch)
					if err != nil {
						return re.JSON(500, map[string]string{"error": err.Error()})
					}
				}
				notEqual := st.eval.NOT(isEqual)
				var err error
				noSanctioned, err = st.eval.AND(noSanctioned, notEqual)
				if err != nil {
					return re.JSON(500, map[string]string{"error": err.Error()})
				}
			}
		}
		sanctionsOk := st.dec.Decrypt(noSanctioned)

		st.result = &proofResult{
			Diversification: diversificationOk,
			Sanctions:       sanctionsOk,
			Overall:         diversificationOk && sanctionsOk,
		}

		return re.JSON(200, map[string]string{
			"message": "proof generated, call GET /v1/proof to see result",
		})
	})

	// GET /v1/proof — get proof result
	g.GET("/proof", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.result == nil {
			return re.JSON(404, map[string]string{"error": "no proof generated yet"})
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
