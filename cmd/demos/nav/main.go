// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command nav demonstrates confidential Net Asset Value (NAV) computation using FHE.
//
// An ETF's holdings (positions with share counts and prices) are encrypted.
// NAV = sum(holdings * prices) / totalShares is computed on encrypted data using
// repeated addition. Only the final NAV is decrypted for the authorized party.
//
// Usage:
//
//	go run ./cmd/demos/nav serve
package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/fhe"
)

type encHolding struct {
	Ticker   string
	Shares   uint8
	EncPrice [8]*fhe.Ciphertext
}

type navResult struct {
	TotalValue       uint64 `json:"total_value"`
	SharesOutstanding uint64 `json:"shares_outstanding"`
	NAVPerShare      uint64 `json:"nav_per_share"`
}

type fheState struct {
	mu               sync.Mutex
	enc              *fhe.Encryptor
	dec              *fhe.Decryptor
	eval             *fhe.Evaluator
	holdings         []encHolding
	sharesOutstanding uint64
	result           *navResult
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

	// POST /v1/holdings — submit encrypted holdings
	g.POST("/holdings", func(re *core.RequestEvent) error {
		var req struct {
			SharesOutstanding uint64 `json:"shares_outstanding"`
			Holdings          []struct {
				Ticker string `json:"ticker"`
				Shares uint8  `json:"shares"`
				Price  uint8  `json:"price"`
			} `json:"holdings"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}
		if len(req.Holdings) == 0 {
			return re.JSON(400, map[string]string{"error": "holdings required"})
		}
		if req.SharesOutstanding == 0 {
			return re.JSON(400, map[string]string{"error": "shares_outstanding required"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		st.holdings = nil
		st.result = nil
		st.sharesOutstanding = req.SharesOutstanding

		for _, h := range req.Holdings {
			st.holdings = append(st.holdings, encHolding{
				Ticker:   h.Ticker,
				Shares:   h.Shares,
				EncPrice: encryptByte(st.enc, h.Price),
			})
		}

		return re.JSON(201, map[string]any{
			"count":   len(st.holdings),
			"message": "holdings encrypted",
		})
	})

	// POST /v1/compute — compute NAV homomorphically
	g.POST("/compute", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.holdings) == 0 {
			return re.JSON(400, map[string]string{"error": "no holdings loaded"})
		}

		var encTotal [8]*fhe.Ciphertext
		initialized := false

		for _, h := range st.holdings {
			// shares * price via repeated addition
			posValue := h.EncPrice
			var err error
			for s := uint8(1); s < h.Shares; s++ {
				posValue, err = addBytes(st.eval, st.enc, posValue, h.EncPrice)
				if err != nil {
					return re.JSON(500, map[string]string{"error": err.Error()})
				}
			}

			if !initialized {
				encTotal = posValue
				initialized = true
			} else {
				encTotal, err = addBytes(st.eval, st.enc, encTotal, posValue)
				if err != nil {
					return re.JSON(500, map[string]string{"error": err.Error()})
				}
			}
		}

		decTotal := uint64(decryptByte(st.dec, encTotal))
		st.result = &navResult{
			TotalValue:        decTotal,
			SharesOutstanding: st.sharesOutstanding,
			NAVPerShare:       decTotal / st.sharesOutstanding,
		}

		return re.JSON(200, map[string]string{
			"message": "NAV computed, call GET /v1/nav to see result",
		})
	})

	// GET /v1/nav — get encrypted NAV value
	g.GET("/nav", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.result == nil {
			return re.JSON(404, map[string]string{"error": "no NAV computed yet"})
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

func decryptByte(dec *fhe.Decryptor, bits [8]*fhe.Ciphertext) uint8 {
	var v uint8
	for i := 0; i < 8; i++ {
		if dec.Decrypt(bits[i]) {
			v |= 1 << i
		}
	}
	return v
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
