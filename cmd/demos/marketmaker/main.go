//go:build demos

// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command marketmaker demonstrates private market making with FHE.
//
// Market makers submit encrypted bid/ask quotes. The system selects the best
// bid (highest) and best ask (lowest) via boolean circuit comparisons.
// Only the winning quotes are decrypted -- losing quotes stay private.
//
// Usage:
//
//	go run ./cmd/demos/marketmaker serve
package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/uuid"
	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/fhe"
)

const priceBits = 8

type encQuote struct {
	ID     string
	Maker  string
	EncBid [8]*fhe.Ciphertext
	EncAsk [8]*fhe.Ciphertext
}

type spreadResult struct {
	BestBidMaker string `json:"best_bid_maker"`
	BestBidPrice uint8  `json:"best_bid_price"`
	BestAskMaker string `json:"best_ask_maker"`
	BestAskPrice uint8  `json:"best_ask_price"`
	Spread       int    `json:"spread"`
}

type fheState struct {
	mu     sync.Mutex
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator
	quotes []encQuote
	spread *spreadResult
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

	// POST /v1/quotes — submit encrypted quote
	g.POST("/quotes", func(re *core.RequestEvent) error {
		var req struct {
			Maker string `json:"maker"`
			Bid   uint8  `json:"bid"`
			Ask   uint8  `json:"ask"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}
		if req.Maker == "" {
			return re.JSON(400, map[string]string{"error": "maker required"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		q := encQuote{
			ID:     uuid.NewString(),
			Maker:  req.Maker,
			EncBid: encryptByte(st.enc, req.Bid),
			EncAsk: encryptByte(st.enc, req.Ask),
		}
		st.quotes = append(st.quotes, q)
		st.spread = nil // invalidate cached spread

		return re.JSON(201, map[string]string{"id": q.ID, "maker": q.Maker})
	})

	// POST /v1/best — compute best bid/ask homomorphically
	g.POST("/best", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.quotes) < 2 {
			return re.JSON(400, map[string]string{"error": "need at least 2 quotes"})
		}

		// Best bid (highest)
		bestBidIdx := 0
		for i := 1; i < len(st.quotes); i++ {
			gtResult, err := gtEncrypted(st.eval, st.quotes[i].EncBid, st.quotes[bestBidIdx].EncBid)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
			if st.dec.Decrypt(gtResult) {
				bestBidIdx = i
			}
		}

		// Best ask (lowest)
		bestAskIdx := 0
		for i := 1; i < len(st.quotes); i++ {
			ltResult, err := ltEncrypted(st.eval, st.quotes[i].EncAsk, st.quotes[bestAskIdx].EncAsk)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
			if st.dec.Decrypt(ltResult) {
				bestAskIdx = i
			}
		}

		bestBid := decryptByte(st.dec, st.quotes[bestBidIdx].EncBid)
		bestAsk := decryptByte(st.dec, st.quotes[bestAskIdx].EncAsk)

		st.spread = &spreadResult{
			BestBidMaker: st.quotes[bestBidIdx].Maker,
			BestBidPrice: bestBid,
			BestAskMaker: st.quotes[bestAskIdx].Maker,
			BestAskPrice: bestAsk,
			Spread:       int(bestAsk) - int(bestBid),
		}

		return re.JSON(200, st.spread)
	})

	// GET /v1/spread — get cached spread
	g.GET("/spread", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.spread == nil {
			return re.JSON(404, map[string]string{"error": "no spread computed yet"})
		}

		return re.JSON(200, st.spread)
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

func ltEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := priceBits - 1; i >= 0; i-- {
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

func gtEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return ltEncrypted(eval, b, a)
}
