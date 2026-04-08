// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command darkpool demonstrates an encrypted dark pool order matching system.
//
// Traders submit encrypted limit orders (price + quantity). The matching engine
// compares encrypted bids against encrypted asks using FHE boolean circuits.
// Only matched fills are decrypted -- unmatched orders remain private.
//
// Usage:
//
//	go run ./cmd/demos/darkpool serve
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

type encOrder struct {
	ID       string
	Side     string // "bid" or "ask"
	EncPrice [8]*fhe.Ciphertext
	EncQty   [8]*fhe.Ciphertext
}

type matchResult struct {
	BidID string `json:"bid_id"`
	AskID string `json:"ask_id"`
}

type fheState struct {
	mu      sync.Mutex
	params  fhe.Parameters
	enc     *fhe.Encryptor
	dec     *fhe.Decryptor
	eval    *fhe.Evaluator
	orders  map[string]*encOrder
	matches []matchResult
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
		params:  params,
		enc:     fhe.NewEncryptor(params, sk),
		dec:     fhe.NewDecryptor(params, sk),
		eval:    fhe.NewEvaluator(params, bsk),
		orders:  make(map[string]*encOrder),
		matches: nil,
	}, nil
}

func registerRoutes(se *core.ServeEvent, st *fheState) {
	g := se.Router.Group("/v1")

	// POST /v1/orders — submit encrypted order
	g.POST("/orders", func(re *core.RequestEvent) error {
		var req struct {
			Side  string `json:"side"`
			Price uint8  `json:"price"`
			Qty   uint8  `json:"qty"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}
		if req.Side != "bid" && req.Side != "ask" {
			return re.JSON(400, map[string]string{"error": "side must be bid or ask"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		id := uuid.NewString()
		o := &encOrder{
			ID:       id,
			Side:     req.Side,
			EncPrice: encryptByte(st.enc, req.Price),
			EncQty:   encryptByte(st.enc, req.Qty),
		}
		st.orders[id] = o

		return re.JSON(201, map[string]string{"id": id, "side": req.Side})
	})

	// GET /v1/orders — list orders (IDs + side only, values encrypted)
	g.GET("/orders", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		type entry struct {
			ID       string `json:"id"`
			Side     string `json:"side"`
			EncPrice string `json:"enc_price"`
		}
		var out []entry
		for _, o := range st.orders {
			out = append(out, entry{
				ID:       o.ID,
				Side:     o.Side,
				EncPrice: "(encrypted)",
			})
		}
		return re.JSON(200, out)
	})

	// POST /v1/match — run homomorphic matching on all encrypted orders
	g.POST("/match", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		var bids, asks []*encOrder
		for _, o := range st.orders {
			if o.Side == "bid" {
				bids = append(bids, o)
			} else {
				asks = append(asks, o)
			}
		}

		st.matches = nil
		for _, bid := range bids {
			for _, ask := range asks {
				isGe, err := geEncrypted(st.eval, bid.EncPrice, ask.EncPrice)
				if err != nil {
					return re.JSON(500, map[string]string{"error": err.Error()})
				}
				if st.dec.Decrypt(isGe) {
					st.matches = append(st.matches, matchResult{
						BidID: bid.ID,
						AskID: ask.ID,
					})
				}
			}
		}

		return re.JSON(200, map[string]any{
			"matches": st.matches,
			"count":   len(st.matches),
		})
	})

	// POST /v1/reveal/{id} — decrypt an order by ID
	g.POST("/reveal/{id}", func(re *core.RequestEvent) error {
		id := re.Request.PathValue("id")

		st.mu.Lock()
		defer st.mu.Unlock()

		o, ok := st.orders[id]
		if !ok {
			return re.JSON(404, map[string]string{"error": "order not found"})
		}

		price := decryptByte(st.dec, o.EncPrice)
		qty := decryptByte(st.dec, o.EncQty)

		return re.JSON(200, map[string]any{
			"id":    o.ID,
			"side":  o.Side,
			"price": price,
			"qty":   qty,
		})
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

// geEncrypted computes a >= b on encrypted 8-bit values using MSB-first comparison.
func geEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext

	for i := priceBits - 1; i >= 0; i-- {
		bitLt, err := eval.ANDNY(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d ANDNY: %w", i, err)
		}
		bitXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d XOR: %w", i, err)
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

	return eval.NOT(isLess), nil
}
