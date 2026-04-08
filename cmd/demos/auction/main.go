// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command auction demonstrates an encrypted sealed-bid auction using FHE.
//
// Participants submit encrypted sealed bids. The system determines the winner
// via boolean circuit max computation. Only the winning bid is decrypted.
//
// Usage:
//
//	go run ./cmd/demos/auction serve
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

const bidBits = 8

type encBid struct {
	ID          string
	Participant string
	EncAmount   [8]*fhe.Ciphertext
}

type winnerResult struct {
	ID          string `json:"id"`
	Participant string `json:"participant"`
	Amount      uint8  `json:"amount"`
}

type fheState struct {
	mu     sync.Mutex
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator
	bids   []encBid
	winner *winnerResult
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

	// POST /v1/bids — submit sealed encrypted bid
	g.POST("/bids", func(re *core.RequestEvent) error {
		var req struct {
			Participant string `json:"participant"`
			Amount      uint8  `json:"amount"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}
		if req.Participant == "" {
			return re.JSON(400, map[string]string{"error": "participant required"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		b := encBid{
			ID:          uuid.NewString(),
			Participant: req.Participant,
			EncAmount:   encryptByte(st.enc, req.Amount),
		}
		st.bids = append(st.bids, b)
		st.winner = nil

		return re.JSON(201, map[string]string{
			"id":          b.ID,
			"participant": b.Participant,
		})
	})

	// POST /v1/determine-winner — homomorphic max comparison
	g.POST("/determine-winner", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.bids) < 2 {
			return re.JSON(400, map[string]string{"error": "need at least 2 bids"})
		}

		winnerIdx := 0
		for i := 1; i < len(st.bids); i++ {
			gtResult, err := gtEncrypted(st.eval, st.bids[i].EncAmount, st.bids[winnerIdx].EncAmount)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
			if st.dec.Decrypt(gtResult) {
				winnerIdx = i
			}
		}

		st.winner = &winnerResult{
			ID:          st.bids[winnerIdx].ID,
			Participant: st.bids[winnerIdx].Participant,
		}

		return re.JSON(200, map[string]string{
			"winner_id":   st.winner.ID,
			"participant": st.winner.Participant,
			"message":     "winner determined, call POST /v1/reveal to decrypt amount",
		})
	})

	// POST /v1/reveal — decrypt winning bid only
	g.POST("/reveal", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.winner == nil {
			return re.JSON(400, map[string]string{"error": "no winner determined yet"})
		}

		// Find the winner's encrypted bid
		for _, b := range st.bids {
			if b.ID == st.winner.ID {
				st.winner.Amount = decryptByte(st.dec, b.EncAmount)
				break
			}
		}

		return re.JSON(200, st.winner)
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
	for i := bidBits - 1; i >= 0; i-- {
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
