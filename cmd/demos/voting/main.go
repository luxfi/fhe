//go:build demos

// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command voting demonstrates private shareholder voting using FHE.
//
// Shareholders vote encrypted yes/no. Votes are tallied homomorphically
// using a ripple-carry adder on encrypted bits. Only the final count is
// decrypted -- individual votes are never revealed.
//
// Usage:
//
//	go run ./cmd/demos/voting serve
package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/fhe"
)

const tallyBits = 7 // supports up to 127 voters

type tallyResult struct {
	Yes      uint8 `json:"yes"`
	No       int   `json:"no"`
	Total    int   `json:"total"`
	Passed   bool  `json:"passed"`
	Majority int   `json:"majority_threshold"`
}

type fheState struct {
	mu      sync.Mutex
	enc     *fhe.Encryptor
	dec     *fhe.Decryptor
	eval    *fhe.Evaluator
	ballots []*fhe.Ciphertext
	result  *tallyResult
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

	// POST /v1/votes — submit encrypted vote
	g.POST("/votes", func(re *core.RequestEvent) error {
		var req struct {
			Vote bool `json:"vote"`
		}
		if err := re.BindBody(&req); err != nil {
			return re.JSON(400, map[string]string{"error": "invalid body"})
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.ballots) >= 127 {
			return re.JSON(400, map[string]string{"error": "max 127 voters"})
		}

		st.ballots = append(st.ballots, st.enc.Encrypt(req.Vote))
		st.result = nil

		return re.JSON(201, map[string]any{
			"ballot_number": len(st.ballots),
			"message":       "vote encrypted and recorded",
		})
	})

	// POST /v1/tally — homomorphic addition of all votes
	g.POST("/tally", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if len(st.ballots) < 2 {
			return re.JSON(400, map[string]string{"error": "need at least 2 votes"})
		}

		// Initialize tally accumulator
		var tally [tallyBits]*fhe.Ciphertext
		for i := 0; i < tallyBits; i++ {
			tally[i] = st.enc.Encrypt(false)
		}

		// Add each ballot
		var err error
		for _, ballot := range st.ballots {
			tally, err = addBit(st.eval, tally, ballot)
			if err != nil {
				return re.JSON(500, map[string]string{"error": err.Error()})
			}
		}

		// Decrypt final tally only
		var yesCount uint8
		for i := 0; i < tallyBits; i++ {
			if st.dec.Decrypt(tally[i]) {
				yesCount |= 1 << i
			}
		}

		nVoters := len(st.ballots)
		st.result = &tallyResult{
			Yes:      yesCount,
			No:       nVoters - int(yesCount),
			Total:    nVoters,
			Passed:   int(yesCount) > nVoters/2,
			Majority: nVoters/2 + 1,
		}

		return re.JSON(200, map[string]string{
			"message": "tally complete, call GET /v1/result to see outcome",
		})
	})

	// POST /v1/result — decrypt final tally
	g.GET("/result", func(re *core.RequestEvent) error {
		st.mu.Lock()
		defer st.mu.Unlock()

		if st.result == nil {
			return re.JSON(404, map[string]string{"error": "no tally run yet"})
		}

		return re.JSON(200, st.result)
	})
}

// addBit adds a single encrypted bit to an n-bit encrypted accumulator.
func addBit(eval *fhe.Evaluator, acc [tallyBits]*fhe.Ciphertext, bit *fhe.Ciphertext) ([tallyBits]*fhe.Ciphertext, error) {
	carry := bit
	var result [tallyBits]*fhe.Ciphertext

	for i := 0; i < tallyBits; i++ {
		sum, err := eval.XOR(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d XOR: %w", i, err)
		}
		newCarry, err := eval.AND(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d AND: %w", i, err)
		}
		result[i] = sum
		carry = newCarry
	}
	return result, nil
}
