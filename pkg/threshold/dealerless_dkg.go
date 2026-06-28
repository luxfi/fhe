// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Dealerless (trustless) threshold-FHE key generation.
//
// This file closes the one trustless gap in the threshold-FHE stack: the
// generation of the LWE encryption key. The partial-decrypt kernel
// (partial_decrypt.go) is already NO-RECONSTRUCT — the master secret s never
// appears outside the masked aggregate c_1·s. But ShareLWESecretKey assumes a
// TRUSTED DEALER: a single party that samples the whole secret key s and then
// Shamir-splits it. At that instant one process holds s — a single point of
// compromise that violates the trustless-by-default law (no trusted dealer +
// no-reconstruct, the same standard Corona/Pulsar/Magnetar are held to).
//
// DealerlessKeyGen removes the dealer. It is the standard GJKR/Pedersen
// distributed-key-generation structure, specialised to the RLWE/LWE secret and
// composed with the audited Lattigo multiparty collective-public-key protocol
// (CKG, github.com/luxfi/lattice/v7/multiparty):
//
//  1. CRS. All parties derive one common reference polynomial a ∈ R_q from a
//     consensus-supplied seed (sampling.NewKeyedPRNG). Determinism: every
//     validator derives the identical a.
//
//  2. Each party j independently samples its OWN secret contribution
//     s_j ← χ (the library's secret distribution). The collective secret is
//     s = Σ_j s_j. No party ever sees another party's s_j.
//
//  3. Collective public key (dealerless). Each party publishes the CKG share
//     p_j = -a·s_j + e_j; the public aggregate is p = Σ_j p_j = -a·s + e, and
//     pk = (p, a) encrypts to the collective secret s. (Audited Lattigo CKG.)
//
//  4. t-of-n shares (dealerless). Each party j Shamir-splits its OWN s_j
//     coefficient-by-coefficient over Z_q: it sends party k the sub-share
//     σ_{j→k}[i] = f_{j,i}(k) where f_{j,i} is a fresh degree-(t-1) polynomial
//     with f_{j,i}(0) = s_j[i]. Each recipient k sums the sub-shares it
//     receives: σ_k[i] = Σ_j σ_{j→k}[i] = (Σ_j f_{j,i})(k). Because
//     (Σ_j f_{j,i})(0) = Σ_j s_j[i] = s[i], party k holds a degree-(t-1)
//     Shamir share of the collective secret s — and no party, nor this
//     package, ever forms s.
//
// The resulting per-party LWEShare is bit-for-bit the same type the proven
// PartialDecryptLWE / CombineLWE kernel already consumes, so threshold
// decryption is unchanged: encrypt under the collective pk, ≥ t parties each
// PartialDecryptLWE with their share, CombineLWE recovers the plaintext. The
// secret s exists only as the (never-materialised) sum of the parties'
// contributions and only ever acts through the masked aggregate.
//
// DECOMPLECTING NOTE. This is the F-Chain (confidential-decrypt) lane only.
// It generates the LWE ENCRYPTION key and its t-of-n shares — everything the
// confidential encrypt → store → threshold-decrypt flow needs. It deliberately
// does NOT generate the FHEW blind-rotation / bootstrap key (needed for
// homomorphic COMPUTE on committee ciphertexts); dealerless bootstrap-key
// generation is a separate multiparty-FHEW protocol and is documented as the
// residual in this package's README, not faked here.
//
// References:
//   - Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation
//     for Discrete-Log Based Cryptosystems." EUROCRYPT 1999. (Dealerless DKG.)
//   - Mouchet, Troncoso-Pastoriza, Bossuat, Hubaux. "Multiparty Homomorphic
//     Encryption from Ring-Learning-with-Errors." PETS 2021. (Collective
//     public key + threshold scheme; the lattice/multiparty implementation.)
//   - Asharov, Jain, López-Alt, Tromer, Vaikuntanathan, Wichs. EUROCRYPT 2012.
//     (Threshold-FHE decrypt; partial_decrypt.go.)

package threshold

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// PublicKeyShareMsg is a party's BROADCAST contribution to the collective
// public key: the CKG share -a·s_j + e_j. It is PUBLIC — it reveals nothing
// about s_j beyond what the final public key reveals about s — and carries no
// secret-key material.
type PublicKeyShareMsg struct {
	From  int
	Share multiparty.PublicKeyGenShare
}

// SubShareMsg is a private point-to-point message: dealer `From` sends recipient
// `To` the coefficient-wise Shamir evaluation, at x=To, of `From`'s OWN secret
// contribution. It is a SINGLE Shamir point of one party's secret, addressed to
// exactly one recipient — never the secret itself, and never another party's
// share. Any t-1 of these reveal nothing about the dealer's contribution.
//
// Deliberately contains NO *rlwe.SecretKey / *fhe.SecretKey field: the transport
// cannot carry a full secret. (Enforced by dealerless_dkg_test.go's reflect gate.)
type SubShareMsg struct {
	From   int
	To     int
	Coeffs []uint64 // f^{(From)}_i(To) mod q, for i in [0, N)
}

// DealerlessParty is ONE committee member's private state. It is constructed
// from the member's OWN freshly-sampled secret contribution and never ingests
// another party's secret contribution — only public CKG shares and the Shamir
// sub-shares addressed to it. There is intentionally no method that returns or
// reconstructs the collective secret s.
type DealerlessParty struct {
	index            int // 1-based Shamir x-coordinate / party identity
	threshold, total int
	params           fhe.Parameters
	paramsLWE        rlwe.Parameters
	ckg              multiparty.PublicKeyGenProtocol

	// si is this party's OWN secret contribution s_j. Private; never
	// serialized and never leaves the node. Zeroized by Zeroize().
	si *rlwe.SecretKey
}

// NewDealerlessParty creates party `index` (1-based) for a (threshold, total)
// committee and samples its OWN secret contribution s_index. Each party must be
// constructed locally on its own node; the constructor performs no I/O.
func NewDealerlessParty(index, threshold, total int, params fhe.Parameters) (*DealerlessParty, error) {
	if index < 1 || index > total {
		return nil, fmt.Errorf("threshold/dkg: party index %d out of range [1,%d]", index, total)
	}
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("threshold/dkg: bad threshold %d for total %d", threshold, total)
	}
	paramsLWE := params.ParamsLWE()
	if uint64(total) >= paramsLWE.Q()[0] {
		return nil, fmt.Errorf("threshold/dkg: total %d exceeds LWE modulus %d", total, paramsLWE.Q()[0])
	}
	// Each party samples its OWN contribution with the library's exact secret
	// distribution, so the collective key is well-formed for the FHE scheme.
	si := rlwe.NewKeyGenerator(paramsLWE).GenSecretKeyNew()
	return &DealerlessParty{
		index:     index,
		threshold: threshold,
		total:     total,
		params:    params,
		paramsLWE: paramsLWE,
		ckg:       multiparty.NewPublicKeyGenProtocol(paramsLWE),
		si:        si,
	}, nil
}

// Index returns this party's 1-based identity.
func (p *DealerlessParty) Index() int { return p.index }

// SampleDealerlessCRP derives the shared common reference polynomial a from a
// consensus seed and returns it together with a protocol handle. Every
// validator calls this with the identical seed and obtains the identical a, so
// the collective public key is deterministic across the network.
func SampleDealerlessCRP(params fhe.Parameters, crsSeed []byte) (multiparty.PublicKeyGenCRP, multiparty.PublicKeyGenProtocol, error) {
	if len(crsSeed) == 0 {
		return multiparty.PublicKeyGenCRP{}, multiparty.PublicKeyGenProtocol{}, fmt.Errorf("threshold/dkg: empty CRS seed")
	}
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return multiparty.PublicKeyGenCRP{}, multiparty.PublicKeyGenProtocol{}, fmt.Errorf("threshold/dkg: keyed prng: %w", err)
	}
	ckg := multiparty.NewPublicKeyGenProtocol(params.ParamsLWE())
	crp := ckg.SampleCRP(crs)
	return crp, ckg, nil
}

// DealRound1 produces this party's two outputs:
//
//   - its PUBLIC CKG contribution p_index = -a·s_index + e_index, and
//   - one PRIVATE Shamir sub-share per recipient (including itself), being the
//     coefficient-wise degree-(t-1) Shamir dealing of its OWN s_index.
//
// The party's secret contribution s_index is used here and only here; it never
// leaves the node. The full collective secret is never formed.
func (p *DealerlessParty) DealRound1(crp multiparty.PublicKeyGenCRP) (PublicKeyShareMsg, []SubShareMsg, error) {
	if p.si == nil {
		return PublicKeyShareMsg{}, nil, fmt.Errorf("threshold/dkg: party %d already finalized (secret zeroized)", p.index)
	}

	// Public CKG contribution toward the collective encryption key.
	share := p.ckg.AllocateShare()
	p.ckg.GenShare(p.si, crp, &share)

	// Private coefficient-wise Shamir dealing of this party's OWN contribution.
	stdCoeffs := extractStdCoeffs(p.paramsLWE, p.si)
	sub, err := dealCoeffSubShares(stdCoeffs, p.paramsLWE.Q()[0], p.threshold, p.total)
	zeroU64(stdCoeffs)
	if err != nil {
		return PublicKeyShareMsg{}, nil, err
	}

	msgs := make([]SubShareMsg, p.total)
	for r := 0; r < p.total; r++ {
		msgs[r] = SubShareMsg{From: p.index, To: r + 1, Coeffs: sub[r]}
	}
	return PublicKeyShareMsg{From: p.index, Share: share}, msgs, nil
}

// Aggregate folds the Shamir sub-shares addressed to THIS party (one from each
// dealer, including itself) into the party's t-of-n LWEShare of the collective
// secret s. The result is a Shamir share of s; s itself is never reconstructed.
func (p *DealerlessParty) Aggregate(inbound []SubShareMsg) (LWEShare, error) {
	q := p.paramsLWE.Q()[0]
	N := p.paramsLWE.RingQ().N()
	coeffs := make([]uint64, N)
	seen := make(map[int]struct{}, len(inbound))
	for _, m := range inbound {
		if m.To != p.index {
			return LWEShare{}, fmt.Errorf("threshold/dkg: sub-share addressed to %d delivered to party %d", m.To, p.index)
		}
		if _, dup := seen[m.From]; dup {
			return LWEShare{}, fmt.Errorf("threshold/dkg: duplicate sub-share from dealer %d", m.From)
		}
		seen[m.From] = struct{}{}
		if len(m.Coeffs) != N {
			return LWEShare{}, fmt.Errorf("threshold/dkg: sub-share length %d != ring N %d", len(m.Coeffs), N)
		}
		addModQ(coeffs, m.Coeffs, q)
	}
	if len(seen) != p.total {
		return LWEShare{}, fmt.Errorf("threshold/dkg: party %d expected %d sub-shares, got %d", p.index, p.total, len(seen))
	}
	return LWEShare{Index: p.index, Coeffs: coeffs, Q: q, Total: p.total}, nil
}

// Zeroize erases this party's secret contribution. Call once the party has its
// LWEShare; the contribution is no longer needed and must not linger.
func (p *DealerlessParty) Zeroize() {
	if p.si != nil {
		// ring.Poly.Zero is a no-op when Coeffs is empty (no P level), so both
		// parts can be scrubbed unconditionally.
		p.si.Value.Q.Zero()
		p.si.Value.P.Zero()
		p.si = nil
	}
}

// AssembleCollectivePublicKey aggregates every party's PUBLIC CKG share into the
// collective LWE public key. All inputs are public; this forms the public key
// p = Σ_j (-a·s_j + e_j) = -a·s + e, never the secret s.
func AssembleCollectivePublicKey(
	ckg multiparty.PublicKeyGenProtocol,
	crp multiparty.PublicKeyGenCRP,
	shares []PublicKeyShareMsg,
	params fhe.Parameters,
) (*fhe.PublicKey, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("threshold/dkg: no public-key shares")
	}
	agg := ckg.AllocateShare()
	// agg starts at the zero share; fold each contribution in.
	for i := range shares {
		ckg.AggregateShares(agg, shares[i].Share, &agg)
	}
	pkLWE := rlwe.NewPublicKey(params.ParamsLWE())
	ckg.GenPublicKey(agg, crp, pkLWE)
	return &fhe.PublicKey{PKLWE: pkLWE}, nil
}

// DealerlessKeyGen runs the full t-of-n dealerless ceremony. Each simulated
// party touches ONLY its own secret contribution and the messages addressed to
// it; the function never forms the collective secret s. Returns the collective
// LWE public key for encryption and one LWEShare per party for threshold
// decryption.
//
// This in-process driver is the protocol's executable specification and a
// single-coordinator deployment path. A distributed deployment instead runs the
// per-party DealerlessParty methods on separate nodes (DealRound1 broadcasts the
// public CKG share and unicasts each sub-share; Aggregate folds the inbound
// sub-shares) so that no node ever holds another node's contribution.
func DealerlessKeyGen(params fhe.Parameters, threshold, total int, crsSeed []byte) (*fhe.PublicKey, []LWEShare, error) {
	crp, ckg, err := SampleDealerlessCRP(params, crsSeed)
	if err != nil {
		return nil, nil, err
	}

	parties := make([]*DealerlessParty, total)
	for i := 0; i < total; i++ {
		parties[i], err = NewDealerlessParty(i+1, threshold, total, params)
		if err != nil {
			return nil, nil, err
		}
	}

	// Round 1: every party deals. Public CKG shares are collected; each private
	// sub-share is routed to its recipient's inbox. No party's si is ever shared.
	pkShares := make([]PublicKeyShareMsg, total)
	inboxes := make([][]SubShareMsg, total)
	for i, party := range parties {
		pkMsg, subs, derr := party.DealRound1(crp)
		if derr != nil {
			return nil, nil, derr
		}
		pkShares[i] = pkMsg
		for _, s := range subs {
			inboxes[s.To-1] = append(inboxes[s.To-1], s)
		}
	}

	// Collective public key from the public shares only.
	pub, err := AssembleCollectivePublicKey(ckg, crp, pkShares, params)
	if err != nil {
		return nil, nil, err
	}

	// Round 2: every party folds its inbox into its LWEShare of s.
	shares := make([]LWEShare, total)
	for i, party := range parties {
		shares[i], err = party.Aggregate(inboxes[i])
		if err != nil {
			return nil, nil, err
		}
		party.Zeroize()
	}

	return pub, shares, nil
}

// --- shared dealing helpers (used by the dealerless DKG and, for DRY, by the
// trusted-dealer ShareLWESecretKey) ---

// extractStdCoeffs lifts an rlwe secret key from its stored NTT+Montgomery form
// back to standard coefficient form in [0, q), returning a fresh copy. The
// scratch polynomial is zeroized before return.
func extractStdCoeffs(paramsLWE rlwe.Parameters, sk *rlwe.SecretKey) []uint64 {
	ringQ := paramsLWE.RingQ()
	skStd := ringQ.NewPoly()
	ringQ.IMForm(sk.Value.Q, skStd)
	ringQ.INTT(skStd, skStd)
	out := append([]uint64(nil), skStd.Coeffs[0]...)
	skStd.Zero()
	return out
}

// dealCoeffSubShares Shamir-splits a single secret polynomial (given in standard
// coefficient form) coefficient-by-coefficient over Z_q. For each recipient r in
// 1..total it returns a length-N vector whose i-th entry is f_i(r), where f_i is
// a fresh degree-(threshold-1) polynomial with f_i(0) = stdCoeffs[i] mod q. The
// degree-(t-1) masking coefficients are sampled with crypto/rand.
func dealCoeffSubShares(stdCoeffs []uint64, q uint64, threshold, total int) ([][]uint64, error) {
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("threshold/dkg: bad threshold %d for total %d", threshold, total)
	}
	qBig := new(big.Int).SetUint64(q)
	N := len(stdCoeffs)
	out := make([][]uint64, total)
	for r := 0; r < total; r++ {
		out[r] = make([]uint64, N)
	}
	for i := 0; i < N; i++ {
		coeffs := make([]*big.Int, threshold)
		coeffs[0] = new(big.Int).SetUint64(stdCoeffs[i] % q)
		for k := 1; k < threshold; k++ {
			rnd, err := rand.Int(rand.Reader, qBig)
			if err != nil {
				return nil, fmt.Errorf("threshold/dkg: random coeff: %w", err)
			}
			coeffs[k] = rnd
		}
		for r := 0; r < total; r++ {
			x := new(big.Int).SetInt64(int64(r + 1))
			out[r][i] = evalPolyModQ(coeffs, x, qBig)
		}
	}
	return out, nil
}

// addModQ computes dst[i] = (dst[i] + src[i]) mod q in place.
func addModQ(dst, src []uint64, q uint64) {
	for i := range dst {
		// Both operands are < q, so a single conditional subtraction suffices
		// without overflow for q < 2^63.
		s := dst[i] + src[i]
		if s >= q {
			s -= q
		}
		dst[i] = s
	}
}

// zeroU64 scrubs a uint64 slice holding sensitive coefficients.
func zeroU64(b []uint64) {
	for i := range b {
		b[i] = 0
	}
}
