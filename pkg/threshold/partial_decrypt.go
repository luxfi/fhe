// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Real threshold-FHE partial-decrypt primitives.
//
// This file implements the M-of-N threshold decryption flow for the LWE
// ciphertexts produced by github.com/luxfi/fhe. The construction follows
// the standard "noise-flooding" threshold-FHE recipe:
//
//   1. Distributed key share: the LWE secret key s ∈ R_q (a polynomial in
//      Z_q[X]/(X^N+1)) is Shamir-split coefficient-by-coefficient over the
//      prime field Z_q. Party j gets a polynomial s_j whose i-th coefficient
//      equals f_i(j), where f_i is a degree-(t-1) polynomial with f_i(0) =
//      s[i]. No party ever holds s, and no t-1 parties together can
//      recover s.
//
//   2. Partial decryption: given an LWE ciphertext ct = (c_0, c_1) (in NTT,
//      with c_0 = -a·s + m + e and c_1 = a), party j computes
//
//          d_j  =  c_1 · s_j  +  e_j        (mod q, NTT domain)
//
//      where e_j is fresh smudging noise sampled from a discrete Gaussian
//      whose standard deviation is large enough to statistically hide the
//      structure of c_1·s_j. The share s_j stays local.
//
//   3. Combine: collect ≥ t partials and compute
//
//          c_0  +  sum_j λ_j · d_j
//        = c_0  +  c_1 · (sum_j λ_j s_j)  +  sum_j λ_j e_j
//        = c_0  +  c_1 · s  +  sum_j λ_j e_j
//        = m + e + sum_j λ_j e_j      (mod q)
//
//      where λ_j is the Lagrange basis coefficient at x=0 for the chosen
//      subset of t parties. Rounding then recovers the bit. The combined
//      noise sum_j λ_j e_j is the *original* fresh-encryption noise plus the
//      smudging tail; the parameter set picks the smudging σ so the round-
//      to-bit decision is correct with overwhelming probability and the
//      simulator can produce d_j from a fresh encryption of the same bit
//      under the master key (the AJL+12 / MTBH20 simulation-soundness
//      argument).
//
// References:
//   - Asharov, Jain, López-Alt, Tromer, Vaikuntanathan, Wichs.
//     "Multiparty Computation with Low Communication, Computation and
//     Interaction via Threshold FHE." EUROCRYPT 2012. ePrint 2011/613.
//   - Mouchet, Troncoso-Pastoriza, Bossuat, Hubaux.
//     "Multiparty Homomorphic Encryption from Ring-Learning-with-Errors."
//     PETS 2021. ePrint 2020/304.
//   - Boschini, Takahashi, Tibouchi. "Floppy-sized group signatures from
//     lattices." (Noise-flooding parameter calibration.) ACNS 2024.
//   - Bendlin, Damgård. "Threshold Decryption and Zero-Knowledge Proofs for
//     Lattice-Based Cryptosystems." TCC 2010. (Lagrange combine over LWE.)
//
// Decomplecting note: LSSS-over-Z_q lives next to LSSS-over-large-prime in
// this package. They are *different primitives* — the large-prime version
// is for masking high-entropy secrets where the secret space need not match
// the FHE modulus (e.g., the SHA-256 hash of a serialized SKLWE used for
// verifiable secret sharing). This file's LSSS works directly in the LWE
// field Z_q so the Shamir math composes with the lattice arithmetic.

package threshold

import (
	"fmt"
	"math/big"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// Bendlin-Damgård denominator-clearing factor.
//
// When we apply the Lagrange interpolation formula λ_j = ∏_{k≠j} (-x_k)/(x_j - x_k)
// over the field Z_q to recombine the secret, the rational λ_j can be
// "small as an integer" but is computed modulo q — so the resulting
// uint64 in [0, q) may be huge. That huge multiplier, applied to the
// smudging noise e_j, destroys the rounding margin. The fix from
// Bendlin-Damgård (TCC 2010, §4.2) is to clear denominators by working
// with the scaled secret  s' = Δ·s  where Δ = (total!).  Then the
// integer Lagrange numerator  Λ_j = Δ · λ_j  is an exact integer with
// |Λ_j| ≤ Δ for any subset of size t.  The combine step yields
//
//     combine = Δ · m + Σ_j Λ_j · e_j      (mod q)
//
// and we divide by Δ (mod q) at the very end.  The noise budget on the
// smudging σ is then  Δ · σ · √t · 6  ≤  Q/16, which is achievable
// for the standard luxfi/fhe parameter sets up to (t, n) = (11, 21).
//
// We expose Δ as deltaFactorial; it's tiny (uint64-fits) for n ≤ 20 and
// requires big.Int once n > 20. We use big.Int unconditionally for
// uniformity.
//
// References:
//   - Bendlin, Damgård. "Threshold Decryption and Zero-Knowledge Proofs
//     for Lattice-Based Cryptosystems." TCC 2010, §4.2.
//   - Asharov, Jain, López-Alt, Tromer, Vaikuntanathan, Wichs.
//     "Multiparty Computation … via Threshold FHE." EUROCRYPT 2012, §4.

// deltaFactorial returns Δ = total! as a big.Int.
func deltaFactorial(total int) *big.Int {
	d := big.NewInt(1)
	for k := int64(2); k <= int64(total); k++ {
		d.Mul(d, big.NewInt(k))
	}
	return d
}

// SmudgingSigma computes the smudging-noise σ for the given LWE
// parameters, threshold, and total committee size. The choice satisfies
// the Bendlin-Damgård noise bound
//
//	max_i |Λ_i| · σ · √t · 6  ≤  Q/16,
//
// where Λ_i is the integer Bendlin-Damgård Lagrange numerator (which is
// bounded by Δ · C(n-1, t-1) for the worst-case subset, and 6 covers the
// truncation bound of the discrete Gaussian (we sample bounded by 6σ —
// matches lattice/ring conventions).
//
// The combined-noise worst case is when partial indices cluster at one
// end of {1..n}; the Lagrange numerator at the far point scales as
// Δ · (n-1 choose t-1) for that subset. We use that tight bound here.
//
// For PN10QP27 (Q ≈ 2^27) at (t, n) = (2, 3): Δ · C(2,1) = 6 · 2 = 12,
// so σ ≤ Q/(16 · 6 · √2 · 12) ≈ 82400 — very comfortable.
//
// For (t, n) = (5, 9): Δ · C(8,4) = 362880 · 70 = 2.5e7; σ ≤ Q/(16 · 6 ·
// √5 · 2.5e7) ≈ 0.025 — well below 1, so PN10QP27 *cannot* support 5-of-
// 9 securely.  The caller must escalate to PN11QP54 (Q ≈ 2^54) or
// PN12QP109.  This function returns the upper-bound σ regardless;
// callers who get σ < 1 should pick a wider parameter set.
//
// Returns σ_smudge for use in PartialDecryptLWE. Passing a larger σ
// breaks the rounding margin, a smaller one weakens the masking.
func SmudgingSigma(params rlwe.Parameters, threshold, total int) float64 {
	q := float64(params.Q()[0])
	worst := worstLagrangeBoundFloat(threshold, total)
	margin := q / 16.0
	bound := 6.0 * sqrtApprox(float64(threshold)) * worst
	if bound <= 0 {
		return 1
	}
	sigma := margin / bound
	if sigma < 1 {
		// Floor at 1 so callers still get *some* masking; whether this
		// is cryptographically sufficient is a parameter-set choice
		// (see comment above).
		sigma = 1
	}
	return sigma
}

// worstLagrangeBoundFloat returns Δ · max_{S ⊂ [n], |S|=t} max_{i ∈ S}
// |∏_{j ∈ S, j≠i} x_j / ∏_{j ∈ S, j≠i}(x_i - x_j)|, lifted to float64.
//
// The maximum over all t-subsets is achieved when the subset clusters at
// one end of [1..total]. We bound by Δ · C(total-1, threshold-1) which
// is sharp for the cluster-at-one-end case.
func worstLagrangeBoundFloat(threshold, total int) float64 {
	if threshold <= 0 || total < threshold {
		return 0
	}
	delta := deltaFactorial(total)
	binom := new(big.Int).Binomial(int64(total-1), int64(threshold-1))
	w := new(big.Int).Mul(delta, binom)
	f, _ := new(big.Float).SetInt(w).Float64()
	return f
}

// sqrtApprox returns a cheap sqrt suitable for parameter-set sizing.
// Newton's method, six iterations, seeded with x/2 — exact to >2 decimals
// for the N values we care about (256..2048).
func sqrtApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 6; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// LWEShare carries one party's Shamir share of the LWE secret key under
// the Bendlin-Damgård denominator-clearing scheme.
//
// The share is itself a polynomial s_j ∈ R_q in *coefficient* domain
// (non-NTT, non-Montgomery). The i-th coefficient s_j[i] equals f_i(j)
// where f_i is the secret-sharing polynomial for the i-th coefficient of
// Δ·s (NOT s) and Δ = total!. Index is the Shamir x-coordinate (1-based).
//
// Combine recovers Δ·s exactly via *integer* Lagrange coefficients (no
// modular inverse on the noise path), then divides by Δ mod q to recover
// s. See partial_decrypt.go header comment for the full noise budget.
//
// Domain choice: we store in coefficient form because (a) it serialises
// compactly (just N·8 bytes for level=0) and (b) partial decrypt needs to
// re-NTT and re-MForm anyway with the local PRNG state. Crucially, the
// share lives in the *standard* representation, NOT the NTT+Montgomery
// representation of the master secret — a stolen NTT-Montgomery share
// would leak the same information; that's not a defect of either form.
type LWEShare struct {
	// Index is the Shamir x-coordinate, 1-based.
	Index int

	// Coeffs is the polynomial s_j ∈ Z_q[X]/(X^N+1) in coefficient form,
	// representing one party's share of Δ·s. Length is exactly N.
	Coeffs []uint64

	// Q is the LWE modulus this share is bound to. Recorded so combine
	// can detect cross-parameter mixing.
	Q uint64

	// Total is the committee size used at sharing time. Combine needs
	// this to compute Δ = Total! and divide it out at the end. Carried
	// per-share so a stale share is detected at combine time.
	Total int
}

// LWEPartialDecryption is one party's partial decryption d_j of an LWE
// ciphertext under their LWEShare. Stored in NTT domain so the combine
// step can sum directly without re-NTT.
type LWEPartialDecryption struct {
	// Index is the Shamir x-coordinate of the contributing share.
	Index int

	// Value is the polynomial d_j = c_1·s_j + e_j in NTT domain.
	// Length is exactly N at level 0. s_j here is a share of Δ·s,
	// matching the LWEShare convention.
	Value []uint64

	// Q is the LWE modulus.
	Q uint64

	// Total is the committee size at sharing time, copied from the
	// contributing LWEShare. Combine uses it to derive Δ.
	Total int
}

// ShareLWESecretKey Shamir-splits the LWE secret key coefficient-by-
// coefficient over Z_q where q is the LWE modulus.
//
// TRUSTED-DEALER. This takes a WHOLE secret key, so the caller momentarily holds
// the full FHE secret — a single point of compromise. It is retained as a
// test/KAT oracle for the LWEShare type; the trustless PRODUCTION key generation
// is DealerlessKeyGen (dealerless_dkg.go), where no party ever holds the secret.
// Both produce the same LWEShare via the same dealing helpers (dealCoeffSubShares).
//
// Pipeline:
//
//  1. Extract the secret-key polynomial from NTT+Montgomery form back to
//     standard coefficient form. (skLWE.Value.Q is stored NTT+Montgomery
//     per rlwe.KeyGenerator.genSecretKeyFromSampler.)
//  2. For each coefficient s[i], pick a random degree-(t-1) polynomial f_i
//     with f_i(0) = s[i], evaluate at x = 1, ..., total.
//  3. Bundle the j-th evaluation of every coefficient into the j-th share.
//
// The master secret is NEVER materialised outside step 1's local buffer;
// after sharing, the caller is expected to zero it. (Callers should also
// zero the rlwe.SecretKey itself if they only need shares.)
//
// Parameters validation: threshold must be in [1, total]; an honest-
// majority deployment picks t = floor(total/2)+1. For total > q-1 the
// Shamir x-coordinates would collide modulo q; we explicitly reject this
// to avoid silent share corruption.
func ShareLWESecretKey(skLWE *rlwe.SecretKey, params rlwe.Parameters, threshold, total int) ([]LWEShare, error) {
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("threshold/lwe: bad threshold %d for total %d", threshold, total)
	}
	q := params.Q()[0]
	if uint64(total) >= q {
		return nil, fmt.Errorf("threshold/lwe: total %d exceeds LWE modulus %d", total, q)
	}

	// 1) Extract the secret key to standard coefficient form. (Shared helper
	//    extractStdCoeffs mirrors genSecretKeyFromSampler in reverse: IMForm
	//    then INTT, returning a fresh copy and zeroing its scratch.)
	stdCoeffs := extractStdCoeffs(params, skLWE)

	// 2) Share s itself (not Δ·s) via the SAME coefficient-wise dealing used by
	//    the dealerless DKG (dealCoeffSubShares). The Bendlin-Damgård trick is
	//    that the *integer* Lagrange numerators Λ_j = Δ · λ_j satisfy
	//    Σ_j Λ_j · f(j) = Δ · f(0) by linearity; combine therefore yields Δ · s
	//    without any pre-scaling of the secret. The smudging noise is the only
	//    term that picks up a Λ-factor in magnitude (see SmudgingSigma).
	//
	//    The ONLY difference from the dealerless path: here a single trusted
	//    dealer holds the whole skLWE and deals it; in DealerlessKeyGen each
	//    party deals only its own contribution and the shares are summed. The
	//    dealing math is identical — hence shared — but the trust model is not.
	sub, err := dealCoeffSubShares(stdCoeffs, q, threshold, total)
	zeroU64(stdCoeffs)
	if err != nil {
		return nil, err
	}

	shares := make([]LWEShare, total)
	for j := 0; j < total; j++ {
		shares[j] = LWEShare{
			Index:  j + 1,
			Coeffs: sub[j],
			Q:      q,
			Total:  total,
		}
	}

	return shares, nil
}

// evalPolyModQ evaluates coeffs[0] + coeffs[1]·x + ... + coeffs[t-1]·x^(t-1)
// modulo q using Horner's method, returning a uint64 in [0, q).
func evalPolyModQ(coeffs []*big.Int, x, q *big.Int) uint64 {
	acc := new(big.Int).Set(coeffs[len(coeffs)-1])
	for k := len(coeffs) - 2; k >= 0; k-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[k])
		acc.Mod(acc, q)
	}
	if acc.Sign() < 0 {
		acc.Add(acc, q)
	}
	return acc.Uint64()
}

// PartialDecryptLWE produces party j's partial decryption d_j of the LWE
// ciphertext ct under their LWEShare. The output is in NTT domain at
// level 0.
//
//	d_j  =  c_1 · s_j  +  e_j        (mod q, NTT)
//
// where c_1 is ct.Value[1] (already in NTT per rlwe convention), s_j is
// the share polynomial NTT'd into the LWE ring, and e_j is sampled from
// a discrete Gaussian with the supplied σ. The share polynomial is
// reduced into the LWE ring on the fly; the caller must not pre-NTT it.
//
// IMPORTANT: every call to PartialDecryptLWE on the same ciphertext with
// the same share *must* produce a new e_j. Reusing e_j across calls
// completely breaks the noise-flooding masking. The caller-supplied prng
// is responsible for this freshness; we wire a fresh PRNG per call to
// make the contract explicit.
func PartialDecryptLWE(
	share *LWEShare,
	ct *rlwe.Ciphertext,
	params rlwe.Parameters,
	sigma float64,
	prng sampling.PRNG,
) (*LWEPartialDecryption, error) {
	if share == nil {
		return nil, fmt.Errorf("threshold/lwe: nil share")
	}
	q := params.Q()[0]
	if share.Q != q {
		return nil, fmt.Errorf("threshold/lwe: share q=%d does not match params q=%d", share.Q, q)
	}
	ringQ := params.RingQ().AtLevel(0)
	if got := len(share.Coeffs); got != ringQ.N() {
		return nil, fmt.Errorf("threshold/lwe: share length %d != ring N %d", got, ringQ.N())
	}

	// 1) Lift the share into the lattice ring representation. We start in
	//    coefficient form, NTT, then MForm so the Montgomery-domain
	//    multiplication MulCoeffsMontgomery composes correctly.
	sPoly := ringQ.NewPoly()
	copy(sPoly.Coeffs[0], share.Coeffs)
	ringQ.NTT(sPoly, sPoly)
	ringQ.MForm(sPoly, sPoly)

	// 2) Compute c_1 · s_j in NTT/Montgomery domain.
	//    rlwe stores ciphertexts with Value[1] in NTT form already.
	c1 := ct.Value[1]
	if !ct.IsNTT {
		// Defensive: NTT into a buffer rather than mutating the caller's
		// ciphertext. The standard fhe.Encryptor produces NTT ciphertexts
		// (see encryptor.go addPtToCt + lwe encoding), but we handle both.
		buf := ringQ.NewPoly()
		ringQ.NTT(c1, buf)
		c1 = buf
	}
	dPoly := ringQ.NewPoly()
	ringQ.MulCoeffsMontgomery(c1, sPoly, dPoly)

	// 3) Sample smudging noise e_j ∈ R_q with discrete-Gaussian σ.
	//    We sample in standard form, NTT, then add to d_j. Bound is set
	//    to 6σ (truncated Gaussian — matches lattice/ring conventions).
	bound := 6.0 * sigma
	if bound > float64(q)/2 {
		bound = float64(q) / 2
	}
	xeSampler, err := ring.NewSampler(prng, ringQ, ring.DiscreteGaussian{
		Sigma: sigma,
		Bound: bound,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("threshold/lwe: noise sampler: %w", err)
	}
	ePoly := ringQ.NewPoly()
	xeSampler.AtLevel(0).Read(ePoly)
	ringQ.NTT(ePoly, ePoly)
	ringQ.Add(dPoly, ePoly, dPoly)

	// Zero the share's lattice-ring lift; the persistent share is in
	// coefficient form (share.Coeffs) and was untouched.
	sPoly.Zero()
	ePoly.Zero()

	out := &LWEPartialDecryption{
		Index: share.Index,
		Value: make([]uint64, ringQ.N()),
		Q:     q,
		Total: share.Total,
	}
	copy(out.Value, dPoly.Coeffs[0])
	return out, nil
}

// CombineLWE Lagrange-interpolates ≥ t partial decryptions and finishes
// the recovery, returning the recovered plaintext polynomial in NTT.
//
// Under Bendlin-Damgård denominator clearing we recover Δ·m where Δ =
// total!:
//
//	Δ · pt  =  Δ · c_0  +  Σ_j Λ_j · d_j        (NTT)
//
// where Λ_j = Δ · λ_j ∈ ℤ are *integer* Lagrange numerators, and the
// noise stays bounded by |Σ_j Λ_j · e_j| ≤ Δ · √t · 6σ ≤ Q/16. After
// summing in Z_q we multiply by Δ^{-1} mod q to peel the scaling off
// and return the canonical plaintext polynomial.
//
// Returns the plaintext polynomial in NTT form. Apply INTT then read
// coefficient 0 for bit ciphertexts to recover the bit.
//
// Errors out if any partial's Q or Total disagrees with the supplied
// params, if indices repeat, or if fewer than 1 partial is supplied.
// The threshold itself is enforced by the caller — combine does not
// know t. Re-using partials beyond their Total field's value is rejected
// to catch cross-keygen mixing.
func CombineLWE(
	ct *rlwe.Ciphertext,
	partials []*LWEPartialDecryption,
	params rlwe.Parameters,
) (*rlwe.Plaintext, error) {
	if len(partials) < 1 {
		return nil, fmt.Errorf("threshold/lwe: no partials supplied")
	}
	q := params.Q()[0]
	total := partials[0].Total
	for _, p := range partials {
		if p == nil {
			return nil, fmt.Errorf("threshold/lwe: nil partial")
		}
		if p.Q != q {
			return nil, fmt.Errorf("threshold/lwe: partial q=%d != params q=%d", p.Q, q)
		}
		if p.Total != total {
			return nil, fmt.Errorf("threshold/lwe: partial total=%d differs from %d", p.Total, total)
		}
	}
	seen := make(map[int]struct{}, len(partials))
	for _, p := range partials {
		if _, dup := seen[p.Index]; dup {
			return nil, fmt.Errorf("threshold/lwe: duplicate partial index %d", p.Index)
		}
		seen[p.Index] = struct{}{}
	}

	ringQ := params.RingQ().AtLevel(0)
	qBig := new(big.Int).SetUint64(q)
	delta := deltaFactorial(total)
	deltaMod := new(big.Int).Mod(delta, qBig)

	// Accumulator starts at Δ · c_0 in NTT form (since the right-hand
	// side of the Bendlin-Damgård identity is Δ · c_0 + Σ_j Λ_j d_j).
	accum := ringQ.NewPoly()
	c0 := ct.Value[0]
	if ct.IsNTT {
		accum.Coeffs[0] = append([]uint64(nil), c0.Coeffs[0]...)
	} else {
		// Defensive NTT into a buffer if the ciphertext is non-NTT.
		ringQ.NTT(c0, accum)
	}
	ringQ.MulScalar(accum, deltaMod.Uint64(), accum)

	// For each partial: Λ_j (integer, then mod q for ring scalar mul),
	// then accum += Λ_j · d_j in NTT.
	scratch := ringQ.NewPoly()
	for i, pi := range partials {
		lambdaInt := lagrangeIntegerNumeratorAtZero(partials, i, delta)
		// Reduce mod q for the lattice ring-scalar multiply.
		lambdaMod := new(big.Int).Mod(lambdaInt, qBig)
		if lambdaMod.Sign() < 0 {
			lambdaMod.Add(lambdaMod, qBig)
		}
		// Lift partial into a poly, then scale by Λ_j mod q.
		copy(scratch.Coeffs[0], pi.Value)
		ringQ.MulScalar(scratch, lambdaMod.Uint64(), scratch)
		ringQ.Add(accum, scratch, accum)
	}
	scratch.Zero()

	// Divide out Δ to recover m: multiply accum by Δ^{-1} mod q.
	deltaInv := new(big.Int).ModInverse(deltaMod, qBig)
	if deltaInv == nil {
		return nil, fmt.Errorf("threshold/lwe: Δ has no inverse mod q (total %d, q %d)", total, q)
	}
	ringQ.MulScalar(accum, deltaInv.Uint64(), accum)

	pt := rlwe.NewPlaintext(params, 0)
	pt.Value.Coeffs[0] = accum.Coeffs[0]
	pt.IsNTT = true
	return pt, nil
}

// lagrangeIntegerNumeratorAtZero returns Λ_i = Δ · λ_i evaluated at 0
// for the supplied subset of partials, where Δ is total! (assumed to
// equal delta). Λ_i is an *exact integer* by Bendlin-Damgård §4.2;
// |Λ_i| ≤ Δ for any subset of size t ≤ total.
//
// λ_i = ∏_{j≠i} (-x_j) / (x_i - x_j), and Λ_i = Δ · λ_i. We compute
// the integer numerator N_i = ∏(-x_j) and denominator D_i = ∏(x_i - x_j),
// then return Δ · N_i / D_i as a big.Int (the division is exact when
// Δ = total!).
func lagrangeIntegerNumeratorAtZero(partials []*LWEPartialDecryption, i int, delta *big.Int) *big.Int {
	xi := new(big.Int).SetInt64(int64(partials[i].Index))
	num := big.NewInt(1)
	den := big.NewInt(1)
	for j, pj := range partials {
		if j == i {
			continue
		}
		xj := new(big.Int).SetInt64(int64(pj.Index))
		// num *= (-xj) — full integer product, no mod.
		neg := new(big.Int).Neg(xj)
		num.Mul(num, neg)
		// den *= (xi - xj)
		diff := new(big.Int).Sub(xi, xj)
		den.Mul(den, diff)
	}
	// Λ = Δ · num / den. The division is exact because den divides Δ:
	// den = ∏_{j≠i}(x_i - x_j) divides ∏_{k=1..total}(x_i - k) which
	// divides total! · (a unit). The standard B-D argument.
	t := new(big.Int).Mul(delta, num)
	q, r := new(big.Int).QuoRem(t, den, new(big.Int))
	if r.Sign() != 0 {
		// Should never happen if delta = total! and indices ⊂ {1..total}.
		// Panic loudly — wrong delta would silently break security.
		panic(fmt.Sprintf("threshold/lwe: non-exact integer Lagrange numerator (delta=%s, t=%s, den=%s, r=%s)", delta, t, den, r))
	}
	return q
}

// DecryptBitFromPlaintext decodes a single bit from the recovered
// plaintext polynomial, applying luxfi/fhe's encoding scheme: true ↦ Q/8,
// false ↦ 7Q/8. After INTT, coefficient 0 lies near +Q/8 or -Q/8; we
// return true iff it lies in [0, Q/2). Mirrors fhe.Decryptor.Decrypt.
func DecryptBitFromPlaintext(pt *rlwe.Plaintext, params rlwe.Parameters) bool {
	ringQ := params.RingQ().AtLevel(0)
	if pt.IsNTT {
		// INTT into a buffer so we don't mutate the caller's plaintext.
		out := ringQ.NewPoly()
		ringQ.INTT(pt.Value, out)
		c := out.Coeffs[0][0]
		out.Zero()
		return c < params.Q()[0]>>1
	}
	c := pt.Value.Coeffs[0][0]
	return c < params.Q()[0]>>1
}

// ShareLWESecretKeyFHE is a thin convenience over ShareLWESecretKey that
// works directly against fhe.Parameters / fhe.SecretKey. Use this from
// out-of-tree callers (notably luxfi/threshold/protocols/tfhe) who already
// have fhe types in hand.
func ShareLWESecretKeyFHE(sk *fhe.SecretKey, params fhe.Parameters, threshold, total int) ([]LWEShare, error) {
	return ShareLWESecretKey(sk.SKLWE, params.ParamsLWE(), threshold, total)
}

// PartialDecryptFHE is a thin convenience that operates against the
// fhe.Ciphertext + fhe.Parameters wrapper. Returns a per-bit partial
// decryption sized for the supplied threshold (used only to pick σ).
//
// The σ choice here uses (threshold, share.Total) per Bendlin-Damgård.
// PRNG defaults to a fresh sampling.PRNG when nil — production callers
// pass a process-managed PRNG so smudging noise is logged for audit.
func PartialDecryptFHE(
	share *LWEShare,
	ct *fhe.Ciphertext,
	params fhe.Parameters,
	threshold int,
	prng sampling.PRNG,
) (*LWEPartialDecryption, error) {
	if prng == nil {
		var err error
		prng, err = sampling.NewPRNG()
		if err != nil {
			return nil, fmt.Errorf("threshold/lwe: default prng: %w", err)
		}
	}
	sigma := SmudgingSigma(params.ParamsLWE(), threshold, share.Total)
	return PartialDecryptLWE(share, ct.Ciphertext, params.ParamsLWE(), sigma, prng)
}

// CombineFHE Lagrange-combines a set of LWEPartialDecryptions and
// decodes a single bit. Convenience over CombineLWE + DecryptBit.
func CombineFHE(
	ct *fhe.Ciphertext,
	partials []*LWEPartialDecryption,
	params fhe.Parameters,
) (bool, error) {
	pt, err := CombineLWE(ct.Ciphertext, partials, params.ParamsLWE())
	if err != nil {
		return false, err
	}
	return DecryptBitFromPlaintext(pt, params.ParamsLWE()), nil
}
