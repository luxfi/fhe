// Package fhe - Security Levels
//
// This file defines standard security parameter sets that are compatible
// across both Go (luxfi/fhe) and C++ (OpenFHE) implementations.
//
// # Security Levels
//
// All parameter sets target specific security levels against classical and/or
// quantum attacks, with varying performance characteristics.
//
// # Classical vs Quantum Security
//
// - STD128: 128-bit classical security
// - STD128Q: 128-bit quantum security (post-quantum resistant)
// - STD192: 192-bit classical security
// - STD192Q: 192-bit quantum security
// - STD256: 256-bit classical security
// - STD256Q: 256-bit quantum security
//
// # Bootstrapping Methods
//
// - AP: Ducas-Micciancio variant (original TFHE)
// - GINX: Chillotti-Gama-Georgieva-Izabachene variant
// - LMKCDEY: Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo variant (fastest)
//
// The LMKCDEY method uses Gaussian secrets which enables smaller parameters
// and faster bootstrapping compared to AP/GINX with uniform secrets.
//
// # Parameter Set Naming Convention
//
// Format: STD{bits}[Q][_{inputs}][_LMKCDEY]
//
// - bits: Security level (128, 192, 256)
// - Q: Quantum-resistant (post-quantum)
// - inputs: Number of gate inputs (default 2, can be 3 or 4)
// - LMKCDEY: Optimized for LMKCDEY bootstrapping method
//
// # OpenFHE Compatibility
//
// These parameter sets directly correspond to OpenFHE's BINFHE_PARAMSET enum:
//
//	Go                    C++ (OpenFHE)         Security    Failure Prob
//	------------------------------------------------------------------
//	STD128_LMKCDEY        STD128_LMKCDEY        128-bit     2^(-55)
//	STD128Q_LMKCDEY       STD128Q_LMKCDEY       128-bit PQ  2^(-50)
//	STD192_LMKCDEY        STD192_LMKCDEY        192-bit     2^(-60)
//	STD192Q_LMKCDEY       STD192Q_LMKCDEY       192-bit PQ  2^(-70)
//	STD256_LMKCDEY        STD256_LMKCDEY        256-bit     2^(-50)
//	STD256Q_LMKCDEY       STD256Q_LMKCDEY       256-bit PQ  2^(-60)
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package fhe

// SecurityLevel represents the target security level
type SecurityLevel int

const (
	// Security128 provides 128-bit classical security
	Security128 SecurityLevel = 128
	// Security128Q provides 128-bit post-quantum security
	Security128Q SecurityLevel = 1128
	// Security192 provides 192-bit classical security
	Security192 SecurityLevel = 192
	// Security192Q provides 192-bit post-quantum security
	Security192Q SecurityLevel = 1192
	// Security256 provides 256-bit classical security
	Security256 SecurityLevel = 256
	// Security256Q provides 256-bit post-quantum security
	Security256Q SecurityLevel = 1256
)

// BootstrapMethod represents the bootstrapping algorithm
type BootstrapMethod int

const (
	// MethodAP is the Ducas-Micciancio (original TFHE) method
	MethodAP BootstrapMethod = iota
	// MethodGINX is the Chillotti-Gama-Georgieva-Izabachene method
	MethodGINX
	// MethodLMKCDEY is the Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo method (fastest)
	MethodLMKCDEY
)

// SecretDistribution represents the type of secret key distribution
type SecretDistribution int

const (
	// UniformTernary uses uniform ternary secrets (-1, 0, 1)
	UniformTernary SecretDistribution = iota
	// Gaussian uses Gaussian-distributed secrets
	Gaussian
)

// SecurityParams defines a complete security parameter specification
// matching OpenFHE's internal parameter structure
type SecurityParams struct {
	// Name is the parameter set identifier
	Name string
	// Security is the target security level
	Security SecurityLevel
	// Method is the bootstrapping method
	Method BootstrapMethod
	// LogQ is the log2 of the ciphertext modulus
	LogQ int
	// RingDim is the polynomial ring dimension (N)
	RingDim int
	// LWEDim is the LWE dimension (n)
	LWEDim int
	// BootstrapBase is the decomposition base for bootstrapping
	BootstrapBase int
	// KeySwitchBase is the decomposition base for key switching
	KeySwitchBase int
	// SecretDist is the secret key distribution
	SecretDist SecretDistribution
	// FailureProb is the approximate log2 of failure probability
	FailureProb int
}

// Standard security parameter sets matching OpenFHE
// These are the recommended parameter sets for production use
var (
	// STD128_LMKCDEY provides 128-bit classical security with LMKCDEY bootstrapping
	// This is the recommended default for most applications.
	// OpenFHE equivalent: BINFHE_PARAMSET::STD128_LMKCDEY
	STD128_LMKCDEY = SecurityParams{
		Name:          "STD128_LMKCDEY",
		Security:      Security128,
		Method:        MethodLMKCDEY,
		LogQ:          28,
		RingDim:       1024,
		LWEDim:        447,
		BootstrapBase: 32,
		KeySwitchBase: 1024,
		SecretDist:    Gaussian,
		FailureProb:   -55,
	}

	// STD128Q_LMKCDEY provides 128-bit post-quantum security
	// Use this for applications requiring quantum resistance.
	// OpenFHE equivalent: BINFHE_PARAMSET::STD128Q_LMKCDEY
	STD128Q_LMKCDEY = SecurityParams{
		Name:          "STD128Q_LMKCDEY",
		Security:      Security128Q,
		Method:        MethodLMKCDEY,
		LogQ:          27,
		RingDim:       1024,
		LWEDim:        483,
		BootstrapBase: 32,
		KeySwitchBase: 512,
		SecretDist:    Gaussian,
		FailureProb:   -50,
	}

	// STD192_LMKCDEY provides 192-bit classical security
	// Higher security with larger parameters.
	// OpenFHE equivalent: BINFHE_PARAMSET::STD192_LMKCDEY
	STD192_LMKCDEY = SecurityParams{
		Name:          "STD192_LMKCDEY",
		Security:      Security192,
		Method:        MethodLMKCDEY,
		LogQ:          39,
		RingDim:       2048,
		LWEDim:        716,
		BootstrapBase: 32,
		KeySwitchBase: 1048576,
		SecretDist:    Gaussian,
		FailureProb:   -60,
	}

	// STD192Q_LMKCDEY provides 192-bit post-quantum security
	// OpenFHE equivalent: BINFHE_PARAMSET::STD192Q_LMKCDEY
	STD192Q_LMKCDEY = SecurityParams{
		Name:          "STD192Q_LMKCDEY",
		Security:      Security192Q,
		Method:        MethodLMKCDEY,
		LogQ:          36,
		RingDim:       2048,
		LWEDim:        776,
		BootstrapBase: 32,
		KeySwitchBase: 262144,
		SecretDist:    Gaussian,
		FailureProb:   -70,
	}

	// STD256_LMKCDEY provides 256-bit classical security
	// Maximum security level.
	// OpenFHE equivalent: BINFHE_PARAMSET::STD256_LMKCDEY
	STD256_LMKCDEY = SecurityParams{
		Name:          "STD256_LMKCDEY",
		Security:      Security256,
		Method:        MethodLMKCDEY,
		LogQ:          30,
		RingDim:       2048,
		LWEDim:        939,
		BootstrapBase: 32,
		KeySwitchBase: 1024,
		SecretDist:    Gaussian,
		FailureProb:   -50,
	}

	// STD256Q_LMKCDEY provides 256-bit post-quantum security
	// Maximum security with quantum resistance.
	// OpenFHE equivalent: BINFHE_PARAMSET::STD256Q_LMKCDEY
	STD256Q_LMKCDEY = SecurityParams{
		Name:          "STD256Q_LMKCDEY",
		Security:      Security256Q,
		Method:        MethodLMKCDEY,
		LogQ:          28,
		RingDim:       2048,
		LWEDim:        1019,
		BootstrapBase: 32,
		KeySwitchBase: 1024,
		SecretDist:    Gaussian,
		FailureProb:   -60,
	}
)

// AllSecurityParams returns all available security parameter sets
func AllSecurityParams() []SecurityParams {
	return []SecurityParams{
		STD128_LMKCDEY,
		STD128Q_LMKCDEY,
		STD192_LMKCDEY,
		STD192Q_LMKCDEY,
		STD256_LMKCDEY,
		STD256Q_LMKCDEY,
	}
}

// GetSecurityParams returns the SecurityParams for a given name
func GetSecurityParams(name string) (SecurityParams, bool) {
	for _, p := range AllSecurityParams() {
		if p.Name == name {
			return p, true
		}
	}
	return SecurityParams{}, false
}

// ToParametersLiteral converts SecurityParams to ParametersLiteral
// for use with the existing FHE implementation
func (sp SecurityParams) ToParametersLiteral() ParametersLiteral {
	// Calculate Q from LogQ
	q := uint64(1) << sp.LogQ

	// For compatibility with existing code, we use ring dimension for both
	// LWE and BR when they match OpenFHE's LMKCDEY parameters
	logN := 0
	for n := sp.RingDim; n > 1; n >>= 1 {
		logN++
	}

	return ParametersLiteral{
		LogNLWE:              logN,
		LogNBR:               logN,
		QLWE:                 q,
		QBR:                  q,
		BaseTwoDecomposition: 5, // log2(32) = 5 for LMKCDEY
	}
}
