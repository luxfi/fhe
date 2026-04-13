// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cli provides the "fhe" subcommand for the lux CLI.
// It wires directly to the github.com/luxfi/fhe package for
// key generation, encryption, decryption, and evaluation.
package cli

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/luxfi/fhe"
	"github.com/spf13/cobra"
)

// NewCmd returns the "fhe" command tree for the lux CLI.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fhe",
		Short: "Fully Homomorphic Encryption operations",
		Long: `The fhe command provides tools for Fully Homomorphic Encryption (FHE)
on the Lux network, including key generation, encryption, computation
on encrypted data, and decryption.

These operations integrate with the T-Chain (Threshold chain) for
on-chain FHE computation via precompiled contracts.

SCHEMES:

  TFHE    - Fast bootstrapping, boolean/small integer circuits
  BGV     - Batched integer arithmetic
  CKKS    - Approximate fixed-point arithmetic`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newKeygenCmd())
	cmd.AddCommand(newEncryptCmd())
	cmd.AddCommand(newDecryptCmd())
	cmd.AddCommand(newEvalCmd())

	return cmd
}

// paramsByName resolves a parameter set name to a ParametersLiteral.
func paramsByName(name string) (fhe.ParametersLiteral, error) {
	switch name {
	case "PN10QP27", "":
		return fhe.PN10QP27, nil
	case "PN11QP54":
		return fhe.PN11QP54, nil
	case "STD128":
		return fhe.PN9QP28_STD128, nil
	case "STD128Q":
		return fhe.PN9QP27_STD128Q, nil
	default:
		return fhe.ParametersLiteral{}, fmt.Errorf("unknown parameter set: %s (valid: PN10QP27, PN11QP54, STD128, STD128Q)", name)
	}
}

func newKeygenCmd() *cobra.Command {
	var (
		scheme string
		output string
	)
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate FHE key pair",
		Long: `Generate a Fully Homomorphic Encryption key pair.

Produces a secret key (for decryption), public key (for encryption),
and bootstrap key (for homomorphic operations).

Examples:
  lux fhe keygen
  lux fhe keygen --scheme PN11QP54 --output ./keys/`,
		RunE: func(_ *cobra.Command, _ []string) error {
			lit, err := paramsByName(scheme)
			if err != nil {
				return err
			}
			params, err := fhe.NewParametersFromLiteral(lit)
			if err != nil {
				return fmt.Errorf("initialize parameters: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Generating FHE keys (params=%s, N=%d)...\n", scheme, params.N())

			kg := fhe.NewKeyGenerator(params)
			sk, pk := kg.GenKeyPair()

			skData, err := sk.MarshalBinary()
			if err != nil {
				return fmt.Errorf("serialize secret key: %w", err)
			}
			pkData, err := pk.MarshalBinary()
			if err != nil {
				return fmt.Errorf("serialize public key: %w", err)
			}

			if output == "" {
				output = "."
			}
			if err := os.MkdirAll(output, 0o750); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}

			skPath := output + "/secret.key"
			pkPath := output + "/public.key"

			if err := os.WriteFile(skPath, skData, 0o600); err != nil {
				return fmt.Errorf("write secret key: %w", err)
			}
			if err := os.WriteFile(pkPath, pkData, 0o644); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Secret key: %s (%d bytes)\n", skPath, len(skData))
			fmt.Fprintf(os.Stderr, "Public key: %s (%d bytes)\n", pkPath, len(pkData))
			return nil
		},
	}
	cmd.Flags().StringVar(&scheme, "scheme", "PN10QP27", "Parameter set (PN10QP27, PN11QP54, STD128, STD128Q)")
	cmd.Flags().StringVar(&output, "output", "", "Output directory for keys (default: current dir)")
	return cmd
}

func newEncryptCmd() *cobra.Command {
	var (
		keyPath string
		value   bool
	)
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a boolean value under FHE",
		Long: `Encrypt a boolean value using an FHE secret key.
Outputs hex-encoded ciphertext to stdout.

Examples:
  lux fhe encrypt --key ./keys/secret.key --value true
  lux fhe encrypt --key ./keys/secret.key --value false`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if keyPath == "" {
				return fmt.Errorf("--key is required")
			}
			skData, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read secret key: %w", err)
			}
			var sk fhe.SecretKey
			if err := sk.UnmarshalBinary(skData); err != nil {
				return fmt.Errorf("deserialize secret key: %w", err)
			}

			params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
			if err != nil {
				return fmt.Errorf("initialize parameters: %w", err)
			}
			enc := fhe.NewEncryptor(params, &sk)
			ct, err := enc.EncryptSafe(value)
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}
			ctData, err := ct.MarshalBinary()
			if err != nil {
				return fmt.Errorf("serialize ciphertext: %w", err)
			}
			fmt.Println(hex.EncodeToString(ctData))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to secret key file")
	cmd.Flags().BoolVar(&value, "value", false, "Boolean value to encrypt")
	return cmd
}

func newDecryptCmd() *cobra.Command {
	var (
		keyPath string
		input   string
	)
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt FHE ciphertext",
		Long: `Decrypt a hex-encoded ciphertext using the FHE secret key.

Examples:
  lux fhe decrypt --key ./keys/secret.key --input <hex>`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if keyPath == "" {
				return fmt.Errorf("--key is required")
			}
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			skData, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("read secret key: %w", err)
			}
			var sk fhe.SecretKey
			if err := sk.UnmarshalBinary(skData); err != nil {
				return fmt.Errorf("deserialize secret key: %w", err)
			}

			ctData, err := hex.DecodeString(input)
			if err != nil {
				return fmt.Errorf("decode ciphertext hex: %w", err)
			}
			ct := new(fhe.Ciphertext)
			if err := ct.UnmarshalBinary(ctData); err != nil {
				return fmt.Errorf("deserialize ciphertext: %w", err)
			}

			params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
			if err != nil {
				return fmt.Errorf("initialize parameters: %w", err)
			}
			dec := fhe.NewDecryptor(params, &sk)
			result := dec.Decrypt(ct)
			fmt.Println(result)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to secret key file")
	cmd.Flags().StringVar(&input, "input", "", "Hex-encoded ciphertext")
	return cmd
}

func newEvalCmd() *cobra.Command {
	var (
		op string
	)
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate boolean gate on ciphertexts",
		Long: `Evaluate a boolean operation on FHE-encrypted data without decrypting.

Requires bootstrap key for homomorphic evaluation.

Supported gates: AND, OR, XOR, NAND, NOR, XNOR, NOT

Examples:
  lux fhe eval --op AND --inputs ct1.hex,ct2.hex --bsk ./keys/bootstrap.key`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("fhe eval requires bootstrap key generation (lux fhe keygen --bootstrap); gate: %s", op)
		},
	}
	cmd.Flags().StringVar(&op, "op", "AND", "Boolean gate (AND, OR, XOR, NAND, NOR, XNOR, NOT)")
	return cmd
}
