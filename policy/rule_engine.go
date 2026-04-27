// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Rule engine: a small declarative DSL that compiles a YAML policy
// document to an executable RulePlan against luxfi/fhe primitives.
//
// The DSL is intentionally narrow. It expresses exactly the ops F-Chain
// PolicyVault clauses need today — strict-less-than, less-than-or-equal,
// equality, set membership, and an AND/OR reduction across clauses.
// Arithmetic, multiplication, scalar fold, and signed integers are
// out of scope; they are the job of the general FHE evaluator, not a
// policy gate.
//
// Compilation is one-shot per (policy_id, policy_hash) and is cached in
// plan_cache.go. The compiled plan is read-only and safe to share across
// goroutines; per-evaluation state lives entirely in the input map and
// the per-step intermediates slice.

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/luxfi/fhe"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the YAML schema version this engine accepts. Bumping
// the schema version requires a new field in YAMLDocument, not an
// override of an existing field.
const SchemaVersion = "1"

// Op is the small enumerated set of operations a clause may use. Adding
// a new op is a deliberate change: it requires a Step.run case + a
// validate-time entry in opArity.
type Op string

const (
	OpLt  Op = "lt"  // field < constant
	OpLte Op = "lte" // field <= constant
	OpEq  Op = "eq"  // field == constant
	OpIn  Op = "in"  // field ∈ {constants...}
)

// Combinator selects how clause verdicts reduce to one verdict.
type Combinator string

const (
	CombAnd Combinator = "and" // all clauses must pass
	CombOr  Combinator = "or"  // any clause may pass
)

// FieldWidth declares the bit-width of the integer-valued field/constant
// operands in a clause. The width must match the BitCiphertext.Type() of
// the encrypted operand at runtime; mismatch is a configuration bug and
// is rejected at evaluation time by luxfi/fhe.
type FieldWidth string

const (
	WidthU4   FieldWidth = "u4"
	WidthU8   FieldWidth = "u8"
	WidthU16  FieldWidth = "u16"
	WidthU32  FieldWidth = "u32"
	WidthU64  FieldWidth = "u64"
	WidthU128 FieldWidth = "u128"
	WidthU160 FieldWidth = "u160" // address-shaped fields
	WidthU256 FieldWidth = "u256"
)

// FheType maps a declared FieldWidth to the matching luxfi/fhe type. A
// blank or unknown width returns 0 / FheBool which is rejected when the
// operand width is checked at runtime.
func (w FieldWidth) FheType() fhe.FheUintType {
	switch w {
	case WidthU4:
		return fhe.FheUint4
	case WidthU8:
		return fhe.FheUint8
	case WidthU16:
		return fhe.FheUint16
	case WidthU32:
		return fhe.FheUint32
	case WidthU64:
		return fhe.FheUint64
	case WidthU128:
		return fhe.FheUint128
	case WidthU160:
		return fhe.FheUint160
	case WidthU256:
		return fhe.FheUint256
	}
	return fhe.FheBool
}

// YAMLClause is the on-disk shape of a single clause. Authors hand-edit
// these or generate them from a higher-level policy compiler.
type YAMLClause struct {
	Name       string     `yaml:"name"`
	Op         Op         `yaml:"op"`
	Field      string     `yaml:"field"`
	Constant   string     `yaml:"constant,omitempty"`
	Constants  []string   `yaml:"constants,omitempty"`
	FieldWidth FieldWidth `yaml:"field_width"`
}

// YAMLDocument is the top-level policy document.
type YAMLDocument struct {
	SchemaVersion string       `yaml:"rule_engine_version"`
	PolicyID      string       `yaml:"policy_id"`
	Clauses       []YAMLClause `yaml:"clauses"`
	Combinator    Combinator   `yaml:"combinator"`
}

// EvaluationStep is one compiled clause. The executor walks Steps in
// order; each Step produces a single encrypted boolean. The terminal
// reduction (AND/OR across all Step results) is performed by the
// executor — Steps never reduce against each other.
//
// EvaluationStep is read-only after Compile; do not mutate fields from
// callers.
type EvaluationStep struct {
	Name       string
	Op         Op
	FieldKey   string   // input map key
	ConstKey   string   // constant map key (lt/lte/eq) — empty for "in"
	ConstKeys  []string // constant map keys (in)
	FieldWidth FieldWidth
}

// RulePlan is a compiled, read-only policy program.
type RulePlan struct {
	Version    string
	PolicyID   string
	PolicyHash [32]byte
	Steps      []EvaluationStep
	Combinator Combinator

	// rawYAML is retained so the plan can be re-hashed deterministically
	// or re-emitted for audit trails. It is not used during evaluation.
	rawYAML []byte
}

// HashYAML returns the canonical sha256 of the YAML bytes used to compile
// the plan. This is the same hash the cache keys on.
func HashYAML(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// Compile parses YAML and returns a ready-to-evaluate RulePlan. The
// PolicyHash is the sha256 of the input bytes — callers MUST pass the
// same canonical bytes used by F-Chain so cache keys agree.
//
// Compile is deterministic: equivalent inputs produce equivalent plans.
// Failures are returned as errors; this never panics.
func Compile(data []byte) (*RulePlan, error) {
	if len(data) == 0 {
		return nil, errors.New("rule_engine: empty policy document")
	}
	var doc YAMLDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("rule_engine: yaml: %w", err)
	}
	if err := validate(&doc); err != nil {
		return nil, err
	}
	steps := make([]EvaluationStep, len(doc.Clauses))
	for i, c := range doc.Clauses {
		steps[i] = EvaluationStep{
			Name:       c.Name,
			Op:         c.Op,
			FieldKey:   c.Field,
			ConstKey:   c.Constant,
			ConstKeys:  append([]string(nil), c.Constants...),
			FieldWidth: c.FieldWidth,
		}
	}
	return &RulePlan{
		Version:    doc.SchemaVersion,
		PolicyID:   doc.PolicyID,
		PolicyHash: HashYAML(data),
		Steps:      steps,
		Combinator: doc.Combinator,
		rawYAML:    append([]byte(nil), data...),
	}, nil
}

// validate enforces structural invariants the executor relies on.
//
//   - schema version equals SchemaVersion
//   - policy_id non-empty
//   - clauses non-empty
//   - each clause has a recognised op + matching operand shape
//   - combinator is "and" or "or"
//
// Reaching the executor requires passing validate; the executor does
// not re-check these invariants on the hot path.
func validate(doc *YAMLDocument) error {
	if doc.SchemaVersion != SchemaVersion {
		return fmt.Errorf("rule_engine: unsupported schema version %q (want %q)", doc.SchemaVersion, SchemaVersion)
	}
	if doc.PolicyID == "" {
		return errors.New("rule_engine: policy_id required")
	}
	if len(doc.Clauses) == 0 {
		return errors.New("rule_engine: at least one clause required")
	}
	switch doc.Combinator {
	case CombAnd, CombOr:
	default:
		return fmt.Errorf("rule_engine: unknown combinator %q", doc.Combinator)
	}
	for i, c := range doc.Clauses {
		if c.Name == "" {
			return fmt.Errorf("rule_engine: clause[%d]: name required", i)
		}
		if c.Field == "" {
			return fmt.Errorf("rule_engine: clause[%d] %q: field required", i, c.Name)
		}
		if c.FieldWidth.FheType() == fhe.FheBool {
			return fmt.Errorf("rule_engine: clause[%d] %q: unknown field_width %q", i, c.Name, c.FieldWidth)
		}
		switch c.Op {
		case OpLt, OpLte, OpEq:
			if c.Constant == "" {
				return fmt.Errorf("rule_engine: clause[%d] %q: constant required for op %q", i, c.Name, c.Op)
			}
			if len(c.Constants) != 0 {
				return fmt.Errorf("rule_engine: clause[%d] %q: constants forbidden for op %q (use constant)", i, c.Name, c.Op)
			}
		case OpIn:
			if c.Constant != "" {
				return fmt.Errorf("rule_engine: clause[%d] %q: constant forbidden for op in (use constants)", i, c.Name)
			}
			if len(c.Constants) == 0 {
				return fmt.Errorf("rule_engine: clause[%d] %q: at least one constants entry required for op in", i, c.Name)
			}
		default:
			return fmt.Errorf("rule_engine: clause[%d] %q: unknown op %q", i, c.Name, c.Op)
		}
	}
	return nil
}
