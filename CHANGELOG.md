# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Renamed module from `github.com/luxfi/tfhe` to `github.com/luxfi/fhe`
- Updated Go version requirement to 1.23

### Fixed
- AND/NAND gate test polynomials now use correct threshold comparison
- Carry refresh in ScalarAdd prevents noise accumulation
- WASM SDK build errors resolved
- Code formatting with gofmt

### Added
- Comprehensive test coverage for FHE operations
- Pure Go mode tests (`CGO_ENABLED=0`)
- CGO mode tests with GPU acceleration stubs
- Integer arithmetic tests (Add, Sub, Mul)
- BigInt type tests (uint128, uint160, uint256)
- Serialization tests for keys
- RNG tests for encrypted random number generation
- Adversarial and fuzz tests

## [0.1.0] - 2025-01-01

### Added
- Initial FHE implementation based on TFHE scheme
- Boolean FHE operations (AND, OR, XOR, NOT, NAND, NOR, XNOR, MUX)
- Integer FHE types (FheUint4 through FheUint256)
- Bitwise integer operations with ripple-carry arithmetic
- ShortInt operations with LUT-based evaluation
- Key generation (SecretKey, PublicKey, BootstrapKey)
- Serialization support for all key types
- Multi-SDK support:
  - C shared library
  - Python bindings (via CFFI)
  - Rust bindings (via bindgen)
  - TypeScript/WASM support
- GPU acceleration framework (CUDA via MLX)
- Server mode for FHE-as-a-service
- Comprehensive benchmarks and documentation

[Unreleased]: https://github.com/luxfi/fhe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/luxfi/fhe/releases/tag/v0.1.0
