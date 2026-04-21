// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Encrypted compliance — illustrative Solidity interface
//
// This file is the on-chain twin of `./main.go` in this directory. It is
// intentionally illustrative — not a production contract and not meant to
// deploy as-is — and its purpose is to show reviewers how the gates the Go
// demo evaluates against luxfi/fhe directly would be expressed on the EVM
// side via the luxfi/precompile FHE address space documented in
// `LLM.md` § "Native luxd Integration".
//
// Precompile address convention used here:
//   Unified FHE API reserves the `0x02000000...00XX` range for FHE operations
//   (see `LLM.md` lines 534 and 499–503). The low byte identifies the
//   operation. Exact low bytes below are representative; if the maintainers
//   wire these demos into a deployable test contract the constants should
//   be pulled from `@luxfi/contracts/contracts/fhe/FHE.sol` rather than
//   hard-coded.
// -----------------------------------------------------------------------------

/// Opaque handle to an encrypted 8-bit unsigned integer, as produced by
/// `FHE.asEuint8(bytes)` or `FHE.trivialEncrypt(uint256, ctType)`.
type euint8 is bytes32;

/// Opaque handle to an encrypted boolean.
type ebool is bytes32;

/// Minimal interface against the luxfi/precompile FHE surface. Real calls
/// from Solidity go through `FHE.sol` / `IFHE.sol` in `@luxfi/contracts`;
/// we reproduce only the signatures exercised by this demo for clarity.
interface IFHEPrecompile {
    // --- 0x02000000...0020  FHEGe  — encrypted a >= b on euint8
    function ge(euint8 a, euint8 b) external view returns (ebool);

    // --- 0x02000000...0022  FHELt  — encrypted a < b on euint8
    function lt(euint8 a, euint8 b) external view returns (ebool);

    // --- 0x02000000...0024  FHENe  — encrypted a != b on euint8
    function ne(euint8 a, euint8 b) external view returns (ebool);

    // --- 0x02000000...0030  FHEAnd — encrypted boolean AND
    function and_(ebool a, ebool b) external view returns (ebool);

    // --- 0x02000000...0040  TrivialEncrypt — public plaintext → ciphertext
    //     under the network's bootstrap key (used for embedding policy
    //     constants like `minIncome` without leaking who submitted them).
    function trivialEncrypt8(uint8 v) external view returns (euint8);

    // --- 0x02000000...0083  IFHEDecrypt.decrypt
    //     Request asynchronous threshold decryption; returns a request id
    //     the caller polls with `reveal`. See `LLM.md` line 534.
    function decrypt(ebool handle) external returns (bytes32 requestId);

    // --- 0x02000000...0083  IFHEDecrypt.reveal
    //     Fetch the plaintext once the decryption committee has posted it.
    //     Reverts if not yet ready.
    function reveal(bytes32 requestId) external view returns (bool value, bool ready);
}

/// EncryptedCompliance is the Solidity analogue of `./main.go`. It takes
/// four encrypted 8-bit inputs, runs the same three gates the Go demo
/// runs, and emits either the ciphertext of `overall` (for downstream
/// contracts to keep composing on it) or a decrypt request id (for the
/// off-chain committee to reveal the final boolean to a user).
contract EncryptedCompliance {
    IFHEPrecompile public immutable fhe;

    event GateEvaluated(
        address indexed caller,
        ebool incomeOK,
        ebool jurisdictionOK,
        ebool overall
    );

    event DecryptRequested(address indexed caller, bytes32 requestId);

    constructor(IFHEPrecompile _fhe) {
        fhe = _fhe;
    }

    /// Mirror of the Go `encrypted-compliance` demo.
    ///
    /// `encIncome` and `encJurisdiction` are client-encrypted handles
    /// (the applicant's private data, known only to the applicant and to
    /// the decryption committee). `minIncome` and `blockedJurisdiction`
    /// are public policy constants and we use `trivialEncrypt8` to lift
    /// them into ciphertext space so that the same precompile signatures
    /// apply.
    function check(
        euint8 encIncome,
        euint8 encJurisdiction,
        uint8 minIncome,
        uint8 blockedJurisdiction
    ) external returns (ebool incomeOK, ebool jurisdictionOK, ebool overall) {
        // Lift policy constants into ciphertext space. No secret is leaked:
        // the precompile uses a deterministic trivial-encryption under the
        // public bootstrap key.
        euint8 encMinIncome = fhe.trivialEncrypt8(minIncome);
        euint8 encBlocked = fhe.trivialEncrypt8(blockedJurisdiction);

        // Gate 1: income >= minIncome.  Go equivalent: geEncrypted().
        incomeOK = fhe.ge(encIncome, encMinIncome);

        // Gate 2: jurisdiction != blocked. Go equivalent: neEncrypted().
        jurisdictionOK = fhe.ne(encJurisdiction, encBlocked);

        // Gate 3: incomeOK AND jurisdictionOK. Go equivalent: eval.AND().
        overall = fhe.and_(incomeOK, jurisdictionOK);

        emit GateEvaluated(msg.sender, incomeOK, jurisdictionOK, overall);
    }

    /// Request asynchronous threshold decryption of a ciphertext booleaned.
    /// Caller polls `revealResult(requestId)` until `ready == true`.
    function requestReveal(ebool handle) external returns (bytes32 requestId) {
        requestId = fhe.decrypt(handle);
        emit DecryptRequested(msg.sender, requestId);
    }

    /// Poll for the decrypted boolean. Reverts if the committee hasn't
    /// posted it yet; use `revealSafe`-style handling in production.
    function revealResult(bytes32 requestId) external view returns (bool) {
        (bool value, bool ready) = fhe.reveal(requestId);
        require(ready, "decryption not ready");
        return value;
    }
}
