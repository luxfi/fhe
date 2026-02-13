// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@luxfhe/luxfhe-contracts/FHE.sol";

/// @title DataSeal - Verifiable Data Integrity Seal Protocol
/// @notice FHE-encrypted tamper-proof document sealing with three seal modes
/// @dev Implements PIP-0010 / LP-0535: Public, ZK, and Private (FHE) seals
contract DataSeal {
    /// @notice Seal modes matching PIP-0010 specification
    enum SealMode {
        Public,  // Fully transparent, anyone can verify
        ZK,      // Content hidden, properties provable via ZK
        Private  // FHE-encrypted with selective disclosure
    }

    struct Seal {
        bytes32 contentHash;      // SHA-256 of original content
        euint32 encryptedTag;     // FHE-encrypted integrity tag
        address creator;          // Seal creator
        uint256 timestamp;        // Block timestamp at creation
        SealMode mode;            // Seal type
        bool revoked;             // Revocation status
    }

    /// @notice All seals indexed by ID
    mapping(uint256 => Seal) public seals;
    uint256 public sealCount;

    /// @notice Batch seal tracking
    mapping(bytes32 => uint256[]) public batchSeals; // batchId => sealIds

    /// @notice Seal verification results (encrypted)
    mapping(uint256 => euint32) private verificationResults;

    event SealCreated(uint256 indexed sealId, address indexed creator, SealMode mode, bytes32 contentHash);
    event SealVerified(uint256 indexed sealId, address indexed verifier);
    event SealRevoked(uint256 indexed sealId, address indexed revoker);
    event BatchSealed(bytes32 indexed batchId, uint256 sealCount);

    /// @notice Create a new data integrity seal
    /// @param contentHash SHA-256 hash of the content being sealed
    /// @param encryptedTag FHE-encrypted integrity tag (creator's secret)
    /// @param mode Seal mode: Public, ZK, or Private
    /// @return sealId The ID of the newly created seal
    function createSeal(
        bytes32 contentHash,
        inEuint32 calldata encryptedTag,
        SealMode mode
    ) external returns (uint256 sealId) {
        sealId = sealCount++;

        euint32 tag = FHE.asEuint32(encryptedTag);
        FHE.allowThis(tag);
        FHE.allow(tag, msg.sender);

        seals[sealId] = Seal({
            contentHash: contentHash,
            encryptedTag: tag,
            creator: msg.sender,
            timestamp: block.timestamp,
            mode: mode,
            revoked: false
        });

        emit SealCreated(sealId, msg.sender, mode, contentHash);
    }

    /// @notice Verify a seal by comparing encrypted tags homomorphically
    /// @param sealId The seal to verify
    /// @param challengeTag Encrypted tag from the verifier
    /// @dev Result is FHE-encrypted: 1 = match, 0 = mismatch
    function verifySeal(
        uint256 sealId,
        inEuint32 calldata challengeTag
    ) external {
        Seal storage seal = seals[sealId];
        require(!seal.revoked, "Seal revoked");

        euint32 challenge = FHE.asEuint32(challengeTag);

        // Homomorphic equality check: encrypted comparison
        // If tags match, result = 1; otherwise result = 0
        ebool isEqual = FHE.eq(seal.encryptedTag, challenge);
        euint32 result = FHE.select(isEqual, FHE.asEuint32(1), FHE.asEuint32(0));

        FHE.allowThis(result);
        FHE.allow(result, msg.sender);
        verificationResults[sealId] = result;

        // Request decryption for the verifier
        FHE.decrypt(result);

        emit SealVerified(sealId, msg.sender);
    }

    /// @notice Get the decrypted verification result
    /// @param sealId The seal that was verified
    /// @return matched Whether the verification passed
    /// @return ready Whether the decryption is complete
    function getVerificationResult(uint256 sealId) external view returns (bool matched, bool ready) {
        euint32 result = verificationResults[sealId];
        (uint256 value, bool decrypted) = FHE.getDecryptResultSafe(result);
        return (value == 1, decrypted);
    }

    /// @notice Create multiple seals in a single transaction (batch sealing)
    /// @param contentHashes Array of content hashes
    /// @param encryptedTags Array of encrypted integrity tags
    /// @param mode Seal mode for all seals in the batch
    /// @return batchId Identifier for the batch
    function batchSeal(
        bytes32[] calldata contentHashes,
        inEuint32[] calldata encryptedTags,
        SealMode mode
    ) external returns (bytes32 batchId) {
        require(contentHashes.length == encryptedTags.length, "Length mismatch");
        require(contentHashes.length > 0, "Empty batch");

        batchId = keccak256(abi.encodePacked(msg.sender, block.timestamp, sealCount));
        uint256[] storage ids = batchSeals[batchId];

        for (uint256 i = 0; i < contentHashes.length; i++) {
            uint256 sealId = sealCount++;

            euint32 tag = FHE.asEuint32(encryptedTags[i]);
            FHE.allowThis(tag);
            FHE.allow(tag, msg.sender);

            seals[sealId] = Seal({
                contentHash: contentHashes[i],
                encryptedTag: tag,
                creator: msg.sender,
                timestamp: block.timestamp,
                mode: mode,
                revoked: false
            });

            ids.push(sealId);
            emit SealCreated(sealId, msg.sender, mode, contentHashes[i]);
        }

        emit BatchSealed(batchId, contentHashes.length);
    }

    /// @notice Revoke a seal (only creator can revoke)
    /// @param sealId The seal to revoke
    function revokeSeal(uint256 sealId) external {
        Seal storage seal = seals[sealId];
        require(seal.creator == msg.sender, "Not seal creator");
        require(!seal.revoked, "Already revoked");

        seal.revoked = true;
        emit SealRevoked(sealId, msg.sender);
    }

    /// @notice Get seal metadata (public fields only)
    function getSeal(uint256 sealId) external view returns (
        bytes32 contentHash,
        address creator,
        uint256 timestamp,
        SealMode mode,
        bool revoked
    ) {
        Seal storage seal = seals[sealId];
        return (seal.contentHash, seal.creator, seal.timestamp, seal.mode, seal.revoked);
    }

    /// @notice Get all seal IDs in a batch
    function getBatchSeals(bytes32 batchId) external view returns (uint256[] memory) {
        return batchSeals[batchId];
    }
}
