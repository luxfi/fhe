// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@luxfhe/luxfhe-contracts/FHE.sol";

/// @title EncryptedCRDT - FHE-Encrypted Conflict-Free Replicated Data Types
/// @notice Last-Writer-Wins Register and OR-Set with encrypted values
/// @dev Implements PIP-0013 / LP-6500: Privacy-preserving offline-first collaboration
contract EncryptedCRDT {
    /// @notice LWW-Register: encrypted value with Lamport timestamp for conflict resolution
    struct LWWRegister {
        euint32 value;           // FHE-encrypted value
        uint256 timestamp;       // Lamport clock (higher wins)
        address lastWriter;      // Who last wrote
        bytes32 documentId;      // Parent document
        bool exists;
    }

    /// @notice OR-Set element: encrypted value with unique tag for add/remove semantics
    struct ORSetElement {
        euint32 value;           // FHE-encrypted element value
        bytes32 uniqueTag;       // Unique tag for add-remove semantics
        bool removed;            // Tombstone flag
    }

    /// @notice LWW Registers indexed by (documentId, fieldName)
    mapping(bytes32 => LWWRegister) public registers;

    /// @notice OR-Set elements indexed by setId
    mapping(bytes32 => ORSetElement[]) public sets;

    /// @notice Merge results for conflict resolution
    mapping(bytes32 => euint32) private mergeResults;

    /// @notice Document receipts counter
    uint256 public operationCount;

    event RegisterUpdated(bytes32 indexed registerId, address indexed writer, uint256 timestamp);
    event SetElementAdded(bytes32 indexed setId, bytes32 uniqueTag);
    event SetElementRemoved(bytes32 indexed setId, bytes32 uniqueTag);
    event RegistersMerged(bytes32 indexed registerId, address indexed merger);

    /// @notice Set a LWW-Register value (higher timestamp wins)
    /// @param registerId Unique register identifier (keccak256 of docId + fieldName)
    /// @param encryptedValue FHE-encrypted new value
    /// @param timestamp Lamport clock value
    /// @param documentId Parent document identifier
    function setRegister(
        bytes32 registerId,
        inEuint32 calldata encryptedValue,
        uint256 timestamp,
        bytes32 documentId
    ) external {
        LWWRegister storage reg = registers[registerId];

        // LWW semantics: only accept if timestamp is higher
        if (reg.exists && timestamp <= reg.timestamp) {
            // Tie-breaking: higher address wins (deterministic)
            if (timestamp == reg.timestamp && msg.sender <= reg.lastWriter) {
                revert("Stale update: lower timestamp or address");
            }
            if (timestamp < reg.timestamp) {
                revert("Stale update: lower timestamp");
            }
        }

        euint32 value = FHE.asEuint32(encryptedValue);
        FHE.allowThis(value);
        FHE.allow(value, msg.sender);

        registers[registerId] = LWWRegister({
            value: value,
            timestamp: timestamp,
            lastWriter: msg.sender,
            documentId: documentId,
            exists: true
        });

        operationCount++;
        emit RegisterUpdated(registerId, msg.sender, timestamp);
    }

    /// @notice Merge two registers homomorphically (take the one with higher timestamp)
    /// @dev Uses FHE.select to pick winner without revealing values
    /// @param registerId1 First register
    /// @param registerId2 Second register (from peer's sync)
    /// @param resultId Where to store the merged result
    function mergeRegisters(
        bytes32 registerId1,
        bytes32 registerId2,
        bytes32 resultId
    ) external {
        LWWRegister storage reg1 = registers[registerId1];
        LWWRegister storage reg2 = registers[registerId2];
        require(reg1.exists && reg2.exists, "Registers must exist");

        // Deterministic merge: higher timestamp wins
        euint32 merged;
        uint256 winnerTs;
        address winnerAddr;

        if (reg1.timestamp > reg2.timestamp) {
            merged = reg1.value;
            winnerTs = reg1.timestamp;
            winnerAddr = reg1.lastWriter;
        } else if (reg2.timestamp > reg1.timestamp) {
            merged = reg2.value;
            winnerTs = reg2.timestamp;
            winnerAddr = reg2.lastWriter;
        } else {
            // Same timestamp: use FHE.select based on address comparison
            if (reg1.lastWriter > reg2.lastWriter) {
                merged = reg1.value;
                winnerAddr = reg1.lastWriter;
            } else {
                merged = reg2.value;
                winnerAddr = reg2.lastWriter;
            }
            winnerTs = reg1.timestamp;
        }

        FHE.allowThis(merged);
        FHE.allow(merged, msg.sender);

        registers[resultId] = LWWRegister({
            value: merged,
            timestamp: winnerTs,
            lastWriter: winnerAddr,
            documentId: reg1.documentId,
            exists: true
        });

        mergeResults[resultId] = merged;
        operationCount++;
        emit RegistersMerged(resultId, msg.sender);
    }

    /// @notice Add an element to an OR-Set
    /// @param setId Set identifier
    /// @param encryptedValue FHE-encrypted element value
    /// @return tag Unique tag for this element (needed for removal)
    function addToSet(
        bytes32 setId,
        inEuint32 calldata encryptedValue
    ) external returns (bytes32 tag) {
        euint32 value = FHE.asEuint32(encryptedValue);
        FHE.allowThis(value);
        FHE.allow(value, msg.sender);

        tag = keccak256(abi.encodePacked(setId, msg.sender, block.timestamp, sets[setId].length));

        sets[setId].push(ORSetElement({
            value: value,
            uniqueTag: tag,
            removed: false
        }));

        operationCount++;
        emit SetElementAdded(setId, tag);
    }

    /// @notice Remove an element from an OR-Set by its unique tag
    /// @param setId Set identifier
    /// @param tag The unique tag of the element to remove
    function removeFromSet(bytes32 setId, bytes32 tag) external {
        ORSetElement[] storage elements = sets[setId];
        for (uint256 i = 0; i < elements.length; i++) {
            if (elements[i].uniqueTag == tag && !elements[i].removed) {
                elements[i].removed = true;
                operationCount++;
                emit SetElementRemoved(setId, tag);
                return;
            }
        }
        revert("Element not found or already removed");
    }

    /// @notice Get the current register value (request decryption)
    /// @param registerId The register to read
    function decryptRegister(bytes32 registerId) external {
        LWWRegister storage reg = registers[registerId];
        require(reg.exists, "Register not found");
        FHE.allow(reg.value, msg.sender);
        FHE.decrypt(reg.value);
    }

    /// @notice Get decrypted register value
    function getDecryptedRegister(bytes32 registerId) external view returns (uint256 value, bool ready) {
        LWWRegister storage reg = registers[registerId];
        require(reg.exists, "Register not found");
        (uint256 v, bool decrypted) = FHE.getDecryptResultSafe(reg.value);
        return (v, decrypted);
    }

    /// @notice Get register metadata
    function getRegisterInfo(bytes32 registerId) external view returns (
        uint256 timestamp,
        address lastWriter,
        bytes32 documentId,
        bool exists
    ) {
        LWWRegister storage reg = registers[registerId];
        return (reg.timestamp, reg.lastWriter, reg.documentId, reg.exists);
    }

    /// @notice Get active (non-removed) element count in an OR-Set
    function getSetSize(bytes32 setId) external view returns (uint256 active) {
        ORSetElement[] storage elements = sets[setId];
        for (uint256 i = 0; i < elements.length; i++) {
            if (!elements[i].removed) active++;
        }
    }
}
