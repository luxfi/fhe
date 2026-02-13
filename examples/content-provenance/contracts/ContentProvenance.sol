// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@luxfhe/luxfhe-contracts/FHE.sol";

/// @title ContentProvenance - AI & Media Content Provenance
/// @notice Tracks provenance of AI models, outputs, and media with FHE privacy
/// @dev Implements PIP-0011 / LP-7110: Model sealing, output attestation, media auth
contract ContentProvenance {
    /// @notice Content types
    enum ContentType {
        AIModel,       // Neural network model weights/architecture
        AIOutput,      // Generated content from a model
        MediaCapture,  // Point-of-capture media (photo, video, audio)
        MediaEdit,     // Edited derivative of existing media
        Document       // Text document
    }

    /// @notice A registered content item
    struct ContentRecord {
        bytes32 contentHash;       // SHA-256 of content
        ContentType contentType;   // Type of content
        address creator;           // Who registered it
        uint256 timestamp;         // When registered
        uint256 parentId;          // 0 if original, else parent record ID
        euint32 encryptedModelId;  // FHE-encrypted model identifier (for AI outputs)
        bool exists;
    }

    /// @notice Model manifest for AI provenance
    struct ModelManifest {
        bytes32 weightsHash;       // Hash of model weights
        bytes32 architectureHash;  // Hash of architecture spec
        bytes32 trainingDataHash;  // Hash of training dataset description
        address registrant;        // Who registered the model
        uint256 timestamp;
        euint32 encryptedVersion;  // FHE-encrypted version (IP protection)
    }

    /// @notice All content records
    mapping(uint256 => ContentRecord) public records;
    uint256 public recordCount;

    /// @notice Model manifests
    mapping(uint256 => ModelManifest) public models;
    uint256 public modelCount;

    /// @notice Provenance chain: contentId => child IDs
    mapping(uint256 => uint256[]) public derivations;

    /// @notice Attestation results
    mapping(uint256 => euint32) private attestationResults;

    event ContentRegistered(uint256 indexed id, ContentType contentType, address indexed creator, bytes32 contentHash);
    event ModelRegistered(uint256 indexed modelId, address indexed registrant, bytes32 weightsHash);
    event OutputAttested(uint256 indexed outputId, uint256 indexed modelId);
    event DerivationRecorded(uint256 indexed parentId, uint256 indexed childId);

    /// @notice Register an AI model manifest
    /// @param weightsHash Hash of model weights
    /// @param architectureHash Hash of architecture
    /// @param trainingDataHash Hash of training data description
    /// @param encryptedVersion FHE-encrypted version number (protects IP)
    /// @return modelId The registered model ID
    function registerModel(
        bytes32 weightsHash,
        bytes32 architectureHash,
        bytes32 trainingDataHash,
        inEuint32 calldata encryptedVersion
    ) external returns (uint256 modelId) {
        modelId = modelCount++;

        euint32 version = FHE.asEuint32(encryptedVersion);
        FHE.allowThis(version);
        FHE.allow(version, msg.sender);

        models[modelId] = ModelManifest({
            weightsHash: weightsHash,
            architectureHash: architectureHash,
            trainingDataHash: trainingDataHash,
            registrant: msg.sender,
            timestamp: block.timestamp,
            encryptedVersion: version
        });

        emit ModelRegistered(modelId, msg.sender, weightsHash);
    }

    /// @notice Register content (media, document, or AI output)
    /// @param contentHash Hash of the content
    /// @param contentType Type of content being registered
    /// @param parentId Parent content ID (0 for originals)
    /// @param encryptedModelId FHE-encrypted model ID (for AI outputs)
    /// @return contentId The registered content ID
    function registerContent(
        bytes32 contentHash,
        ContentType contentType,
        uint256 parentId,
        inEuint32 calldata encryptedModelId
    ) external returns (uint256 contentId) {
        contentId = recordCount++;

        euint32 modelId = FHE.asEuint32(encryptedModelId);
        FHE.allowThis(modelId);
        FHE.allow(modelId, msg.sender);

        records[contentId] = ContentRecord({
            contentHash: contentHash,
            contentType: contentType,
            creator: msg.sender,
            timestamp: block.timestamp,
            parentId: parentId,
            encryptedModelId: modelId,
            exists: true
        });

        // Track derivation chain
        if (parentId > 0 && records[parentId].exists) {
            derivations[parentId].push(contentId);
            emit DerivationRecorded(parentId, contentId);
        }

        emit ContentRegistered(contentId, contentType, msg.sender, contentHash);
    }

    /// @notice Attest that an AI output was produced by a specific model
    /// @dev Homomorphic comparison of encrypted model IDs
    /// @param outputId The content record to attest
    /// @param claimedModelId FHE-encrypted model ID to verify against
    function attestOutput(
        uint256 outputId,
        inEuint32 calldata claimedModelId
    ) external {
        require(records[outputId].exists, "Content not found");

        euint32 claimed = FHE.asEuint32(claimedModelId);

        // Homomorphic equality check
        ebool isMatch = FHE.eq(records[outputId].encryptedModelId, claimed);
        euint32 result = FHE.select(isMatch, FHE.asEuint32(1), FHE.asEuint32(0));

        FHE.allowThis(result);
        FHE.allow(result, msg.sender);
        attestationResults[outputId] = result;

        FHE.decrypt(result);
        emit OutputAttested(outputId, outputId);
    }

    /// @notice Get attestation result
    function getAttestationResult(uint256 outputId) external view returns (bool attested, bool ready) {
        euint32 result = attestationResults[outputId];
        (uint256 value, bool decrypted) = FHE.getDecryptResultSafe(result);
        return (value == 1, decrypted);
    }

    /// @notice Get content record metadata
    function getRecord(uint256 contentId) external view returns (
        bytes32 contentHash,
        ContentType contentType,
        address creator,
        uint256 timestamp,
        uint256 parentId
    ) {
        ContentRecord storage r = records[contentId];
        require(r.exists, "Not found");
        return (r.contentHash, r.contentType, r.creator, r.timestamp, r.parentId);
    }

    /// @notice Get the full derivation chain for content
    function getDerivations(uint256 contentId) external view returns (uint256[] memory) {
        return derivations[contentId];
    }

    /// @notice Get model manifest metadata
    function getModel(uint256 modelId) external view returns (
        bytes32 weightsHash,
        bytes32 architectureHash,
        bytes32 trainingDataHash,
        address registrant,
        uint256 timestamp
    ) {
        ModelManifest storage m = models[modelId];
        return (m.weightsHash, m.architectureHash, m.trainingDataHash, m.registrant, m.timestamp);
    }
}
