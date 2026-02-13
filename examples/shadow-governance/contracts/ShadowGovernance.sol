// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@luxfhe/luxfhe-contracts/FHE.sol";

/// @title ShadowGovernance - Anonymous Parallel Governance Protocol
/// @notice Encrypted voting, anonymous proposals, and shadow ministry management
/// @dev Implements PIP-7010: Shadow Government Protocol for pars.vote
contract ShadowGovernance {
    /// @notice Proposal status
    enum ProposalStatus {
        Active,     // Accepting votes
        Tallying,   // Vote period ended, tallying in progress
        Passed,     // Proposal passed
        Rejected,   // Proposal rejected
        Cancelled   // Cancelled by proposer
    }

    /// @notice Ministry (shadow government department)
    struct Ministry {
        bytes32 name;            // Ministry name hash
        bytes32 descriptionHash; // Description hash
        uint256 memberCount;     // Number of members
        bool active;
    }

    /// @notice Governance proposal
    struct Proposal {
        bytes32 contentHash;     // Hash of proposal content (stored off-chain)
        bytes32 ministryId;      // Which ministry this belongs to
        uint256 voteDeadline;    // Block number when voting ends
        euint32 yesVotes;        // FHE-encrypted yes vote count
        euint32 noVotes;         // FHE-encrypted no vote count
        uint256 voterCount;      // Number of voters (public for quorum)
        ProposalStatus status;
        address proposer;        // Anonymous via relay
    }

    /// @notice All proposals
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    /// @notice Ministries
    mapping(bytes32 => Ministry) public ministries;
    bytes32[] public ministryIds;

    /// @notice Double-vote prevention via nullifiers (hashed commitments)
    mapping(uint256 => mapping(bytes32 => bool)) public nullifiers;

    /// @notice Tally results
    mapping(uint256 => euint32) private tallyResults;

    /// @notice Quorum: minimum voters needed (as percentage * 100)
    uint256 public quorumBps = 1000; // 10%

    /// @notice Total registered participants
    uint256 public totalParticipants;

    /// @notice Governance admin (multisig in production)
    address public admin;

    event MinistryCreated(bytes32 indexed ministryId, bytes32 name);
    event ProposalCreated(uint256 indexed proposalId, bytes32 indexed ministryId, bytes32 contentHash);
    event VoteCast(uint256 indexed proposalId, bytes32 nullifier);
    event TallyStarted(uint256 indexed proposalId);
    event ProposalFinalized(uint256 indexed proposalId, ProposalStatus status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Create a shadow ministry
    /// @param ministryId Unique identifier
    /// @param name Ministry name hash
    /// @param descriptionHash Description hash
    function createMinistry(
        bytes32 ministryId,
        bytes32 name,
        bytes32 descriptionHash
    ) external onlyAdmin {
        require(!ministries[ministryId].active, "Ministry exists");

        ministries[ministryId] = Ministry({
            name: name,
            descriptionHash: descriptionHash,
            memberCount: 0,
            active: true
        });

        ministryIds.push(ministryId);
        emit MinistryCreated(ministryId, name);
    }

    /// @notice Register participants (admin sets total for quorum calculation)
    function setParticipantCount(uint256 count) external onlyAdmin {
        totalParticipants = count;
    }

    /// @notice Create a governance proposal
    /// @param contentHash Hash of the proposal content
    /// @param ministryId Ministry this proposal belongs to
    /// @param votingBlocks Number of blocks for the voting period
    /// @return proposalId The new proposal ID
    function createProposal(
        bytes32 contentHash,
        bytes32 ministryId,
        uint256 votingBlocks
    ) external returns (uint256 proposalId) {
        require(ministries[ministryId].active, "Ministry not active");
        require(votingBlocks > 0, "Invalid voting period");

        proposalId = proposalCount++;

        // Initialize encrypted vote counters to zero
        euint32 zeroVotes = FHE.asEuint32(0);
        FHE.allowThis(zeroVotes);

        euint32 zeroNo = FHE.asEuint32(0);
        FHE.allowThis(zeroNo);

        proposals[proposalId] = Proposal({
            contentHash: contentHash,
            ministryId: ministryId,
            voteDeadline: block.number + votingBlocks,
            yesVotes: zeroVotes,
            noVotes: zeroNo,
            voterCount: 0,
            status: ProposalStatus.Active,
            proposer: msg.sender
        });

        emit ProposalCreated(proposalId, ministryId, contentHash);
    }

    /// @notice Cast an anonymous encrypted vote
    /// @param proposalId Proposal to vote on
    /// @param encryptedVote FHE-encrypted vote (1 = yes, 0 = no)
    /// @param nullifier Unique nullifier to prevent double-voting
    /// @dev Nullifier = hash(secret || proposalId) — verifier cannot link to identity
    function castVote(
        uint256 proposalId,
        inEuint32 calldata encryptedVote,
        bytes32 nullifier
    ) external {
        Proposal storage p = proposals[proposalId];
        require(p.status == ProposalStatus.Active, "Not active");
        require(block.number <= p.voteDeadline, "Voting ended");
        require(!nullifiers[proposalId][nullifier], "Already voted");

        // Mark nullifier as used
        nullifiers[proposalId][nullifier] = true;

        euint32 vote = FHE.asEuint32(encryptedVote);

        // Homomorphic tally: add vote to yes counter
        // vote=1 means yes, vote=0 means no
        // yesVotes += vote
        p.yesVotes = FHE.add(p.yesVotes, vote);
        FHE.allowThis(p.yesVotes);

        // noVotes += (1 - vote) via select
        euint32 one = FHE.asEuint32(1);
        euint32 noIncrement = FHE.sub(one, vote);
        p.noVotes = FHE.add(p.noVotes, noIncrement);
        FHE.allowThis(p.noVotes);

        p.voterCount++;

        emit VoteCast(proposalId, nullifier);
    }

    /// @notice Start the tally process (request decryption)
    /// @param proposalId Proposal to tally
    function startTally(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.status == ProposalStatus.Active, "Not active");
        require(block.number > p.voteDeadline, "Voting still open");

        p.status = ProposalStatus.Tallying;

        // Request decryption of vote counts
        FHE.decrypt(p.yesVotes);
        FHE.decrypt(p.noVotes);

        emit TallyStarted(proposalId);
    }

    /// @notice Finalize the proposal after decryption
    /// @param proposalId Proposal to finalize
    function finalize(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.status == ProposalStatus.Tallying, "Not tallying");

        (uint256 yesCount, bool yesReady) = FHE.getDecryptResultSafe(p.yesVotes);
        (uint256 noCount, bool noReady) = FHE.getDecryptResultSafe(p.noVotes);
        require(yesReady && noReady, "Decryption pending");

        // Check quorum
        uint256 quorumNeeded = (totalParticipants * quorumBps) / 10000;
        bool hasQuorum = p.voterCount >= quorumNeeded;

        // Simple majority with quorum
        if (hasQuorum && yesCount > noCount) {
            p.status = ProposalStatus.Passed;
        } else {
            p.status = ProposalStatus.Rejected;
        }

        emit ProposalFinalized(proposalId, p.status);
    }

    /// @notice Get proposal summary
    function getProposal(uint256 proposalId) external view returns (
        bytes32 contentHash,
        bytes32 ministryId,
        uint256 voteDeadline,
        uint256 voterCount,
        ProposalStatus status
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.contentHash, p.ministryId, p.voteDeadline, p.voterCount, p.status);
    }

    /// @notice Get decrypted tally (only after finalization)
    function getTally(uint256 proposalId) external view returns (
        uint256 yesVotes,
        uint256 noVotes,
        bool ready
    ) {
        Proposal storage p = proposals[proposalId];
        (uint256 y, bool yr) = FHE.getDecryptResultSafe(p.yesVotes);
        (uint256 n, bool nr) = FHE.getDecryptResultSafe(p.noVotes);
        return (y, n, yr && nr);
    }

    /// @notice Get number of ministries
    function getMinistryCount() external view returns (uint256) {
        return ministryIds.length;
    }

    /// @notice Update quorum (admin only)
    function setQuorum(uint256 newQuorumBps) external onlyAdmin {
        require(newQuorumBps <= 10000, "Max 100%");
        quorumBps = newQuorumBps;
    }
}
