# Shadow Governance - Anonymous Parallel Government

FHE-encrypted anonymous governance protocol for shadow government operations.

**Implements**: [PIP-7010](https://pips.pars.network/PIPs/pip-7010-shadow-governance) / Shadow Government Protocol for [pars.vote](https://pars.vote)

## Features

- **Shadow Ministries**: Parallel government departments monitoring real governance
- **Anonymous Proposals**: Submit proposals without revealing identity
- **Encrypted Voting**: FHE-encrypted ballots — homomorphic tallying without decrypting individual votes
- **Nullifier-based Anti-Fraud**: Prevent double-voting without linking votes to identities
- **Quorum Enforcement**: Configurable quorum requirements

## How It Works

1. **Admin** creates shadow ministries (Education, Health, Economy, etc.)
2. **Anyone** submits proposals tied to a ministry
3. **Participants** vote with encrypted ballots using unique nullifiers
4. After the voting period, **tally** decrypts aggregate counts (not individual votes)
5. **Finalization** checks quorum and majority to pass/reject

## Anonymity Guarantees

- **Vote privacy**: Individual votes are FHE-encrypted; only the aggregate is decrypted
- **Voter unlinkability**: Nullifier = hash(secret || proposalId) — cannot link voter to vote
- **Proposal anonymity**: Proposals can be submitted via relay/mixer for full anonymity

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test

# Deploy
npx hardhat task:deploy-gov

# Create a ministry
# (done programmatically in deploy or via admin functions)

# Create a proposal
npx hardhat task:propose --contract <addr> --content "Reform education" --ministry <id>

# Vote anonymously
npx hardhat task:vote --contract <addr> --proposal 0 --choice yes --secret "my-secret"

# Tally after voting period
npx hardhat task:tally --contract <addr> --proposal 0

# List ministries
npx hardhat task:list-ministries --contract <addr>
```

## Related

- **Go implementation**: [github.com/luxfi/fhe/cmd/vote](https://github.com/luxfi/fhe/tree/main/cmd/vote) — Boolean-circuit encrypted voting
- **Pars voting app**: [pars.vote](https://pars.vote) — Production deployment
- **PIP-0012**: Encrypted Voting protocol
- **LP-6500**: fheCRDT Architecture
