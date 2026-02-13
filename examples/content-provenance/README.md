# Content Provenance - AI & Media Authentication

FHE-powered content provenance tracking for AI models, generated outputs, and media.

**Implements**: [PIP-0011](https://pips.pars.network/PIPs/pip-0011-content-provenance) / [LP-7110](https://lps.lux.network/docs/lp-7110-ai-media-content-provenance)

## Features

- **Model Sealing**: Register AI model manifests (weights, architecture, training data) with FHE-encrypted version
- **Output Attestation**: Prove AI output came from a specific model via homomorphic comparison — model ID never revealed
- **Media Chain**: Track full provenance from point-of-capture through every edit
- **Derivation DAG**: Directed acyclic graph of content lineage

## Content Types

| Type | Description | Example |
|------|-------------|---------|
| AIModel | Model weights/architecture | GPT checkpoint |
| AIOutput | Generated content | Text, image, code |
| MediaCapture | Point-of-capture media | Photo from device |
| MediaEdit | Edited derivative | Cropped, filtered |
| Document | Text document | Article, report |

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test

# Deploy
npx hardhat task:deploy

# Register a model
npx hardhat task:register-content --contract <addr> --hash 0x... --type 0

# Register AI output
npx hardhat task:register-content --contract <addr> --hash 0x... --type 1 --model 42

# Attest output origin
npx hardhat task:attest-output --contract <addr> --output 1 --model 42

# View provenance chain
npx hardhat task:verify-provenance --contract <addr> --id 0
```

## Related

- **Go implementation**: [github.com/luxfi/fhe/cmd/provenance](https://github.com/luxfi/fhe/tree/main/cmd/provenance) — Boolean-circuit model provenance
- **Go media seal**: [github.com/luxfi/fhe/cmd/mediaseal](https://github.com/luxfi/fhe/tree/main/cmd/mediaseal) — Media authentication
- **LP-0535**: Data Integrity Seal Protocol
- **LP-0530**: Z-Chain Receipt Registry
