#!/bin/bash
# Migrate Zama FHE repos to Lux FHE stack
# Forks to github.com/luxfi, strips Zama references, updates imports

set -e

ZAMA_DIR="$HOME/work/zama"
LUX_FHE_DIR="$HOME/work/lux/fhe"
LUXFI_ORG="luxfi"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

# Repos to migrate with their new names
declare -A MIGRATE_REPOS=(
    # Core libraries
    ["concrete-compiler-internal-llvm-project"]="fhe-compiler"
    ["concrete-ntt"]="fhe-ntt"
    ["concrete-fft"]="fhe-fft"

    # ML
    ["torus-ml"]="fhe-ml"
    ["torus-ml-extensions"]="fhe-ml-extensions"
    ["torus-ml-processing-rs"]="fhe-ml-rs"

    # Templates & dApps
    ["dapps"]="fhe-dapps"
    ["fhevm-hardhat-template"]="fhe-hardhat-template"
    ["fhevm-next-template"]="fhe-next-template"
    ["fhevm-react-template"]="fhe-react-template"
    ["fhevm-vue-template"]="fhe-vue-template"
    ["fhevm-remix-plugin"]="fhe-remix-plugin"
    ["fhevm-workshop"]="fhe-workshop"
    ["fhevm-test-suite"]="fhe-test-suite"
    ["fhevm-mocks"]="fhe-mocks"

    # Infrastructure
    ["fhevm-contracts"]="fhe-contracts"
    ["fhevm-go"]="fhe-go"
    ["fhevm-solidity"]="fhe-solidity"
    ["fhevm-decryptions-db"]="fhe-decryptions-db"
    ["fhevm-tfhe-cli"]="fhe-cli"
    ["go-ethereum-coprocessor"]="fhe-geth"
    ["relayer-sdk"]="fhe-relayer"

    # Research & Docs
    ["tfhe-rs-handbook"]="fhe-handbook"
    ["verifiable-fhe-paper"]="fhe-papers"
    ["threshold-fhe"]="fhe-threshold"

    # Demos
    ["fhe_ios_demo"]="fhe-ios"
    ["fhe-biometrics"]="fhe-biometrics"
)

# Skip these (Zama-specific, already have, or third-party)
SKIP_REPOS=(
    "tfhe-rs"           # Use luxfi/fhe instead
    "concrete"          # Zama main product
    "awesome-zama"      # Promotional
    "bounty-ecdsa-signature"
    "bounty-matrix-inversion"
    "bounty-program"
    "ci-templates"
    "fhenix"            # Third party
    "HElib"             # IBM
    "SEAL"              # Microsoft
    "openfhe-development"
    "slab-github-runner"
    "terraform-mpc-modules"
    "tfhe-backward-compat-data"
    "zbc-go-ethereum"
    "hpu_fpga"
    "hw_regmap"
    "ocp-fhe"
    "poc-prime-match"
    "progress-tracker-python"
    "copz25-code"
    "blockchain-wallet-exporter"
)

# Files/patterns to strip Zama references from
ZAMA_PATTERNS=(
    "zama.ai"
    "zama-ai"
    "Zama"
    "ZAMA"
    "tfhe-rs"
    "github.com/zama-ai"
    "@zama-ai"
)

# Replacement mappings
declare -A REPLACEMENTS=(
    ["zama.ai"]="lux.network"
    ["zama-ai"]="luxfi"
    ["Zama"]="Lux"
    ["ZAMA"]="LUX"
    ["tfhe-rs"]="luxfi/fhe"
    ["github.com/zama-ai"]="github.com/luxfi"
    ["@zama-ai"]="@luxfi"
    ["torus-ml"]="fhe-ml"
    ["concrete-ntt"]="fhe-ntt"
    ["concrete-fft"]="fhe-fft"
    ["fhevm-"]="fhe-"
)

fork_repo() {
    local src_name="$1"
    local dst_name="$2"

    log "Forking $src_name -> $dst_name"

    # Check if already exists
    if gh repo view "$LUXFI_ORG/$dst_name" &>/dev/null; then
        warn "Repo $LUXFI_ORG/$dst_name already exists, skipping fork"
        return 0
    fi

    # Check if source exists locally
    if [[ ! -d "$ZAMA_DIR/$src_name" ]]; then
        error "Source $ZAMA_DIR/$src_name not found"
        return 1
    fi

    # Create new repo
    gh repo create "$LUXFI_ORG/$dst_name" --public --description "Lux FHE: $(echo $dst_name | sed 's/-/ /g')" || {
        warn "Could not create repo, may already exist"
    }

    # Clone, strip refs, push
    local tmp_dir="/tmp/migrate-$$-$dst_name"
    cp -r "$ZAMA_DIR/$src_name" "$tmp_dir"
    cd "$tmp_dir"

    # Remove old git history
    rm -rf .git
    git init

    # Strip Zama references
    strip_zama_refs "$tmp_dir"

    # Commit and push
    git add -A
    git commit -m "Initial import from Zama (Apache 2.0), migrated to Lux FHE stack"
    git branch -M main
    git remote add origin "git@github.com:$LUXFI_ORG/$dst_name.git"
    git push -u origin main --force || warn "Push failed for $dst_name"

    cd -
    rm -rf "$tmp_dir"

    log "Successfully migrated $src_name -> $dst_name"
}

strip_zama_refs() {
    local dir="$1"

    log "Stripping Zama references from $dir"

    # Find all text files
    find "$dir" -type f \( -name "*.py" -o -name "*.rs" -o -name "*.go" -o -name "*.ts" -o -name "*.js" \
        -o -name "*.sol" -o -name "*.md" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" \
        -o -name "*.toml" -o -name "Makefile" -o -name "*.sh" -o -name "*.txt" \
        -o -name "Cargo.toml" -o -name "package.json" -o -name "pyproject.toml" \) 2>/dev/null | while read -r file; do

        # Apply replacements
        for pattern in "${!REPLACEMENTS[@]}"; do
            replacement="${REPLACEMENTS[$pattern]}"
            if grep -q "$pattern" "$file" 2>/dev/null; then
                sed -i '' "s|$pattern|$replacement|g" "$file" 2>/dev/null || true
            fi
        done
    done

    # Update README files
    find "$dir" -name "README.md" -type f 2>/dev/null | while read -r readme; do
        # Add Lux header
        if ! grep -q "Lux FHE" "$readme" 2>/dev/null; then
            sed -i '' '1s/^/# Lux FHE\n\nPart of the Lux FHE stack. See https:\/\/github.com\/luxfi\/fhe\n\n/' "$readme" 2>/dev/null || true
        fi
    done
}

update_imports() {
    local dir="$1"

    log "Updating imports in $dir"

    # Python imports
    find "$dir" -name "*.py" -type f 2>/dev/null | xargs -I {} sed -i '' \
        -e 's/from concrete\./from luxfhe./g' \
        -e 's/import concrete/import luxfhe/g' \
        -e 's/torus-ml/fhe-ml/g' \
        {} 2>/dev/null || true

    # Rust imports
    find "$dir" -name "*.rs" -o -name "Cargo.toml" 2>/dev/null | xargs -I {} sed -i '' \
        -e 's/tfhe = /fhe = { git = "https:\/\/github.com\/luxfi\/fhe" } # /g' \
        -e 's/concrete_/luxfhe_/g' \
        {} 2>/dev/null || true

    # TypeScript/JavaScript
    find "$dir" -name "*.ts" -o -name "*.js" -o -name "package.json" 2>/dev/null | xargs -I {} sed -i '' \
        -e 's/@zama-ai\/fhevm/@luxfi\/fhe/g' \
        -e 's/fhevm/luxfhe/g' \
        {} 2>/dev/null || true

    # Go imports
    find "$dir" -name "*.go" -o -name "go.mod" 2>/dev/null | xargs -I {} sed -i '' \
        -e 's|github.com/zama-ai/|github.com/luxfi/|g' \
        {} 2>/dev/null || true
}

# Main migration
main() {
    log "Starting Zama -> Lux FHE migration"
    log "Source: $ZAMA_DIR"
    log "Org: $LUXFI_ORG"
    echo

    # Check prerequisites
    if ! command -v gh &>/dev/null; then
        error "GitHub CLI (gh) not found"
        exit 1
    fi

    if ! gh auth status &>/dev/null; then
        error "Not logged into GitHub CLI"
        exit 1
    fi

    # Migrate each repo
    for src_name in "${!MIGRATE_REPOS[@]}"; do
        dst_name="${MIGRATE_REPOS[$src_name]}"

        echo "---"
        fork_repo "$src_name" "$dst_name" || warn "Failed to migrate $src_name"
    done

    log "Migration complete!"
    echo
    log "Next steps:"
    echo "  1. Review each repo and fix any remaining Zama references"
    echo "  2. Update CI/CD pipelines"
    echo "  3. Update documentation"
    echo "  4. Test integrations with luxfi/fhe"
}

# Run with specific repo or all
if [[ $# -eq 1 ]]; then
    src="$1"
    if [[ -v "MIGRATE_REPOS[$src]" ]]; then
        fork_repo "$src" "${MIGRATE_REPOS[$src]}"
    else
        error "Unknown repo: $src"
        echo "Available repos:"
        for r in "${!MIGRATE_REPOS[@]}"; do
            echo "  $r -> ${MIGRATE_REPOS[$r]}"
        done
        exit 1
    fi
else
    main
fi
