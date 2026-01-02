#!/usr/bin/env bash
#
# flatten-repos.sh - Migrate luxfhe monorepo to separate repos
#
# Usage: ./flatten-repos.sh [--dry-run] [--target-dir /path/to/output]
#
# This script:
# 1. Creates separate git repos for each component
# 2. Updates package.json/go.mod with correct names and paths
# 3. Generates README files
# 4. Does NOT push to remote (manual step)

set -euo pipefail

# Configuration
SOURCE_DIR="/Users/z/work/luxfhe"
TARGET_DIR="${TARGET_DIR:-/Users/z/work/luxfhe-repos}"
DRY_RUN=false
ORG="luxfhe"
GITHUB_BASE="https://github.com/${ORG}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --target-dir) TARGET_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log() { echo "[$(date +%H:%M:%S)] $*"; }
run() { if $DRY_RUN; then echo "[DRY-RUN] $*"; else eval "$*"; fi; }

# Repo definitions: source_path:repo_name:package_name:description
declare -a REPOS=(
    "contracts:contracts:@luxfhe/contracts:Lux FHE Smart Contracts - Fully Homomorphic Encryption for Solidity"
    "js/v1-sdk:v1-sdk:@luxfhe/v1-sdk:Lux FHE v1 SDK - Standard TFHE with single-key encryption"
    "js/v2-sdk:v2-sdk:@luxfhe/v2-sdk:Lux FHE v2 SDK - Network-based Threshold TFHE"
    "js/permit:permit:@luxfhe/permit:Lux FHE Permit - Signing utilities for FHE access control"
    "mocks:mocks:@luxfhe/mocks:Lux FHE Mocks - Mock contracts for testing"
    "examples:examples::Lux FHE Examples - Sample applications and demos"
    "templates:templates::Lux FHE Templates - Starter project templates"
    "docs:docs::Lux FHE Documentation"
    "research:research::Lux FHE Research - Experimental projects"
    "scaffold-eth:scaffold-eth::Lux FHE Scaffold-ETH Integration"
    "wasm/sdk:wasm-sdk:@luxfhe/wasm-sdk:Lux FHE WASM SDK - Rust WebAssembly bindings"
    "proto:proto::Lux FHE Protocol Buffers - gRPC service definitions"
    "plugins/hardhat:hardhat-plugin:@luxfhe/hardhat-plugin:Lux FHE Hardhat Plugin"
    "plugins/remix:remix-plugin:@luxfhe/remix-plugin:Lux FHE Remix IDE Plugin"
    "sdk/cofhe:cofhe-sdk:@luxfhe/cofhe-sdk:Lux FHE CoFHE SDK Monorepo"
    "sdk/relayer:relayer:@luxfhe/relayer:Lux FHE Transaction Relayer"
    "ml:ml::Lux FHE ML - Machine Learning Extensions"
)

# Create target directory
log "Creating target directory: $TARGET_DIR"
run "mkdir -p '$TARGET_DIR'"

# Generate README template
generate_readme() {
    local repo_name="$1"
    local pkg_name="$2"
    local description="$3"
    
    cat <<EOF
# ${repo_name}

${description}

## Installation

EOF
    if [[ -n "$pkg_name" ]]; then
        cat <<EOF
\`\`\`bash
npm install ${pkg_name}
# or
pnpm add ${pkg_name}
\`\`\`

EOF
    fi
    cat <<EOF
## Usage

See [documentation](${GITHUB_BASE}/docs) for detailed usage instructions.

## Development

\`\`\`bash
# Install dependencies
pnpm install

# Build
pnpm build

# Test
pnpm test
\`\`\`

## License

BSD-3-Clause - See LICENSE for details.

## Links

- [Documentation](${GITHUB_BASE}/docs)
- [Examples](${GITHUB_BASE}/examples)
- [GitHub Organization](${GITHUB_BASE})
EOF
}

# Update package.json
update_package_json() {
    local file="$1"
    local pkg_name="$2"
    local repo_name="$3"
    local description="$4"
    
    if [[ ! -f "$file" ]]; then
        return
    fi
    
    log "Updating $file"
    
    # Use node to update JSON safely
    node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('$file', 'utf8'));

// Update fields
pkg.name = '$pkg_name' || pkg.name;
pkg.description = '$description' || pkg.description;
pkg.repository = {
    type: 'git',
    url: '${GITHUB_BASE}/${repo_name}.git'
};
pkg.homepage = '${GITHUB_BASE}/${repo_name}#readme';
pkg.bugs = { url: '${GITHUB_BASE}/${repo_name}/issues' };

// Ensure publishConfig for scoped packages
if (pkg.name && pkg.name.startsWith('@')) {
    pkg.publishConfig = pkg.publishConfig || {};
    pkg.publishConfig.access = 'public';
}

// Update internal dependency references
const internalDeps = ['@luxfhe/contracts', '@luxfhe/v1-sdk', '@luxfhe/v2-sdk', '@luxfhe/permit', '@luxfhe/mocks'];
for (const section of ['dependencies', 'peerDependencies', 'devDependencies']) {
    if (!pkg[section]) continue;
    
    // Rename old package names
    const renames = {
        'cofhe-hardhat-plugin': '@luxfhe/hardhat-plugin',
        'cofhejs': '@luxfhe/v2-sdk',
        'cofhejs-permit': '@luxfhe/permit',
        '@fhenixprotocol/contracts': '@luxfhe/contracts',
        '@luxfhe/cofhe-contracts': '@luxfhe/contracts',
        '@luxfhe/cofhe-mock-contracts': '@luxfhe/mocks',
    };
    
    for (const [old, new_] of Object.entries(renames)) {
        if (pkg[section][old]) {
            pkg[section][new_] = pkg[section][old];
            delete pkg[section][old];
        }
    }
}

fs.writeFileSync('$file', JSON.stringify(pkg, null, 2) + '\\n');
console.log('Updated: $file');
"
}

# Update go.mod
update_go_mod() {
    local file="$1"
    local repo_name="$2"
    
    if [[ ! -f "$file" ]]; then
        return
    fi
    
    log "Updating $file"
    run "sed -i '' 's|module github.com/fhenixprotocol/[^[:space:]]*|module github.com/${ORG}/${repo_name}|g' '$file'"
}

# Process each repo
for repo_def in "${REPOS[@]}"; do
    IFS=':' read -r src_path repo_name pkg_name description <<< "$repo_def"
    
    src_full="${SOURCE_DIR}/${src_path}"
    dst_full="${TARGET_DIR}/${repo_name}"
    
    # Skip if source doesn't exist
    if [[ ! -d "$src_full" ]]; then
        log "SKIP: Source not found: $src_full"
        continue
    fi
    
    log "Processing: $src_path -> $repo_name"
    
    # Copy directory
    run "rm -rf '$dst_full'"
    run "cp -R '$src_full' '$dst_full'"
    
    # Remove existing .git if present (we'll create fresh)
    run "rm -rf '$dst_full/.git'"
    
    # Initialize new git repo
    run "cd '$dst_full' && git init"
    
    # Generate README
    if ! $DRY_RUN; then
        generate_readme "$repo_name" "$pkg_name" "$description" > "$dst_full/README.md"
        log "Generated README.md for $repo_name"
    fi
    
    # Update package.json if exists
    if [[ -f "$dst_full/package.json" && -n "$pkg_name" ]]; then
        if ! $DRY_RUN; then
            update_package_json "$dst_full/package.json" "$pkg_name" "$repo_name" "$description"
        fi
    fi
    
    # Update go.mod if exists
    for gomod in "$dst_full"/go.mod "$dst_full"/*/go.mod; do
        if [[ -f "$gomod" ]]; then
            if ! $DRY_RUN; then
                update_go_mod "$gomod" "$repo_name"
            fi
        fi
    done
    
    # Create LICENSE if missing
    if [[ ! -f "$dst_full/LICENSE" && ! -f "$dst_full/LICENSE.md" ]]; then
        if ! $DRY_RUN; then
            cat > "$dst_full/LICENSE" <<'EOF'
BSD 3-Clause License

Copyright (c) 2024, Lux Partners

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
EOF
            log "Created LICENSE for $repo_name"
        fi
    fi
    
    # Create .gitignore if missing
    if [[ ! -f "$dst_full/.gitignore" ]]; then
        if ! $DRY_RUN; then
            cat > "$dst_full/.gitignore" <<'EOF'
# Dependencies
node_modules/
vendor/

# Build outputs
dist/
lib/
out/
build/
*.wasm

# Cache
.cache/
.turbo/
*.tsbuildinfo

# IDE
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Environment
.env
.env.local
.env.*.local

# Logs
*.log
npm-debug.log*

# Test coverage
coverage/
.nyc_output/

# Artifacts
artifacts/
cache/
typechain-types/
EOF
            log "Created .gitignore for $repo_name"
        fi
    fi
    
    # Initial commit
    if ! $DRY_RUN; then
        cd "$dst_full"
        git add -A
        git commit -m "Initial commit: migrate from luxfhe monorepo

Source: ${SOURCE_DIR}/${src_path}
Target: github.com/${ORG}/${repo_name}"
        cd - > /dev/null
    fi
    
    log "Completed: $repo_name"
    echo ""
done

# Summary
log "========================================="
log "Migration complete!"
log "========================================="
log ""
log "Output directory: $TARGET_DIR"
log ""
log "Next steps:"
log "1. Review each repo in $TARGET_DIR"
log "2. Create repos on GitHub: https://github.com/organizations/${ORG}/repositories/new"
log "3. For each repo, add remote and push:"
log ""
log "   cd $TARGET_DIR/<repo>"
log "   git remote add origin git@github.com:${ORG}/<repo>.git"
log "   git push -u origin main"
log ""
log "4. Set up npm publishing:"
log ""
log "   npm login --scope=@luxfhe"
log "   cd $TARGET_DIR/<repo>"
log "   npm publish --access public"
log ""
if $DRY_RUN; then
    log "NOTE: This was a dry run. No files were modified."
fi
