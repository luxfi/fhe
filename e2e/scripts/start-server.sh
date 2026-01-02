#!/bin/bash
# Start FHE server for e2e tests

set -e

TFHE_DIR="$HOME/work/lux/tfhe"
FHE_SERVER="$TFHE_DIR/bin/fhe-server"

# Build if needed
if [ ! -f "$FHE_SERVER" ]; then
    echo "Building FHE server..."
    cd "$TFHE_DIR"
    go build -o bin/fhe-server ./cmd/fhe-server/
fi

echo "Starting FHE server on :8448..."
exec "$FHE_SERVER" -addr :8448
