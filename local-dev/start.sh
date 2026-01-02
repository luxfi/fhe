#!/bin/bash
# LuxFHE Local Development Starter
#
# This script uses the main FHE repo's compose.yml
# All components are built from: ~/work/lux/fhe
#
# Usage:
#   ./start.sh              - Start FHE server (Docker)
#   ./start.sh threshold    - Start threshold mode
#   ./start.sh coprocessor  - Start full coprocessor stack
#   ./start.sh all          - Start everything
#   ./start.sh stop         - Stop all services
#   ./start.sh logs         - View logs
#   ./start.sh build        - Build images locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FHE_REPO="${FHE_REPO:-$HOME/work/lux/fhe}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🔐 LuxFHE Local Development${NC}\n"

# Check if FHE repo exists
if [[ ! -d "$FHE_REPO" ]]; then
    echo -e "${YELLOW}Warning: FHE repo not found at $FHE_REPO${NC}"
    echo "Set FHE_REPO environment variable to point to the fhe repo"
    echo "Example: FHE_REPO=~/work/lux/fhe ./start.sh"
    exit 1
fi

cd "$FHE_REPO"

case "${1:-start}" in
    start|server)
        echo "Starting FHE server..."
        docker compose up -d server
        echo -e "${GREEN}✓ FHE server running at http://localhost:8448${NC}"
        ;;
    threshold)
        echo "Starting FHE server in THRESHOLD mode..."
        docker compose --profile threshold up -d
        echo -e "${GREEN}✓ FHE threshold server running at http://localhost:8449${NC}"
        ;;
    coprocessor)
        echo "Starting full FHE coprocessor stack..."
        docker compose --profile coprocessor up -d
        echo -e "${GREEN}✓ FHE coprocessor stack running${NC}"
        echo "  - Server: http://localhost:8448"
        echo "  - Gateway: http://localhost:8080"
        echo "  - Redis: localhost:6379"
        echo "  - Workers: processing FHE operations"
        ;;
    contracts)
        echo "Starting with Anvil for contract testing..."
        docker compose --profile contracts up -d
        echo -e "${GREEN}✓ Anvil running at http://localhost:8545${NC}"
        ;;
    all)
        echo "Starting all services..."
        docker compose --profile threshold --profile coprocessor --profile contracts up -d
        echo -e "${GREEN}✓ All services running${NC}"
        ;;
    stop)
        echo "Stopping all services..."
        docker compose --profile threshold --profile coprocessor --profile contracts down
        echo -e "${GREEN}✓ All services stopped${NC}"
        ;;
    logs)
        docker compose logs -f
        ;;
    status)
        docker compose ps
        ;;
    build)
        echo "Building images locally..."
        docker compose build
        echo -e "${GREEN}✓ Images built${NC}"
        ;;
    pull)
        echo "Pulling latest images..."
        docker compose pull
        echo -e "${GREEN}✓ Images updated${NC}"
        ;;
    *)
        echo "Usage: $0 {start|threshold|coprocessor|contracts|all|stop|logs|status|build|pull}"
        exit 1
        ;;
esac
