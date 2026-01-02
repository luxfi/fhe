#!/bin/bash
# LuxFHE Local Development - Start Script
# Starts lux dev node + FHE server for local development
#
# Requirements:
#   - lux CLI installed (brew install lux or go install github.com/luxfi/cli@latest)
#   - FHE server binary at ~/work/luxcpp/fhe/bin/fhe-server-cpp
#
# Usage:
#   ./start-local.sh           # Start both services
#   ./start-local.sh --node    # Start node only
#   ./start-local.sh --fhe     # Start FHE server only
#   ./start-local.sh --stop    # Stop all services

set -e

# Configuration
NODE_PORT=${NODE_PORT:-8545}
FHE_PORT=${FHE_PORT:-8448}
FAUCET_PORT=${FAUCET_PORT:-42069}
FHE_SERVER_BIN="${FHE_SERVER_BIN:-$HOME/work/luxcpp/fhe/server/build/bin/fhe_server}"
FHE_SERVER_ALT="$HOME/work/luxcpp/fhe/bin/fhe-server-cpp"
LUX_CLI="${LUX_CLI:-lux}"
PID_DIR="$HOME/.lux/dev/pids"
LOG_DIR="$HOME/.lux/dev/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

mkdir -p "$PID_DIR" "$LOG_DIR"

log() {
    echo -e "${GREEN}[luxfhe]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[luxfhe]${NC} $1"
}

error() {
    echo -e "${RED}[luxfhe]${NC} $1"
    exit 1
}

find_fhe_server() {
    if [ -f "$FHE_SERVER_BIN" ]; then
        echo "$FHE_SERVER_BIN"
    elif [ -f "$FHE_SERVER_ALT" ]; then
        echo "$FHE_SERVER_ALT"
    else
        error "FHE server binary not found. Build with: cd ~/work/luxcpp/fhe && mkdir -p build && cd build && cmake .. && make"
    fi
}

start_fhe_server() {
    if pgrep -f "fhe.*server.*:$FHE_PORT" > /dev/null; then
        warn "FHE server already running on port $FHE_PORT"
        return
    fi

    local fhe_bin=$(find_fhe_server)
    log "Starting FHE server on port $FHE_PORT..."
    nohup "$fhe_bin" -addr ":$FHE_PORT" > "$LOG_DIR/fhe-server.log" 2>&1 &
    echo $! > "$PID_DIR/fhe-server.pid"

    # Wait for health
    for i in {1..30}; do
        if curl -s "http://localhost:$FHE_PORT/health" > /dev/null 2>&1; then
            log "FHE server started successfully (PID: $(cat $PID_DIR/fhe-server.pid))"
            return
        fi
        sleep 1
    done
    error "FHE server failed to start"
}

start_node() {
    if lsof -i :$NODE_PORT > /dev/null 2>&1; then
        warn "Node already running on port $NODE_PORT"
        return
    fi

    log "Starting Lux dev node on port $NODE_PORT..."
    log "Run: $LUX_CLI dev start --port $NODE_PORT"

    # Start lux dev in background
    nohup "$LUX_CLI" dev start --port "$NODE_PORT" > "$LOG_DIR/lux-dev.log" 2>&1 &
    echo $! > "$PID_DIR/lux-dev.pid"

    # Wait for health
    for i in {1..60}; do
        if curl -s "http://localhost:$NODE_PORT/ext/health" > /dev/null 2>&1; then
            log "Lux dev node started (PID: $(cat $PID_DIR/lux-dev.pid))"
            return
        fi
        sleep 1
    done
    error "Lux dev node failed to start"
}

stop_services() {
    log "Stopping services..."

    if [ -f "$PID_DIR/fhe-server.pid" ]; then
        local pid=$(cat "$PID_DIR/fhe-server.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" && log "FHE server stopped"
        fi
        rm -f "$PID_DIR/fhe-server.pid"
    fi

    # Also try to kill by port
    pkill -f "fhe.*server.*:$FHE_PORT" 2>/dev/null || true

    if [ -f "$PID_DIR/lux-dev.pid" ]; then
        local pid=$(cat "$PID_DIR/lux-dev.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" && log "Lux dev node stopped"
        fi
        rm -f "$PID_DIR/lux-dev.pid"
    fi

    # Also run lux dev stop
    "$LUX_CLI" dev stop 2>/dev/null || true

    log "All services stopped"
}

print_status() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}                   LuxFHE Local Development                   ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}C-Chain RPC:${NC}  http://localhost:$NODE_PORT/ext/bc/C/rpc          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}C-Chain WS:${NC}   ws://localhost:$NODE_PORT/ext/bc/C/ws              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}FHE Server:${NC}   http://localhost:$FHE_PORT                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}Chain ID:${NC}     1337                                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}FHE Precompiles:${NC}                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    FHEOS:    0x0200000000000000000000000000000000000080      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    ACL:      0x0200000000000000000000000000000000000081      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    Verifier: 0x0200000000000000000000000000000000000082      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    Gateway:  0x0200000000000000000000000000000000000083      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}Logs:${NC}         ~/.lux/dev/logs/                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}Stop:${NC}         ./start-local.sh --stop                       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main
case "${1:-}" in
    --stop)
        stop_services
        ;;
    --node)
        start_node
        ;;
    --fhe)
        start_fhe_server
        ;;
    *)
        log "Starting LuxFHE local development environment..."
        start_fhe_server
        start_node
        print_status
        ;;
esac
