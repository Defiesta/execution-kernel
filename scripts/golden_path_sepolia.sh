#!/bin/bash
#
# Golden Path Demo: End-to-end Agent Pack execution on Sepolia
#
# This script demonstrates the complete workflow:
#   1. Verify bundle offline and on-chain
#   2. Generate a proof
#   3. Execute on-chain via the vault
#
# Usage:
#   ./scripts/golden_path_sepolia.sh <bundle-dir> [opaque-inputs-file]
#
# Required environment variables:
#   RPC_URL          - Ethereum RPC endpoint
#   VERIFIER_ADDRESS - KernelExecutionVerifier contract address
#   VAULT_ADDRESS    - KernelVault contract address
#   PRIVATE_KEY      - Private key for signing (0x prefixed)
#
# Optional:
#   NONCE            - Execution nonce (default: 1)
#   DEV_MODE         - Set to "true" for dev mode proving (faster, not on-chain verifiable)
#
# Exit codes:
#   0 - Success
#   1 - Missing arguments or environment variables
#   2 - Verification failed
#   3 - Agent not registered
#   4 - Proof generation failed
#   5 - Transaction failed

set -e

# Resolve the refint binary path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -x "$REPO_ROOT/target/release/refint" ]; then
    REFINT="$REPO_ROOT/target/release/refint"
elif command -v refint &> /dev/null; then
    REFINT="refint"
else
    echo "ERROR: refint binary not found. Build with: cargo build -p reference-integrator --release --features full"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate arguments
if [ -z "$1" ]; then
    log_error "Usage: $0 <bundle-dir> [opaque-inputs-file]"
    exit 1
fi

BUNDLE_DIR="$1"
OPAQUE_INPUTS_FILE="${2:-}"

if [ ! -d "$BUNDLE_DIR" ]; then
    log_error "Bundle directory not found: $BUNDLE_DIR"
    exit 1
fi

if [ ! -f "$BUNDLE_DIR/agent-pack.json" ]; then
    log_error "No agent-pack.json found in: $BUNDLE_DIR"
    exit 1
fi

# Validate required environment variables
missing_vars=()

if [ -z "$RPC_URL" ]; then
    missing_vars+=("RPC_URL")
fi

if [ -z "$VERIFIER_ADDRESS" ]; then
    missing_vars+=("VERIFIER_ADDRESS")
fi

if [ -z "$VAULT_ADDRESS" ]; then
    missing_vars+=("VAULT_ADDRESS")
fi

if [ -z "$PRIVATE_KEY" ]; then
    missing_vars+=("PRIVATE_KEY")
fi

if [ ${#missing_vars[@]} -ne 0 ]; then
    log_error "Missing required environment variables:"
    for var in "${missing_vars[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "Required variables:"
    echo "  RPC_URL          - Ethereum RPC endpoint"
    echo "  VERIFIER_ADDRESS - KernelExecutionVerifier contract address"
    echo "  VAULT_ADDRESS    - KernelVault contract address"
    echo "  PRIVATE_KEY      - Private key for signing (0x prefixed)"
    exit 1
fi

# Set defaults
NONCE="${NONCE:-1}"

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./run/golden-path/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

log_info "Golden Path Demo"
log_info "================"
log_info "Bundle: $BUNDLE_DIR"
log_info "Output: $OUTPUT_DIR"
log_info "RPC: $RPC_URL"
log_info "Verifier: $VERIFIER_ADDRESS"
log_info "Vault: $VAULT_ADDRESS"
log_info "Nonce: $NONCE"
echo ""

# Step 1: Verify offline
log_info "Step 1: Offline verification..."
if ! $REFINT verify --bundle "$BUNDLE_DIR" --json > "$OUTPUT_DIR/verify_offline.json" 2>&1; then
    log_error "Offline verification failed"
    cat "$OUTPUT_DIR/verify_offline.json"
    exit 2
fi

# Check if offline passed
offline_passed=$(jq -r '.offline_passed' "$OUTPUT_DIR/verify_offline.json")
if [ "$offline_passed" != "true" ]; then
    log_error "Offline verification failed"
    jq '.' "$OUTPUT_DIR/verify_offline.json"
    exit 2
fi

log_info "Offline verification passed"

# Step 2: Verify on-chain
log_info "Step 2: On-chain verification..."
if ! $REFINT verify --bundle "$BUNDLE_DIR" \
    --rpc "$RPC_URL" \
    --verifier "$VERIFIER_ADDRESS" \
    --json > "$OUTPUT_DIR/verify_onchain.json" 2>&1; then

    exit_code=$?
    if [ $exit_code -eq 3 ]; then
        log_error "Agent not registered on-chain"
        exit 3
    elif [ $exit_code -eq 2 ]; then
        log_error "Image ID mismatch"
        exit 2
    else
        log_error "On-chain verification failed"
        cat "$OUTPUT_DIR/verify_onchain.json"
        exit $exit_code
    fi
fi

onchain_status=$(jq -r '.onchain_status // "none"' "$OUTPUT_DIR/verify_onchain.json")
if [ "$onchain_status" = "not_registered" ]; then
    log_error "Agent not registered on-chain"
    exit 3
elif [ "$onchain_status" = "mismatch" ]; then
    log_error "Image ID mismatch"
    exit 2
elif [ "$onchain_status" != "match" ] && [ "$onchain_status" != "none" ]; then
    log_error "On-chain verification failed: $onchain_status"
    exit 2
fi

log_info "On-chain verification passed"

# Step 3: Generate proof
log_info "Step 3: Generating proof..."

PROVE_ARGS=(
    "--bundle" "$BUNDLE_DIR"
    "--nonce" "$NONCE"
    "--out" "$OUTPUT_DIR"
)

if [ -n "$OPAQUE_INPUTS_FILE" ]; then
    if [ ! -f "$OPAQUE_INPUTS_FILE" ]; then
        log_error "Opaque inputs file not found: $OPAQUE_INPUTS_FILE"
        exit 1
    fi
    PROVE_ARGS+=("--opaque-inputs" "@$OPAQUE_INPUTS_FILE")
elif [ -n "$MOCK_YIELD_SOURCE" ]; then
    # For yield agent: construct opaque inputs from environment
    # Format: vault (20 bytes) + yield_source (20 bytes) + amount (8 bytes LE)
    VAULT_ADDR=$(echo "$VAULT_ADDRESS" | sed 's/0x//')
    YIELD_ADDR=$(echo "$MOCK_YIELD_SOURCE" | sed 's/0x//')
    AMOUNT_HEX="${YIELD_AMOUNT:-40420F0000000000}"  # Default: 1000000 (1 USDC)
    OPAQUE_INPUTS="0x${VAULT_ADDR}${YIELD_ADDR}${AMOUNT_HEX}"
    log_info "Using yield agent opaque inputs: vault + yield_source + amount"
    PROVE_ARGS+=("--opaque-inputs" "$OPAQUE_INPUTS")
fi

if [ "$DEV_MODE" = "true" ]; then
    log_warn "Using DEV mode - proof will not be verifiable on-chain"
    PROVE_ARGS+=("--dev")
fi

PROVE_ARGS+=("--json")

if ! $REFINT prove "${PROVE_ARGS[@]}" > "$OUTPUT_DIR/prove.json" 2>&1; then
    log_error "Proof generation failed"
    cat "$OUTPUT_DIR/prove.json"
    exit 4
fi

prove_success=$(jq -r '.success' "$OUTPUT_DIR/prove.json")
if [ "$prove_success" != "true" ]; then
    log_error "Proof generation failed"
    jq '.' "$OUTPUT_DIR/prove.json"
    exit 4
fi

journal_size=$(jq -r '.journal_size' "$OUTPUT_DIR/prove.json")
seal_size=$(jq -r '.seal_size' "$OUTPUT_DIR/prove.json")
log_info "Proof generated: journal=${journal_size}B, seal=${seal_size}B"

# Step 4: Inspect proof (optional, just for display)
log_info "Step 4: Inspecting proof artifacts..."
$REFINT status --artifacts-dir "$OUTPUT_DIR" --json > "$OUTPUT_DIR/status.json" 2>&1 || true

if [ -f "$OUTPUT_DIR/status.json" ]; then
    execution_status=$(jq -r '.artifacts.execution_status // "unknown"' "$OUTPUT_DIR/status.json")
    log_info "Execution status: $execution_status"
fi

# Step 5: Execute on-chain
# Note: The agent output file must exist for execution
# In a real scenario, this would come from the agent's actual output
AGENT_OUTPUT_FILE="$OUTPUT_DIR/agent_output.bin"

if [ ! -f "$AGENT_OUTPUT_FILE" ]; then
    log_warn "Agent output file not found at $AGENT_OUTPUT_FILE"
    log_warn "Creating empty agent output for demo purposes"
    touch "$AGENT_OUTPUT_FILE"
fi

log_info "Step 5: Executing on-chain..."

# Export PRIVATE_KEY for the env: prefix to work
export PRIVATE_KEY

if ! $REFINT execute \
    --bundle "$BUNDLE_DIR" \
    --rpc "$RPC_URL" \
    --vault "$VAULT_ADDRESS" \
    --pk "env:PRIVATE_KEY" \
    --journal "$OUTPUT_DIR/journal.bin" \
    --seal "$OUTPUT_DIR/seal.bin" \
    --agent-output "$AGENT_OUTPUT_FILE" \
    --json > "$OUTPUT_DIR/execute.json" 2>&1; then

    log_error "On-chain execution failed"
    cat "$OUTPUT_DIR/execute.json"
    exit 5
fi

execute_success=$(jq -r '.success' "$OUTPUT_DIR/execute.json")
tx_hash=$(jq -r '.tx_hash // "unknown"' "$OUTPUT_DIR/execute.json")
block_number=$(jq -r '.block_number // "pending"' "$OUTPUT_DIR/execute.json")

if [ "$execute_success" != "true" ]; then
    log_error "Transaction reverted"
    jq '.' "$OUTPUT_DIR/execute.json"
    exit 5
fi

echo ""
log_info "========================================"
log_info "Golden Path Complete!"
log_info "========================================"
log_info "Transaction: $tx_hash"
log_info "Block: $block_number"
log_info "Output directory: $OUTPUT_DIR"
echo ""

exit 0
