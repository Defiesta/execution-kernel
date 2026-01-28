#!/bin/bash
# Print registration values for on-chain deployment
#
# Usage: ./scripts/print_registration_values.sh

set -e

echo "=== Building methods crate with yield agent ==="
echo ""

# Ensure zkvm-guest uses yield agent
echo "Verifying zkvm-guest/Cargo.toml uses example-yield-agent..."
grep -q "example-yield-agent" crates/methods/zkvm-guest/Cargo.toml || {
    echo "ERROR: zkvm-guest/Cargo.toml should use example-yield-agent feature"
    exit 1
}

echo "Building methods crate (this may take a while for first build)..."
cargo build --release -p methods 2>&1 | tail -5

echo ""
echo "=== Registration Values ==="
echo ""

# Print agent code hash
echo "1. AGENT_CODE_HASH (for KernelInputV1.agent_code_hash):"
cargo build -p example-yield-agent 2>&1 | grep "AGENT_CODE_HASH" | sed 's/.*: /   0x/'

echo ""
echo "2. IMAGE_ID (for registerAgent on KernelExecutionVerifier):"
echo "   Run the e2e test to get this value:"
echo "   cargo test -p e2e-tests --features risc0-e2e test_e2e -- --nocapture 2>&1 | grep 'image_id'"
echo ""
echo "   Or print from Rust:"
echo "   use methods::ZKVM_GUEST_ID;"
echo "   let bytes: Vec<u8> = ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect();"
echo "   println!(\"0x{}\", hex::encode(&bytes));"

echo ""
echo "3. AGENT_ID (for KernelVault constructor and KernelInputV1.agent_id):"
echo "   This is any bytes32 you choose to identify this agent/vault pair."
echo "   Example: 0x4242424242424242424242424242424242424242424242424242424242424242"

echo ""
echo "=== On-Chain Registration Steps ==="
echo ""
echo "1. Deploy RISC Zero Verifier (or use existing one)"
echo "2. Deploy KernelExecutionVerifier(_verifier)"
echo "3. Call verifier.registerAgent(AGENT_ID, IMAGE_ID)"
echo "4. Deploy KernelVault(_asset, _verifier, AGENT_ID)"
echo "5. Deploy MockYieldSource(vaultAddress)"
echo "6. Fund MockYieldSource with ETH for yield (10% of expected deposits)"
echo "7. Fund KernelVault with ETH for test deposit"
