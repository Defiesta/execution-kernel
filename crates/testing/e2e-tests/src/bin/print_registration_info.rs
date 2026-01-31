//! Print registration info for on-chain deployment
//!
//! Run with:
//! ```bash
//! cargo run -p e2e-tests --bin print_registration_info --features phase3-e2e
//! ```

#[cfg(not(feature = "phase3-e2e"))]
fn main() {
    eprintln!("ERROR: This binary requires the phase3-e2e feature.");
    eprintln!(
        "Run with: cargo run -p e2e-tests --bin print_registration_info --features phase3-e2e"
    );
    std::process::exit(1);
}

#[cfg(feature = "phase3-e2e")]
fn main() {
    println!("=== Yield Agent Registration Info ===\n");

    // Agent Code Hash
    let agent_code_hash = example_yield_agent::AGENT_CODE_HASH;
    println!("AGENT_CODE_HASH (bytes32):");
    println!("  0x{}", hex::encode(&agent_code_hash));
    println!();

    // Note about IMAGE_ID
    println!("IMAGE_ID:");
    println!("  The IMAGE_ID must be obtained from the methods crate after building");
    println!("  the kernel-guest with --features example-yield-agent.");
    println!();
    println!("  To get it, run the existing e2e tests with --nocapture:");
    println!(
        "  cargo test -p e2e-tests --features risc0-e2e test_e2e_success_with_echo -- --nocapture"
    );
    println!();
    println!("  Or add this to your test:");
    println!("  ```rust");
    println!("  use methods::ZKVM_GUEST_ID;");
    println!(
        "  let image_id: Vec<u8> = ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect();"
    );
    println!("  println!(\"imageId: 0x{{}}\", hex::encode(&image_id));");
    println!("  ```");
    println!();

    // Registration commands
    println!("=== On-Chain Registration Commands ===\n");
    println!("1. First, deploy KernelExecutionVerifier with RISC Zero verifier address");
    println!();
    println!("2. Register the agent (replace IMAGE_ID with actual value):");
    println!("   cast send $VERIFIER_ADDRESS \\");
    println!("       \"registerAgent(bytes32,bytes32)\" \\");
    println!("       $AGENT_ID \\");
    println!("       $IMAGE_ID \\");
    println!("       --private-key $PRIVATE_KEY --rpc-url $RPC_URL");
    println!();
    println!("3. Deploy KernelVault with:");
    println!("   - _asset: Your ERC20 token address (or use WETH)");
    println!("   - _verifier: KernelExecutionVerifier address");
    println!(
        "   - _agentId: The AGENT_ID you chose (any bytes32, used to identify this vault's agent)"
    );
    println!();

    // Example values
    println!("=== Example Values ===\n");
    println!("For testing, you can use any bytes32 as AGENT_ID:");
    println!("  AGENT_ID=0x4242424242424242424242424242424242424242424242424242424242424242");
    println!();
    println!("The AGENT_ID in KernelInputV1 must match the vault's agentId.");
    println!(
        "The agent_code_hash in KernelInputV1 must match: 0x{}",
        hex::encode(&agent_code_hash)
    );
}
