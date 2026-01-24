//! RISC Zero zkVM Guest Entry Point
//!
//! This is a wrapper that delegates to the kernel-guest library for zkVM execution.
//!
//! # Execution Flow
//!
//! 1. Read `KernelInputV1` bytes from the host via `env::read()`
//! 2. Execute `kernel_main()` which runs the agent and enforces constraints
//! 3. Commit the `KernelJournalV1` bytes to the journal via `env::commit_slice()`
//!
//! # Error Handling
//!
//! If kernel execution fails (e.g., version mismatch, agent code hash mismatch),
//! the guest panics. This aborts proof generation - no valid receipt is produced.

fn main() {
    use risc0_zkvm::guest::env;

    // Read input bytes from the host
    let input_bytes: Vec<u8> = env::read();

    // Execute kernel (agent execution + constraint enforcement)
    match kernel_guest::kernel_main(&input_bytes) {
        Ok(journal_bytes) => {
            // Commit journal to the proof receipt
            env::commit_slice(&journal_bytes);
        }
        Err(error) => {
            // Panic aborts proof generation - this is intentional
            panic!("Kernel execution failed: {:?}", error);
        }
    }
}
