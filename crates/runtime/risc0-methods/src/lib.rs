//! RISC Zero Methods Crate
//!
//! This crate provides the compiled kernel guest ELF and its IMAGE_ID for use
//! by host-side code that needs to prove and verify kernel executions.
//!
//! # Exports
//!
//! - [`ZKVM_GUEST_ELF`]: The compiled RISC Zero guest ELF binary
//! - [`ZKVM_GUEST_ID`]: The IMAGE_ID (32-byte hash identifying the guest)
//!
//! # Usage
//!
//! ```ignore
//! use risc0_methods::{ZKVM_GUEST_ELF, ZKVM_GUEST_ID};
//! use risc0_zkvm::{default_prover, ExecutorEnv};
//!
//! let env = ExecutorEnv::builder()
//!     .write_slice(&input_bytes)
//!     .build()
//!     .unwrap();
//!
//! let prover = default_prover();
//! let receipt = prover.prove(env, ZKVM_GUEST_ELF).unwrap();
//!
//! // Verify using IMAGE_ID
//! receipt.verify(ZKVM_GUEST_ID).unwrap();
//! ```
//!
//! # Architecture
//!
//! The guest is built from `zkvm-guest/`, a thin wrapper around `kernel-guest`
//! that provides the main() entry point for zkVM execution. The wrapper:
//! 1. Reads input bytes from the host via `env::read()`
//! 2. Calls `kernel_guest::kernel_main()` to execute the kernel
//! 3. Commits the resulting journal to the proof via `env::commit_slice()`
//!
//! # Determinism
//!
//! For reproducible builds, set `RISC0_USE_DOCKER=1` before building.
//! This ensures the guest ELF is built using the Docker-based RISC Zero
//! toolchain, producing identical binaries across environments.

// Include the generated code from build.rs
// This provides ZKVM_GUEST_ELF and ZKVM_GUEST_ID constants
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
