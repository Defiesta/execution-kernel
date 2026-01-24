//! Build script for the methods crate.
//!
//! This compiles zkvm-guest as a RISC Zero guest program and generates
//! Rust source code with the ELF binary and IMAGE_ID embedded.
//!
//! zkvm-guest is a thin wrapper around kernel-guest that provides the
//! main() entry point for the zkVM execution environment.
//!
//! The generated code exports:
//! - `ZKVM_GUEST_ELF`: The compiled guest ELF binary
//! - `ZKVM_GUEST_ID`: The IMAGE_ID (hash of the ELF)
//!
//! # Build Environment
//!
//! Set `RISC0_USE_DOCKER=1` for deterministic/reproducible builds using Docker.
//! Otherwise, builds use the local risc0 toolchain.

use std::env;
use std::path::PathBuf;

fn main() {
    // Get the manifest directory
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    // Paths to rebuild triggers
    let zkvm_guest_dir = manifest_dir.join("zkvm-guest");
    let kernel_guest_dir = manifest_dir.join("..").join("kernel-guest");
    let example_agent_dir = manifest_dir.join("..").join("example-agent");

    // Rebuild if the zkvm-guest wrapper changes
    println!(
        "cargo:rerun-if-changed={}",
        zkvm_guest_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        zkvm_guest_dir.join("Cargo.toml").display()
    );

    // Rebuild if kernel-guest (the library) changes
    println!(
        "cargo:rerun-if-changed={}",
        kernel_guest_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        kernel_guest_dir.join("Cargo.toml").display()
    );

    // Rebuild if example-agent changes
    println!(
        "cargo:rerun-if-changed={}",
        example_agent_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        example_agent_dir.join("Cargo.toml").display()
    );

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    // Build guest using risc0-build with metadata from Cargo.toml
    // The [package.metadata.risc0] section specifies the guest crate path
    risc0_build::embed_methods();
}
