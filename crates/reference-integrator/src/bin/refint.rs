//! Reference Integrator CLI - Demonstrate the complete integration flow.
//!
//! This CLI provides commands to:
//! - Verify Agent Pack bundles (offline and on-chain)
//! - Generate proofs from bundles
//! - Execute proven results on-chain
//!
//! Exit codes:
//!   0 - Success
//!   1 - Invalid usage / parsing error
//!   2 - Verification mismatch (hash or imageId)
//!   3 - Agent not registered on-chain
//!   4 - Proving failure
//!   5 - On-chain transaction failure

use clap::{Parser, Subcommand};
use reference_integrator::{feature_status, verify_offline, verify_structure, LoadedBundle};
use serde::Serialize;

#[cfg(feature = "prove")]
use reference_integrator::{build_and_encode_input, parse_hex, InputParams};
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit codes for the CLI
#[allow(dead_code)]
mod exit_codes {
    use std::process::ExitCode;

    pub fn success() -> ExitCode {
        ExitCode::SUCCESS
    }
    pub fn invalid_usage() -> ExitCode {
        ExitCode::from(1)
    }
    pub fn verification_mismatch() -> ExitCode {
        ExitCode::from(2)
    }
    pub fn not_registered() -> ExitCode {
        ExitCode::from(3)
    }
    pub fn proving_failure() -> ExitCode {
        ExitCode::from(4)
    }
    pub fn tx_failure() -> ExitCode {
        ExitCode::from(5)
    }
}

#[derive(Parser)]
#[command(name = "refint")]
#[command(about = "Reference Integrator - Demonstrate Agent Pack integration flow")]
#[command(version)]
#[command(long_about = "
A reference implementation showing how external integrators (marketplaces, backends)
can ingest Agent Pack bundles and safely execute agents end-to-end.

WORKFLOW:
  1. Load bundle with 'verify' command to check offline validity
  2. Optionally verify on-chain registration with --rpc and --verifier
  3. Generate proof with 'prove' command
  4. Execute on-chain with 'execute' command

EXIT CODES:
  0 - Success
  1 - Invalid usage / parsing error
  2 - Verification mismatch (hash or imageId)
  3 - Agent not registered on-chain
  4 - Proving failure
  5 - On-chain transaction failure

FEATURES:
  The CLI functionality depends on which features are enabled:
  - Default: verify (offline only)
  - --features onchain: verify (on-chain) + execute
  - --features prove: prove
  - --features full: all commands
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an Agent Pack bundle
    ///
    /// Performs offline verification by default (structure, hashes, imageId).
    /// With --rpc and --verifier, also performs on-chain verification.
    Verify {
        /// Path to the bundle directory
        #[arg(short, long)]
        bundle: PathBuf,

        /// RPC endpoint URL for on-chain verification
        #[arg(long)]
        rpc: Option<String>,

        /// KernelExecutionVerifier contract address for on-chain verification
        #[arg(long)]
        verifier: Option<String>,

        /// Only verify manifest structure, skip file verification
        #[arg(long)]
        structure_only: bool,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Generate a proof from a bundle
    ///
    /// Requires the 'prove' feature to be enabled.
    Prove {
        /// Path to the bundle directory
        #[arg(short, long)]
        bundle: PathBuf,

        /// Opaque agent inputs as hex string (0x prefixed) or @filepath
        #[arg(long)]
        opaque_inputs: Option<String>,

        /// Execution nonce for replay protection
        #[arg(long, default_value = "1")]
        nonce: u64,

        /// Constraint set hash as hex (0x prefixed)
        #[arg(long)]
        constraint_set_hash: Option<String>,

        /// Input root as hex (0x prefixed)
        #[arg(long)]
        input_root: Option<String>,

        /// Output directory for proof artifacts
        #[arg(short, long)]
        out: PathBuf,

        /// Use dev mode (faster, not verifiable on-chain)
        #[arg(long)]
        dev: bool,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Execute a proven result on-chain
    ///
    /// Requires the 'onchain' feature to be enabled.
    Execute {
        /// Path to the bundle directory
        #[arg(short, long)]
        bundle: PathBuf,

        /// KernelVault contract address
        #[arg(long)]
        vault: String,

        /// RPC endpoint URL
        #[arg(long)]
        rpc: String,

        /// Private key for signing (0x prefixed hex, or env:VAR_NAME)
        #[arg(long)]
        pk: String,

        /// Path to journal bytes file (from prove output)
        #[arg(long)]
        journal: PathBuf,

        /// Path to seal bytes file (from prove output)
        #[arg(long)]
        seal: PathBuf,

        /// Path to agent output bytes file (from prove output)
        #[arg(long)]
        agent_output: PathBuf,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Show feature status or inspect proof artifacts
    ///
    /// Without arguments, shows feature availability.
    /// With --artifacts-dir, reads and summarizes proof output.
    Status {
        /// Path to proof artifacts directory to inspect
        #[arg(long)]
        artifacts_dir: Option<PathBuf>,

        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
}

// JSON output structures

#[derive(Serialize)]
struct VerifyOutput {
    success: bool,
    agent_name: String,
    agent_version: String,
    agent_id: String,
    offline_passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_status: Option<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ProveOutput {
    success: bool,
    agent_name: String,
    agent_version: String,
    journal_path: String,
    seal_path: String,
    journal_size: usize,
    seal_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ExecuteOutput {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct StatusOutput {
    version: String,
    features: StatusFeatures,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifacts: Option<ArtifactsInfo>,
}

#[derive(Serialize)]
struct StatusFeatures {
    cli: bool,
    onchain: bool,
    prove: bool,
}

#[derive(Serialize)]
struct ArtifactsInfo {
    journal_size: usize,
    seal_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_status: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            bundle,
            rpc,
            verifier,
            structure_only,
            json,
        } => cmd_verify(bundle, rpc, verifier, structure_only, json),
        Commands::Prove {
            bundle,
            opaque_inputs,
            nonce,
            constraint_set_hash,
            input_root,
            out,
            dev,
            json,
        } => cmd_prove(
            bundle,
            opaque_inputs,
            nonce,
            constraint_set_hash,
            input_root,
            out,
            dev,
            json,
        ),
        Commands::Execute {
            bundle,
            vault,
            rpc,
            pk,
            journal,
            seal,
            agent_output,
            json,
        } => cmd_execute(bundle, vault, rpc, pk, journal, seal, agent_output, json),
        Commands::Status {
            artifacts_dir,
            json,
        } => cmd_status(artifacts_dir, json),
    }
}

fn cmd_verify(
    bundle_path: PathBuf,
    rpc: Option<String>,
    verifier: Option<String>,
    structure_only: bool,
    json_output: bool,
) -> ExitCode {
    let mut output = VerifyOutput {
        success: false,
        agent_name: String::new(),
        agent_version: String::new(),
        agent_id: String::new(),
        offline_passed: false,
        onchain_passed: None,
        onchain_status: None,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Load bundle
    if !json_output {
        println!("Loading bundle from: {}", bundle_path.display());
    }

    let bundle = match LoadedBundle::load(&bundle_path) {
        Ok(b) => b,
        Err(e) => {
            let error_msg = format!("Failed to load bundle: {}", e);
            if json_output {
                output.errors.push(error_msg);
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                eprintln!("Error: {}", error_msg);
            }
            return exit_codes::invalid_usage();
        }
    };

    output.agent_name = bundle.manifest.agent_name.clone();
    output.agent_version = bundle.manifest.agent_version.clone();
    output.agent_id = bundle.manifest.agent_id.clone();

    if !json_output {
        println!(
            "  Agent: {} v{}",
            bundle.manifest.agent_name, bundle.manifest.agent_version
        );
        println!("  Agent ID: {}", bundle.manifest.agent_id);
        println!();
        println!("Running offline verification...");
    }

    // Offline verification
    let result = if structure_only {
        verify_structure(&bundle)
    } else {
        verify_offline(&bundle)
    };

    output.offline_passed = result.passed;
    output.errors = result.report.errors.iter().map(|e| e.to_string()).collect();
    output.warnings = result
        .report
        .warnings
        .iter()
        .map(|w| w.to_string())
        .collect();

    if !json_output {
        println!("{}", result.report);
    }

    if !result.passed {
        output.success = false;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            eprintln!("Offline verification FAILED");
        }
        return exit_codes::verification_mismatch();
    }

    if !json_output {
        println!("Offline verification PASSED");
    }

    // On-chain verification (if requested)
    #[allow(unused_variables)]
    if let (Some(rpc_url), Some(verifier_addr)) = (rpc, verifier) {
        #[cfg(feature = "onchain")]
        {
            if !json_output {
                println!();
                println!("Running on-chain verification...");
                println!("  RPC: {}", rpc_url);
                println!("  Verifier: {}", verifier_addr);
            }

            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let error_msg = format!("Failed to create runtime: {}", e);
                    if json_output {
                        output.errors.push(error_msg);
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        eprintln!("Error: {}", error_msg);
                    }
                    return exit_codes::invalid_usage();
                }
            };

            let onchain_result = rt.block_on(reference_integrator::verify_onchain(
                &bundle,
                &rpc_url,
                &verifier_addr,
            ));

            match onchain_result {
                Ok(reference_integrator::OnchainVerificationResult::Match) => {
                    output.onchain_passed = Some(true);
                    output.onchain_status = Some("match".to_string());
                    output.success = true;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        println!();
                        println!("On-chain verification PASSED");
                        println!("  Image ID matches on-chain registry");
                    }
                    return exit_codes::success();
                }
                Ok(reference_integrator::OnchainVerificationResult::Mismatch {
                    onchain,
                    manifest,
                }) => {
                    output.onchain_passed = Some(false);
                    output.onchain_status = Some("mismatch".to_string());
                    output.errors.push(format!(
                        "Image ID mismatch: on-chain={}, manifest={}",
                        onchain, manifest
                    ));
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        eprintln!();
                        eprintln!("On-chain verification FAILED: Image ID mismatch");
                        eprintln!("  On-chain:  {}", onchain);
                        eprintln!("  Manifest:  {}", manifest);
                    }
                    return exit_codes::verification_mismatch();
                }
                Ok(reference_integrator::OnchainVerificationResult::NotRegistered) => {
                    output.onchain_passed = Some(false);
                    output.onchain_status = Some("not_registered".to_string());
                    output.errors.push(format!(
                        "Agent {} is not registered on-chain",
                        bundle.manifest.agent_id
                    ));
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        eprintln!();
                        eprintln!("On-chain verification FAILED: Agent not registered");
                        eprintln!(
                            "  The agent_id {} is not registered on-chain",
                            bundle.manifest.agent_id
                        );
                    }
                    return exit_codes::not_registered();
                }
                Err(e) => {
                    output
                        .errors
                        .push(format!("On-chain verification error: {}", e));
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        eprintln!();
                        eprintln!("On-chain verification ERROR: {}", e);
                    }
                    return exit_codes::invalid_usage();
                }
            }
        }

        #[cfg(not(feature = "onchain"))]
        {
            let error_msg = "On-chain verification requires --features onchain".to_string();
            if json_output {
                output.errors.push(error_msg);
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                eprintln!();
                eprintln!("Error: {}", error_msg);
                eprintln!("Rebuild with: cargo build -p reference-integrator --features onchain");
            }
            return exit_codes::invalid_usage();
        }
    }

    // No on-chain verification requested, offline passed
    output.success = true;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }
    exit_codes::success()
}

#[allow(unused_variables, clippy::too_many_arguments)]
fn cmd_prove(
    bundle_path: PathBuf,
    opaque_inputs: Option<String>,
    nonce: u64,
    constraint_set_hash: Option<String>,
    input_root: Option<String>,
    out_dir: PathBuf,
    dev_mode: bool,
    json_output: bool,
) -> ExitCode {
    #[cfg(not(feature = "prove"))]
    {
        if json_output {
            let output = ProveOutput {
                success: false,
                agent_name: String::new(),
                agent_version: String::new(),
                journal_path: String::new(),
                seal_path: String::new(),
                journal_size: 0,
                seal_size: 0,
                error: Some("Proving requires --features prove".to_string()),
            };
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            eprintln!("Error: Proving requires --features prove");
            eprintln!("Rebuild with: cargo build -p reference-integrator --features prove");
        }
        exit_codes::invalid_usage()
    }

    #[cfg(feature = "prove")]
    {
        use reference_integrator::{prove, ProvingMode};

        let mut output = ProveOutput {
            success: false,
            agent_name: String::new(),
            agent_version: String::new(),
            journal_path: String::new(),
            seal_path: String::new(),
            journal_size: 0,
            seal_size: 0,
            error: None,
        };

        // Load bundle
        if !json_output {
            println!("Loading bundle from: {}", bundle_path.display());
        }

        let bundle = match LoadedBundle::load(&bundle_path) {
            Ok(b) => b,
            Err(e) => {
                let error_msg = format!("Failed to load bundle: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        output.agent_name = bundle.manifest.agent_name.clone();
        output.agent_version = bundle.manifest.agent_version.clone();

        if !json_output {
            println!(
                "  Agent: {} v{}",
                bundle.manifest.agent_name, bundle.manifest.agent_version
            );
            println!();
        }

        // Parse opaque inputs
        let opaque_agent_inputs = match parse_opaque_inputs(opaque_inputs) {
            Ok(inputs) => inputs,
            Err(e) => {
                let error_msg = format!("Failed to parse opaque inputs: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        // Parse constraint set hash
        let constraint_set_hash_bytes = match parse_optional_hex_32(constraint_set_hash) {
            Ok(hash) => hash.unwrap_or([0u8; 32]),
            Err(e) => {
                let error_msg = format!("Invalid constraint_set_hash: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        // Parse input root
        let input_root_bytes = match parse_optional_hex_32(input_root) {
            Ok(root) => root.unwrap_or([0u8; 32]),
            Err(e) => {
                let error_msg = format!("Invalid input_root: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        // Build input params
        let params = InputParams {
            constraint_set_hash: constraint_set_hash_bytes,
            input_root: input_root_bytes,
            execution_nonce: nonce,
            opaque_agent_inputs,
        };

        // Build and encode input
        if !json_output {
            println!("Building kernel input...");
        }

        let input_bytes = match build_and_encode_input(&bundle, &params) {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to build input: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        if !json_output {
            println!("  Input size: {} bytes", input_bytes.len());
        }

        // Read ELF
        if !json_output {
            println!("Loading ELF binary...");
        }

        let elf_bytes = match bundle.read_elf() {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to read ELF: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        if !json_output {
            println!("  ELF size: {} bytes", elf_bytes.len());
        }

        // Select proving mode
        let mode = if dev_mode {
            if !json_output {
                println!();
                println!("Using DEV mode (not verifiable on-chain)");
            }
            ProvingMode::Dev
        } else {
            if !json_output {
                println!();
                println!("Using Groth16 mode (verifiable on-chain)");
            }
            ProvingMode::Groth16
        };

        // Generate proof
        if !json_output {
            println!("Generating proof (this may take a while)...");
        }

        let proof_result = match prove(&elf_bytes, &input_bytes, mode) {
            Ok(result) => result,
            Err(e) => {
                let error_msg = format!("Proof generation failed: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::proving_failure();
            }
        };

        // Create output directory
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            let error_msg = format!("Failed to create output directory: {}", e);
            if json_output {
                output.error = Some(error_msg);
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                eprintln!("Error: {}", error_msg);
            }
            return exit_codes::invalid_usage();
        }

        // Write output files
        let journal_path = out_dir.join("journal.bin");
        let seal_path = out_dir.join("seal.bin");

        if let Err(e) = std::fs::write(&journal_path, &proof_result.journal_bytes) {
            let error_msg = format!("Failed to write journal: {}", e);
            if json_output {
                output.error = Some(error_msg);
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                eprintln!("Error: {}", error_msg);
            }
            return exit_codes::invalid_usage();
        }

        if let Err(e) = std::fs::write(&seal_path, &proof_result.seal_bytes) {
            let error_msg = format!("Failed to write seal: {}", e);
            if json_output {
                output.error = Some(error_msg);
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                eprintln!("Error: {}", error_msg);
            }
            return exit_codes::invalid_usage();
        }

        // Try to reconstruct agent output (for yield agent)
        let agent_output_path = out_dir.join("agent_output.bin");
        if let Ok(agent_output_bytes) =
            reference_integrator::reconstruct_yield_agent_output(&params.opaque_agent_inputs)
        {
            if let Err(e) = std::fs::write(&agent_output_path, &agent_output_bytes) {
                if !json_output {
                    eprintln!("Warning: Failed to write agent_output.bin: {}", e);
                }
            } else if !json_output {
                println!(
                    "  Agent output reconstructed: {} bytes",
                    agent_output_bytes.len()
                );
            }
        } else if !json_output {
            println!(
                "  Note: Could not reconstruct agent output (non-yield agent or invalid inputs)"
            );
        }

        output.success = true;
        output.journal_path = journal_path.display().to_string();
        output.seal_path = seal_path.display().to_string();
        output.journal_size = proof_result.journal_bytes.len();
        output.seal_size = proof_result.seal_bytes.len();

        if json_output {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            println!();
            println!("Proof generated successfully!");
            println!("  Journal size: {} bytes", proof_result.journal_bytes.len());
            println!("  Seal size: {} bytes", proof_result.seal_bytes.len());
            println!(
                "  Execution status: {:?}",
                proof_result.journal.execution_status
            );
            println!();
            println!("Output files:");
            println!("  {}", journal_path.display());
            println!("  {}", seal_path.display());
            println!();
            println!("NOTE: To execute on-chain, you also need the agent output bytes.");
            println!("      These are the raw action data that the agent produced.");
            println!("      The action_commitment in the journal is SHA256(agent_output_bytes).");
        }

        exit_codes::success()
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_execute(
    _bundle_path: PathBuf,
    _vault: String,
    _rpc: String,
    _pk: String,
    _journal_path: PathBuf,
    _seal_path: PathBuf,
    _agent_output_path: PathBuf,
    json_output: bool,
) -> ExitCode {
    #[cfg(not(feature = "onchain"))]
    {
        if json_output {
            let output = ExecuteOutput {
                success: false,
                tx_hash: None,
                block_number: None,
                error: Some("On-chain execution requires --features onchain".to_string()),
            };
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            eprintln!("Error: On-chain execution requires --features onchain");
            eprintln!("Rebuild with: cargo build -p reference-integrator --features onchain");
        }
        exit_codes::invalid_usage()
    }

    #[cfg(feature = "onchain")]
    {
        use reference_integrator::execute_onchain;

        let mut output = ExecuteOutput {
            success: false,
            tx_hash: None,
            block_number: None,
            error: None,
        };

        // Load bundle (for display purposes)
        if !json_output {
            println!("Loading bundle from: {}", _bundle_path.display());
        }

        let bundle = match LoadedBundle::load(&_bundle_path) {
            Ok(b) => b,
            Err(e) => {
                let error_msg = format!("Failed to load bundle: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        if !json_output {
            println!(
                "  Agent: {} v{}",
                bundle.manifest.agent_name, bundle.manifest.agent_version
            );
            println!();
            println!("Loading proof artifacts...");
        }

        // Read proof artifacts
        let journal_bytes = match std::fs::read(&_journal_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to read journal file: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        let seal_bytes = match std::fs::read(&_seal_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to read seal file: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        let agent_output_bytes = match std::fs::read(&_agent_output_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to read agent output file: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        if !json_output {
            println!("  Journal: {} bytes", journal_bytes.len());
            println!("  Seal: {} bytes", seal_bytes.len());
            println!("  Agent output: {} bytes", agent_output_bytes.len());
        }

        // Parse private key (support env: prefix)
        let pk = if let Some(var_name) = _pk.strip_prefix("env:") {
            match std::env::var(var_name) {
                Ok(val) => val,
                Err(_) => {
                    let error_msg = format!("Environment variable {} not set", var_name);
                    if json_output {
                        output.error = Some(error_msg);
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        eprintln!("Error: {}", error_msg);
                    }
                    return exit_codes::invalid_usage();
                }
            }
        } else {
            _pk
        };

        if !json_output {
            println!();
            println!("Executing on-chain...");
            println!("  Vault: {}", _vault);
            println!("  RPC: {}", _rpc);
        }

        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let error_msg = format!("Failed to create runtime: {}", e);
                if json_output {
                    output.error = Some(error_msg);
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!("Error: {}", error_msg);
                }
                return exit_codes::invalid_usage();
            }
        };

        let result = rt.block_on(execute_onchain(
            &_vault,
            &_rpc,
            &pk,
            &journal_bytes,
            &seal_bytes,
            &agent_output_bytes,
        ));

        match result {
            Ok(exec_result) => {
                output.tx_hash = Some(exec_result.tx_hash.clone());
                output.block_number = exec_result.block_number;

                if exec_result.success {
                    output.success = true;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        println!();
                        println!("Execution successful!");
                        println!("  Transaction: {}", exec_result.tx_hash);
                        if let Some(block) = exec_result.block_number {
                            println!("  Block: {}", block);
                        }
                        println!("  Status: Success");
                    }
                    exit_codes::success()
                } else {
                    output.error = Some("Transaction reverted".to_string());
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    } else {
                        println!();
                        println!("Transaction reverted");
                        println!("  Transaction: {}", exec_result.tx_hash);
                    }
                    exit_codes::tx_failure()
                }
            }
            Err(e) => {
                output.error = Some(format!("Execution failed: {}", e));
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    eprintln!();
                    eprintln!("Execution failed: {}", e);
                }
                exit_codes::tx_failure()
            }
        }
    }
}

fn cmd_status(artifacts_dir: Option<PathBuf>, json_output: bool) -> ExitCode {
    let mut output = StatusOutput {
        version: reference_integrator::VERSION.to_string(),
        features: StatusFeatures {
            cli: true,
            onchain: reference_integrator::is_onchain_available(),
            prove: reference_integrator::is_proving_available(),
        },
        artifacts: None,
    };

    // If artifacts directory provided, read and parse
    if let Some(dir) = artifacts_dir {
        let journal_path = dir.join("journal.bin");
        let seal_path = dir.join("seal.bin");

        let journal_bytes = match std::fs::read(&journal_path) {
            Ok(b) => b,
            Err(e) => {
                if json_output {
                    let error_output = serde_json::json!({
                        "error": format!("Failed to read journal.bin: {}", e)
                    });
                    println!("{}", serde_json::to_string_pretty(&error_output).unwrap());
                } else {
                    eprintln!("Error: Failed to read {}: {}", journal_path.display(), e);
                }
                return exit_codes::invalid_usage();
            }
        };

        let seal_bytes = match std::fs::read(&seal_path) {
            Ok(b) => b,
            Err(e) => {
                if json_output {
                    let error_output = serde_json::json!({
                        "error": format!("Failed to read seal.bin: {}", e)
                    });
                    println!("{}", serde_json::to_string_pretty(&error_output).unwrap());
                } else {
                    eprintln!("Error: Failed to read {}: {}", seal_path.display(), e);
                }
                return exit_codes::invalid_usage();
            }
        };

        let mut artifacts_info = ArtifactsInfo {
            journal_size: journal_bytes.len(),
            seal_size: seal_bytes.len(),
            protocol_version: None,
            kernel_version: None,
            agent_id: None,
            input_commitment: None,
            action_commitment: None,
            execution_status: None,
        };

        // Try to decode journal
        if let Ok(journal) = kernel_core::KernelJournalV1::decode(&journal_bytes) {
            artifacts_info.protocol_version = Some(journal.protocol_version);
            artifacts_info.kernel_version = Some(journal.kernel_version);
            artifacts_info.agent_id = Some(format!("0x{}", hex::encode(journal.agent_id)));
            artifacts_info.input_commitment =
                Some(format!("0x{}", hex::encode(journal.input_commitment)));
            artifacts_info.action_commitment =
                Some(format!("0x{}", hex::encode(journal.action_commitment)));
            artifacts_info.execution_status = Some(format!("{:?}", journal.execution_status));
        }

        output.artifacts = Some(artifacts_info);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("Reference Integrator v{}", output.version);
        println!();
        println!("{}", feature_status());

        if let Some(ref artifacts) = output.artifacts {
            println!();
            println!("Proof Artifacts:");
            println!("  Journal size: {} bytes", artifacts.journal_size);
            println!("  Seal size: {} bytes", artifacts.seal_size);

            if let Some(ref pv) = artifacts.protocol_version {
                println!();
                println!("Journal Contents:");
                println!("  Protocol version: {}", pv);
            }
            if let Some(ref kv) = artifacts.kernel_version {
                println!("  Kernel version: {}", kv);
            }
            if let Some(ref aid) = artifacts.agent_id {
                println!("  Agent ID: {}", aid);
            }
            if let Some(ref ic) = artifacts.input_commitment {
                println!("  Input commitment: {}", ic);
            }
            if let Some(ref ac) = artifacts.action_commitment {
                println!("  Action commitment: {}", ac);
            }
            if let Some(ref es) = artifacts.execution_status {
                println!("  Execution status: {}", es);
            }
        }

        if !reference_integrator::is_proving_available() {
            println!();
            println!("To enable proving, rebuild with:");
            println!("  cargo build -p reference-integrator --features prove");
        }

        if !reference_integrator::is_onchain_available() {
            println!();
            println!("To enable on-chain features, rebuild with:");
            println!("  cargo build -p reference-integrator --features onchain");
        }
    }

    exit_codes::success()
}

// Helper functions

#[cfg(feature = "prove")]
fn parse_opaque_inputs(input: Option<String>) -> Result<Vec<u8>, String> {
    match input {
        None => Ok(Vec::new()),
        Some(s) if s.starts_with('@') => {
            // Load from file
            let path = &s[1..];
            std::fs::read(path).map_err(|e| format!("Failed to read file {}: {}", path, e))
        }
        Some(s) => {
            // Parse as hex
            parse_hex(&s)
        }
    }
}

#[cfg(feature = "prove")]
fn parse_optional_hex_32(input: Option<String>) -> Result<Option<[u8; 32]>, String> {
    match input {
        None => Ok(None),
        Some(s) => {
            let bytes = parse_hex(&s)?;
            if bytes.len() != 32 {
                return Err(format!("Expected 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
    }
}

// Re-export for use in status command
use kernel_core::CanonicalDecode;
