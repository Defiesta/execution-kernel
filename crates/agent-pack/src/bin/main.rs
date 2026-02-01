//! Agent Pack CLI - Create and verify agent bundles.

#[cfg(feature = "onchain")]
use agent_pack::onchain::{verify_onchain_with_timeout, OnchainError, OnchainVerifyResult};
use agent_pack::{
    format_hex, pack_bundle, scaffold, sha256_file, validate_hex_32, verify_manifest_structure,
    verify_manifest_with_files, AgentPackManifest, PackOptions, ScaffoldOptions, TemplateType,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "agent-pack")]
#[command(about = "Create and verify Agent Pack bundles for verifiable agent distribution")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Agent Pack manifest with placeholder values
    Init {
        /// Agent name (e.g., "yield-agent")
        #[arg(short, long)]
        name: String,

        /// Agent version in semver format (e.g., "1.0.0")
        #[arg(short, long)]
        version: String,

        /// 32-byte agent ID as hex with 0x prefix
        #[arg(short, long)]
        agent_id: String,

        /// Output file path [default: ./dist/agent-pack.json]
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Compute hashes from ELF binary and update manifest
    Compute {
        /// Path to the ELF binary
        #[arg(short, long)]
        elf: PathBuf,

        /// Path to manifest file to update [default: ./dist/agent-pack.json]
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Path to Cargo.lock for hash computation
        #[arg(long)]
        cargo_lock: Option<PathBuf>,
    },

    /// Verify an Agent Pack manifest
    Verify {
        /// Path to manifest file [default: ./dist/agent-pack.json]
        #[arg(short, long)]
        manifest: Option<PathBuf>,

        /// Base directory for resolving relative paths
        #[arg(short, long)]
        base_dir: Option<PathBuf>,

        /// Only verify manifest structure, skip file verification
        #[arg(long)]
        structure_only: bool,
    },

    /// Create a distributable Agent Pack bundle
    Pack {
        /// Path to input manifest (may contain placeholders)
        #[arg(short, long)]
        manifest: PathBuf,

        /// Path to the built zkVM guest ELF binary
        #[arg(short, long)]
        elf: PathBuf,

        /// Output directory for the bundle
        #[arg(short, long)]
        out: PathBuf,

        /// Path to Cargo.lock for hash computation
        #[arg(long)]
        cargo_lock: Option<PathBuf>,

        /// Copy ELF into bundle artifacts folder [default: true]
        #[arg(long, default_value = "true")]
        copy_elf: bool,

        /// Overwrite existing files in output directory
        #[arg(long)]
        force: bool,
    },

    /// Verify agent registration on-chain
    #[cfg(feature = "onchain")]
    VerifyOnchain {
        /// Path to manifest file
        #[arg(short, long)]
        manifest: PathBuf,

        /// RPC endpoint URL (e.g., https://sepolia.infura.io/v3/YOUR_KEY)
        #[arg(long)]
        rpc: String,

        /// KernelExecutionVerifier contract address
        #[arg(long)]
        verifier: String,

        /// RPC timeout in milliseconds
        #[arg(long, default_value = "30000")]
        timeout_ms: u64,
    },

    /// Generate a new agent project from template
    Scaffold {
        /// Agent project name (e.g., "my-yield-agent")
        name: String,

        /// Pre-set agent ID (64-character hex string with 0x prefix)
        #[arg(
            long,
            default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
        )]
        agent_id: String,

        /// Output directory (defaults to ./<name>)
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Template type: minimal | yield
        #[arg(long, default_value = "minimal")]
        template: String,

        /// Skip git init
        #[arg(long)]
        no_git: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            name,
            version,
            agent_id,
            out,
        } => cmd_init(name, version, agent_id, out),
        Commands::Compute {
            elf,
            out,
            cargo_lock,
        } => cmd_compute(elf, out, cargo_lock),
        Commands::Verify {
            manifest,
            base_dir,
            structure_only,
        } => cmd_verify(manifest, base_dir, structure_only),
        Commands::Pack {
            manifest,
            elf,
            out,
            cargo_lock,
            copy_elf,
            force,
        } => cmd_pack(manifest, elf, out, cargo_lock, copy_elf, force),
        #[cfg(feature = "onchain")]
        Commands::VerifyOnchain {
            manifest,
            rpc,
            verifier,
            timeout_ms,
        } => cmd_verify_onchain(manifest, rpc, verifier, timeout_ms),
        Commands::Scaffold {
            name,
            agent_id,
            out,
            template,
            no_git,
        } => cmd_scaffold(name, agent_id, out, template, no_git),
    }
}

fn cmd_init(name: String, version: String, agent_id: String, out: Option<PathBuf>) -> ExitCode {
    // Validate agent_id format
    if let Err(e) = validate_hex_32(&agent_id) {
        eprintln!("Error: invalid agent_id: {}", e);
        return ExitCode::FAILURE;
    }

    // Validate version is semver-like
    if !is_valid_semver(&version) {
        eprintln!(
            "Error: invalid version '{}' - must be semver format (e.g., 1.0.0)",
            version
        );
        return ExitCode::FAILURE;
    }

    // Create manifest
    let manifest = AgentPackManifest::new_template(name, version, agent_id);

    // Determine output path
    let out_path = out.unwrap_or_else(|| PathBuf::from("./dist/agent-pack.json"));

    // Create parent directory if needed
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "Error: could not create directory {}: {}",
                    parent.display(),
                    e
                );
                return ExitCode::FAILURE;
            }
        }
    }

    // Write manifest
    if let Err(e) = manifest.to_file(&out_path) {
        eprintln!("Error: could not write manifest: {}", e);
        return ExitCode::FAILURE;
    }

    println!("Created Agent Pack manifest: {}", out_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Fill in the 'inputs' and 'actions_profile' fields");
    println!("  2. Run 'agent-pack compute --elf <path>' to compute hashes");
    println!("  3. Run 'agent-pack verify' to validate the manifest");

    ExitCode::SUCCESS
}

fn cmd_compute(elf: PathBuf, out: Option<PathBuf>, cargo_lock: Option<PathBuf>) -> ExitCode {
    // Check ELF exists
    if !elf.exists() {
        eprintln!("Error: ELF file not found: {}", elf.display());
        return ExitCode::FAILURE;
    }

    // Compute ELF hash
    let elf_hash = match sha256_file(&elf) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: could not read ELF file: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let elf_sha256 = format_hex(&elf_hash);

    // Compute IMAGE_ID if risc0 feature is enabled
    #[cfg(feature = "risc0")]
    let image_id = {
        use agent_pack::compute_image_id_from_file;
        match compute_image_id_from_file(&elf) {
            Ok(id) => Some(format_hex(&id)),
            Err(e) => {
                eprintln!("Warning: could not compute IMAGE_ID: {}", e);
                None
            }
        }
    };

    #[cfg(not(feature = "risc0"))]
    let image_id: Option<String> = {
        eprintln!("Note: IMAGE_ID computation requires --features risc0");
        None
    };

    // Compute Cargo.lock hash if provided
    let cargo_lock_sha256 = if let Some(lock_path) = cargo_lock {
        match sha256_file(&lock_path) {
            Ok(h) => Some(format_hex(&h)),
            Err(e) => {
                eprintln!("Warning: could not read Cargo.lock: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Determine manifest path
    let manifest_path = out.unwrap_or_else(|| PathBuf::from("./dist/agent-pack.json"));

    // Load or create manifest
    let mut manifest = if manifest_path.exists() {
        match AgentPackManifest::from_file(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Error: could not read manifest: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("Error: manifest not found: {}", manifest_path.display());
        eprintln!("Run 'agent-pack init' first to create a manifest");
        return ExitCode::FAILURE;
    };

    // Update manifest
    manifest.artifacts.elf_sha256 = elf_sha256.clone();
    manifest.artifacts.elf_path = elf.to_string_lossy().to_string();

    if let Some(id) = image_id.clone() {
        manifest.image_id = id;
    }

    if let Some(lock_hash) = cargo_lock_sha256.clone() {
        manifest.build.cargo_lock_sha256 = lock_hash;
    }

    // Write updated manifest
    if let Err(e) = manifest.to_file(&manifest_path) {
        eprintln!("Error: could not write manifest: {}", e);
        return ExitCode::FAILURE;
    }

    println!("Updated manifest: {}", manifest_path.display());
    println!();
    println!("Computed values:");
    println!("  elf_sha256: {}", elf_sha256);
    if let Some(id) = image_id {
        println!("  image_id:   {}", id);
    }
    if let Some(lock_hash) = cargo_lock_sha256 {
        println!("  cargo_lock_sha256: {}", lock_hash);
    }

    ExitCode::SUCCESS
}

fn cmd_verify(
    manifest: Option<PathBuf>,
    base_dir: Option<PathBuf>,
    structure_only: bool,
) -> ExitCode {
    let manifest_path = manifest.unwrap_or_else(|| PathBuf::from("./dist/agent-pack.json"));

    // Load manifest
    let manifest = match AgentPackManifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: could not read manifest: {}", e);
            return ExitCode::FAILURE;
        }
    };

    println!("Verifying: {}", manifest_path.display());
    println!(
        "  Agent: {} v{}",
        manifest.agent_name, manifest.agent_version
    );
    println!("  Agent ID: {}", manifest.agent_id);
    println!();

    // Run verification
    let report = if structure_only {
        verify_manifest_structure(&manifest)
    } else {
        let base = base_dir.unwrap_or_else(|| {
            manifest_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
        });
        verify_manifest_with_files(&manifest, &base)
    };

    // Print report
    println!("{}", report);

    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_pack(
    manifest: PathBuf,
    elf: PathBuf,
    out: PathBuf,
    cargo_lock: Option<PathBuf>,
    copy_elf: bool,
    force: bool,
) -> ExitCode {
    let options = PackOptions { copy_elf, force };

    println!("Creating Agent Pack bundle...");
    println!("  Manifest: {}", manifest.display());
    println!("  ELF:      {}", elf.display());
    println!("  Output:   {}", out.display());
    println!();

    match pack_bundle(&manifest, &elf, &out, cargo_lock.as_deref(), &options) {
        Ok(result) => {
            println!("Bundle created successfully!");
            println!();
            println!("Output files:");
            println!("  {}", result.manifest_path.display());
            if let Some(elf_path) = &result.elf_path {
                println!("  {}", elf_path.display());
            }
            println!();
            println!("Computed values:");
            println!("  elf_sha256: {}", result.elf_sha256);
            if let Some(id) = &result.image_id {
                println!("  image_id:   {}", id);
            } else {
                println!("  image_id:   (not computed - build with --features risc0)");
            }
            if let Some(lock_hash) = &result.cargo_lock_sha256 {
                println!("  cargo_lock_sha256: {}", lock_hash);
            }
            println!();
            println!("Verify the bundle with:");
            println!(
                "  agent-pack verify --manifest {} --base-dir {}",
                result.manifest_path.display(),
                out.display()
            );

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn cmd_scaffold(
    name: String,
    agent_id: String,
    out: Option<PathBuf>,
    template: String,
    no_git: bool,
) -> ExitCode {
    // Validate agent_id format
    let agent_id_bytes = match parse_agent_id(&agent_id) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: invalid agent_id: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Parse template type
    let template_type = match TemplateType::parse(&template) {
        Some(t) => t,
        None => {
            eprintln!(
                "Error: invalid template '{}' - must be 'minimal' or 'yield'",
                template
            );
            return ExitCode::FAILURE;
        }
    };

    // Determine output directory
    let output_dir = out.unwrap_or_else(|| PathBuf::from(&name));

    // Build options
    let options = ScaffoldOptions {
        name: name.clone(),
        agent_id: agent_id_bytes,
        output_dir: output_dir.clone(),
        template: template_type,
        init_git: !no_git,
    };

    // Run scaffold
    match scaffold(&options) {
        Ok(result) => {
            println!("✓ Created {}/", result.project_dir.display());
            println!(
                "✓ Generated agent crate ({}/agent/)",
                result.project_dir.display()
            );
            println!(
                "✓ Generated wrapper crate ({}/wrapper/)",
                result.project_dir.display()
            );
            println!(
                "✓ Generated test crate ({}/tests/)",
                result.project_dir.display()
            );
            println!(
                "✓ Generated manifest ({}/dist/agent-pack.json)",
                result.project_dir.display()
            );
            if result.git_initialized {
                println!("✓ Initialized git repository");
            }
            println!();
            println!("Next steps:");
            println!("  cd {}", result.project_dir.display());
            println!("  cargo build                    # Build and compute AGENT_CODE_HASH");
            println!("  cargo test                     # Run unit tests");
            println!("  agent-pack compute --elf ...   # Compute hashes after zkVM build");

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Parse agent ID from hex string to bytes.
fn parse_agent_id(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);

    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }

    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;

    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())
}

/// Simple semver validation (same as in verify.rs)
fn is_valid_semver(version: &str) -> bool {
    let parts: Vec<&str> = version.split(['-', '+']).collect();
    if parts.is_empty() {
        return false;
    }

    let version_core: Vec<&str> = parts[0].split('.').collect();
    if version_core.len() != 3 {
        return false;
    }

    for part in version_core {
        if part.is_empty() || part.parse::<u64>().is_err() {
            return false;
        }
    }

    true
}

/// Exit code values for verify-onchain command.
///
/// Following Unix conventions, different exit codes signal different outcomes:
/// - 0: Match - agent is registered and image_id matches
/// - 1: Error - RPC failure, invalid manifest, etc.
/// - 2: Mismatch - agent is registered but image_id differs
/// - 3: Not Registered - agent_id returns bytes32(0)
#[cfg(feature = "onchain")]
mod exit_codes {
    use std::process::ExitCode;

    pub const MATCH: ExitCode = ExitCode::SUCCESS;
    pub const ERROR: ExitCode = ExitCode::FAILURE;

    pub fn mismatch() -> ExitCode {
        ExitCode::from(2)
    }

    pub fn not_registered() -> ExitCode {
        ExitCode::from(3)
    }
}

#[cfg(feature = "onchain")]
fn cmd_verify_onchain(
    manifest_path: PathBuf,
    rpc_url: String,
    verifier_address: String,
    timeout_ms: u64,
) -> ExitCode {
    // Load manifest
    let manifest = match AgentPackManifest::from_file(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: could not read manifest: {}", e);
            return exit_codes::ERROR;
        }
    };

    // Validate manifest has required fields
    if manifest.agent_id.contains("TODO") {
        eprintln!("Error: manifest agent_id contains placeholder value");
        return exit_codes::ERROR;
    }
    if manifest.image_id.contains("TODO") {
        eprintln!("Error: manifest image_id contains placeholder value");
        return exit_codes::ERROR;
    }

    println!("Verifying on-chain registration...");
    println!(
        "  Agent: {} v{}",
        manifest.agent_name, manifest.agent_version
    );
    println!("  Agent ID: {}", manifest.agent_id);
    println!("  Image ID: {}", manifest.image_id);
    println!("  Verifier: {}", verifier_address);
    println!();

    // Create tokio runtime and execute
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to create async runtime: {}", e);
            return exit_codes::ERROR;
        }
    };

    let result = runtime.block_on(verify_onchain_with_timeout(
        &rpc_url,
        &verifier_address,
        &manifest.agent_id,
        &manifest.image_id,
        timeout_ms,
    ));

    match result {
        Ok(OnchainVerifyResult::Match) => {
            println!("PASS: On-chain image_id matches manifest");
            println!();
            println!("The agent is registered and its image_id matches the manifest.");
            exit_codes::MATCH
        }
        Ok(OnchainVerifyResult::Mismatch { onchain, manifest }) => {
            eprintln!("FAIL: On-chain image_id does not match manifest");
            eprintln!();
            eprintln!("  On-chain:  {}", onchain);
            eprintln!("  Manifest:  {}", manifest);
            eprintln!();
            eprintln!("The agent is registered but with a different image_id.");
            eprintln!("This may indicate a version mismatch or unauthorized modification.");
            exit_codes::mismatch()
        }
        Ok(OnchainVerifyResult::NotRegistered) => {
            eprintln!("FAIL: Agent is not registered on-chain");
            eprintln!();
            eprintln!("The agent_id {} returns bytes32(0).", manifest.agent_id);
            eprintln!("The agent must be registered before verification can succeed.");
            exit_codes::not_registered()
        }
        Err(e) => {
            eprintln!("Error: {}", format_onchain_error(&e));
            exit_codes::ERROR
        }
    }
}

#[cfg(feature = "onchain")]
fn format_onchain_error(e: &OnchainError) -> String {
    match e {
        OnchainError::InvalidRpcUrl(msg) => format!("Invalid RPC URL: {}", msg),
        OnchainError::InvalidVerifierAddress(msg) => {
            format!("Invalid verifier address: {}", msg)
        }
        OnchainError::InvalidAgentId(msg) => format!("Invalid agent_id in manifest: {}", msg),
        OnchainError::InvalidImageId(msg) => format!("Invalid image_id in manifest: {}", msg),
        OnchainError::RpcError(msg) => format!("RPC call failed: {}", msg),
    }
}
