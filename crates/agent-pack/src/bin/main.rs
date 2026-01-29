//! Agent Pack CLI - Create and verify agent bundles.

use agent_pack::{
    format_hex, sha256_file, validate_hex_32, verify_manifest_structure,
    verify_manifest_with_files, AgentPackManifest,
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
        eprintln!("Error: invalid version '{}' - must be semver format (e.g., 1.0.0)", version);
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
                eprintln!("Error: could not create directory {}: {}", parent.display(), e);
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
    println!("  Agent: {} v{}", manifest.agent_name, manifest.agent_version);
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

/// Simple semver validation (same as in verify.rs)
fn is_valid_semver(version: &str) -> bool {
    let parts: Vec<&str> = version.split(|c| c == '-' || c == '+').collect();
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
