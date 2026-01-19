# Execution Kernel

A verifiable execution environment for bounded financial agents using RISC Zero zkVM.

## Overview

This project enables third-party agents to operate on delegated capital **without custody and without trust**, under cryptographically enforced constraints.

**Key Properties:**
- **Deterministic**: Same inputs always produce same outputs
- **Auditable**: All execution is recorded and verifiable  
- **Risk-bounded**: Agents cannot exceed predefined limits
- **Cryptographically verifiable**: Zero-knowledge proofs guarantee correct execution

## Architecture

```
Agent Input (VaultState + MarketState + Params)
        ↓
ExecutionKernel (Constraint Validation + Resource Tracking)
        ↓
Agent.execute() (Pure function, deterministic)
        ↓
AgentAction (Proposed action + metadata)
        ↓
zkVM Proof Generation (RISC Zero)
        ↓
On-chain Verification (Boundless + Vault Settlement)
```

## Project Structure

```
execution-kernel/
├── src/                    # Core execution kernel library
│   ├── agent.rs           # Agent trait and implementations
│   ├── constraints.rs     # Financial/operational/safety constraints  
│   ├── executor.rs        # Sandboxed execution environment
│   ├── vault.rs          # Vault state management
│   └── market.rs         # Market data structures
├── examples/              # Working demonstrations
├── simple-ai-agent/       # Reference implementation (trading signals)
└── SPECIFICATION.md       # Detailed technical specification
```

## Quick Start

### Run the Demo

```bash
cargo run --example basic_usage
```

This demonstrates a complete agent execution cycle:
- TrendFollowingAgent analyzing market volatility
- ExecutionKernel enforcing constraints
- Resource tracking and violation detection
- AgentAction generation with confidence scores

### Core Usage

```rust
use execution_kernel::{TrendFollowingAgent, ExecutionKernel, ConstraintSet};

// Create agent and execution environment
let agent = TrendFollowingAgent::new();
let mut kernel = ExecutionKernel::new(ConstraintSet::default());

// Execute with full constraint validation
let result = kernel.execute_agent(
    &agent, &vault_state, &market_state, &params, context
)?;

if result.execution_metadata.success {
    println!("Action: {:?}", result.action.action_type);
}
```

## Current Status

**✅ Milestone 1 Complete**: Core execution kernel with Agent trait and constraint system

**🚧 In Progress**: 
- Milestone 2: RISC Zero zkVM integration
- Milestone 3: Enhanced vault contracts
- Milestone 4: Boundless proof pipeline

## Reference Implementation

The `simple-ai-agent/` directory contains a working RISC Zero application that demonstrates:
- Linear regression trading signal generation
- End-to-end proof generation with Boundless
- Smart contract verification on Base mainnet
- **Live contract**: `0xEe747ac1869f9F805dCa40Ef2E6197C2F2e25f16`

## Security Model

The system enforces safety through multiple layers:
- **Sandboxing**: Agents cannot access external resources  
- **Resource Limits**: CPU, memory, and time constraints
- **Financial Bounds**: Position size and risk limits
- **Determinism**: Fully reproducible execution
- **Constraint Proofs**: All violations are cryptographically proven

## Development

### Building
```bash
cargo build
cargo test
```

### Documentation
```bash
cargo doc --open
```

### Running Tests
```bash
cargo test --all
```

## Architecture Philosophy

> "This protocol is **not about intelligence**. It is about **control**. 
> 
> It turns untrusted computation into a **verifiable, bounded economic actor**."

The execution kernel provides **infrastructure over strategies** - enabling any agent to operate safely within cryptographically enforced bounds, regardless of its internal logic or complexity.

---

See [SPECIFICATION.md](SPECIFICATION.md) for detailed technical requirements and implementation roadmap.