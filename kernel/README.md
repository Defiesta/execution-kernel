# Execution Kernel

A verifiable execution kernel for bounded financial agents using RISC Zero zkVM.

## Overview

The execution kernel provides a sandboxed environment for financial agents to operate on delegated capital with cryptographically enforced constraints. It ensures that agent behavior is:

- **Deterministic**: Same inputs always produce same outputs
- **Auditable**: All execution is recorded and verifiable  
- **Risk-bounded**: Agents cannot exceed predefined limits
- **Cryptographically verifiable**: Proofs guarantee correct execution

## Core Components

### Agent Trait

The `Agent` trait defines the interface that all financial agents must implement:

```rust
pub trait Agent {
    fn execute(
        &self,
        vault_state: &VaultState,
        market_state: &MarketState,
        params: &AgentParams,
    ) -> Result<AgentAction>;
    
    fn validate_constraints(&self, constraints: &ConstraintSet) -> Result<()>;
    fn agent_hash(&self) -> [u8; 32];
    fn metadata(&self) -> AgentMetadata;
}
```

### Execution Kernel

The `ExecutionKernel` provides sandboxed execution with constraint validation:

- Pre-execution validation (nonce, state consistency, constraints)
- Resource tracking (cycles, memory, time)
- Post-execution validation (action constraints, capital requirements)
- Deterministic execution environment

### Constraint System

Three types of constraints ensure safe execution:

1. **Financial Constraints**: Position size, leverage, drawdown, asset whitelist
2. **Operational Constraints**: Compute cycles, memory, timeouts, rate limiting  
3. **Safety Constraints**: No external calls, deterministic execution, bounded loops

## Quick Start

```rust
use execution_kernel::{
    TrendFollowingAgent, VaultState, MarketState, ExecutionKernel,
    ConstraintSet, ExecutionContext, AgentParams,
};

// Create agent and execution environment
let agent = TrendFollowingAgent::new();
let vault_state = VaultState::new(1, owner_address, initial_capital);
let market_state = MarketState::new(timestamp, block_number);
let mut kernel = ExecutionKernel::new(ConstraintSet::default());

// Execute agent with constraints
let result = kernel.execute_agent(
    &agent,
    &vault_state, 
    &market_state,
    &AgentParams::default(),
    ExecutionContext::new(vault_id, agent_hash, nonce, timestamp)
)?;

// Check results
if result.execution_metadata.success {
    println!("Action: {:?}", result.action);
} else {
    println!("Execution failed: {:?}", result.execution_metadata.error_message);
}
```

## Running the Example

```bash
cargo run --example basic_usage
```

This demonstrates a complete agent execution cycle with constraint validation.

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
Post-execution Validation (Financial constraints)
        ↓
ExecutionResult (Action + resource usage + violations)
```

## Integration with zkVM

In production, the execution kernel runs inside RISC Zero zkVM:

1. **Input**: Serialized vault state + market state + agent parameters
2. **Execution**: Kernel validates constraints and executes agent
3. **Output**: Journal with agent action + constraint validation results
4. **Proof**: RISC Zero proof of correct execution within constraints

## Security Model

The kernel enforces safety through multiple layers:

- **Sandboxing**: Agents cannot access external resources
- **Resource Limits**: CPU, memory, and time constraints prevent DoS
- **Financial Bounds**: Position size and risk limits prevent catastrophic losses
- **Determinism**: Execution is fully deterministic and reproducible
- **Constraint Proofs**: All constraint violations are cryptographically proven

## Next Steps

1. **zkVM Integration**: Implement guest program using this kernel
2. **Vault Contracts**: Smart contracts for capital custody and settlement
3. **Proof Pipeline**: RISC Zero proof generation and Boundless verification
4. **Agent Registry**: System for registering and managing agents
5. **Settlement Layer**: On-chain execution of validated agent actions