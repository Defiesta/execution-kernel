# Execution Kernel Contracts

On-chain contracts for RISC Zero zkVM kernel execution.

| Contract | Description |
|----------|-------------|
| `AgentRegistry` | Permissionless agent registration with deterministic IDs |
| `VaultFactory` | CREATE2 vault deployment with imageId pinning |
| `KernelExecutionVerifier` | Verifies zkVM proofs and parses `KernelJournalV1` |
| `KernelOutputParser` | Library for parsing `AgentOutput` into executable actions |
| `KernelVault` | Vault that executes verified agent actions with pinned imageId |

## Deployed Contracts (Sepolia)

| Contract | Address |
|----------|---------|
| AgentRegistry | `0xBa1DA5f7e12F2c8614696D019A2eb48918E1f2AA` |
| VaultFactory | `0x3bB48a146bBC50F8990c86787a41185A6fC474d2` |
| KernelExecutionVerifier | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |
| RISC Zero Verifier Router | `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` |

## Installation

```bash
cd contracts
forge install
forge build
```

## Testing

```bash
forge test
forge test -vvv          # verbose
forge coverage           # coverage report
```

## Documentation

- [Binary Format Specification](./docs/binary-format.md) - Wire formats for journal and actions

## Dependencies

- [risc0-ethereum](https://github.com/risc0/risc0-ethereum) - RISC Zero verifier contracts
- [forge-std](https://github.com/foundry-rs/forge-std) - Foundry testing library
