# Execution Kernel Contracts

On-chain contracts for RISC Zero zkVM kernel execution.

| Contract | Description |
|----------|-------------|
| `KernelExecutionVerifier` | Verifies zkVM proofs and parses `KernelJournalV1` |
| `KernelOutputParser` | Library for parsing `AgentOutput` into executable actions |
| `KernelVault` | MVP vault that executes verified agent actions |

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
