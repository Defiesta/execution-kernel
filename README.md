# Execution Kernel

Verifiable agent execution using RISC Zero zkVM.

## Quick Start

```bash
# Build
cargo build --release

# Test
cargo test

# Build with zkVM
cargo build --release --features risc0
```

## Project Structure

```
crates/
├── protocol/kernel-core/     # Core types and codec
├── sdk/kernel-sdk/           # Agent development SDK
├── runtime/kernel-guest/     # Kernel execution logic
├── reference-integrator/     # Integration reference implementation
└── testing/                  # Test suites
```

## Reference Integrator

The `reference-integrator` crate provides a complete example of how to integrate with the Execution Kernel, including input construction, proof generation, and on-chain verification.

```bash
cargo run -p reference-integrator -- --help
```

## Deployed Contracts (Sepolia)

| Contract | Address |
|----------|---------|
| KernelExecutionVerifier | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |

## Documentation

https://docs.defiesta.xyz

## License

Apache-2.0
