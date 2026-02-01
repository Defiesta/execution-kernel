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
| AgentRegistry | `0xBa1DA5f7e12F2c8614696D019A2eb48918E1f2AA` |
| VaultFactory | `0x3bB48a146bBC50F8990c86787a41185A6fC474d2` |
| KernelExecutionVerifier | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |
| RISC Zero Verifier Router | `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` |

## Documentation

https://docs.defiesta.xyz

## License

Apache-2.0
