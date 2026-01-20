# SPECIFICATION.md  
## P0.1 — Canonical zkVM Guest Program (Execution Kernel)

**Project:** Verifiable Agent Execution Kernel  
**Milestone:** Q1 2026 — Priority 0 (Blocking)  
**Task:** P0.1 Canonical zkVM Guest Program  
**Status:** Specification v1.0 (Implementation-Ready)  
**Target VM:** RISC Zero zkVM  
**Last Updated:** 2026-01-20  

---

## 1. Purpose

This document specifies the **canonical zkVM guest program** (“Execution Kernel”) that defines what it means for an agent execution to be **valid**.

The kernel is responsible for:

1. Deterministically executing agent logic  
2. Enforcing non-bypassable constraints  
3. Producing a canonical journal committed to a zk receipt  

**Protocol invariant:**  
> Any receipt accepted on-chain MUST correspond to an execution of this kernel with identical semantics.

The kernel is consensus-critical. Any ambiguity breaks the protocol.

---

## 2. Non-Goals

The kernel explicitly does NOT:

- Fetch or validate external data  
- Interpret market semantics  
- Perform settlement or state transitions  
- Manage vault balances or capital  
- Enforce economic policy beyond calling the constraint engine  

The kernel proves **correct execution given committed inputs**, nothing more.

---

## 3. Threat Model

Assume a malicious operator who:

- Controls the host environment  
- Attempts to forge agent outputs  
- Attempts to bypass constraints  
- Attempts to exploit non-determinism  

The kernel MUST ensure such attempts fail cryptographically.

---

## 4. Determinism Requirements (Hard MUSTs)

The kernel MUST be fully deterministic across:

- Machines  
- Provers  
- Rebuilds (with pinned toolchain)  

### 4.1 Forbidden Sources of Non-Determinism

The guest MUST NOT depend on:

- System time  
- Randomness  
- Floating point operations  
- Host environment variables  
- Filesystem or network access  
- Unordered iteration without canonical sorting  

All loops MUST be bounded.  
All memory usage MUST be bounded.

---

## 5. Versioning and Constants (v1)

```text
PROTOCOL_VERSION = 1
KERNEL_VERSION   = 1
MAX_AGENT_INPUT_BYTES = 64_000
HASH_FUNCTION = SHA-256