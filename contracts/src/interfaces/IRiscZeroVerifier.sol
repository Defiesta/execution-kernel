// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IRiscZeroVerifier
/// @notice Minimal interface for RISC Zero proof verification
/// @dev This interface defines the verify function used by KernelExecutionVerifier.
///      For full functionality, see risc0-ethereum/IRiscZeroVerifier.sol
interface IRiscZeroVerifier {
    /// @notice Verify that the given seal is a valid RISC Zero proof of execution with the
    ///         given image ID and journal digest. Reverts on failure.
    /// @dev This method ensures that the input hash is all-zeros (no committed input),
    ///      the exit code is (Halted, 0), and there are no assumptions (unconditional receipt).
    /// @param seal The encoded cryptographic proof (i.e. SNARK).
    /// @param imageId The identifier for the guest program.
    /// @param journalDigest The SHA-256 digest of the journal bytes.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}
