// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IRiscZeroVerifier } from "../../src/interfaces/IRiscZeroVerifier.sol";

/// @title MockVerifier
/// @notice Mock RISC Zero verifier for testing purposes
/// @dev Always passes verification - DO NOT USE IN PRODUCTION
contract MockVerifier is IRiscZeroVerifier {
    /// @notice Whether to fail verification (for testing failure paths)
    bool public shouldFail;

    /// @notice Last verified parameters (for test assertions)
    bytes public lastSeal;
    bytes32 public lastImageId;
    bytes32 public lastJournalDigest;

    /// @notice Error raised when mock is configured to fail
    error MockVerificationFailed();

    /// @notice Set whether verification should fail
    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata, bytes32, bytes32) external view override {
        if (shouldFail) {
            revert MockVerificationFailed();
        }
        // Mock verification always passes (unless configured to fail)
    }

    /// @notice Record the last verification call (for use in tests)
    /// @dev This is a non-view version for tests that need to track calls
    function verifyAndRecord(bytes calldata seal, bytes32 imageId, bytes32 journalDigest)
        external
    {
        lastSeal = seal;
        lastImageId = imageId;
        lastJournalDigest = journalDigest;

        if (shouldFail) {
            revert MockVerificationFailed();
        }
    }
}

/// @title RevertingVerifier
/// @notice A verifier that always reverts (for testing failure scenarios)
contract RevertingVerifier is IRiscZeroVerifier {
    error AlwaysReverts();

    function verify(bytes calldata, bytes32, bytes32) external pure override {
        revert AlwaysReverts();
    }
}
