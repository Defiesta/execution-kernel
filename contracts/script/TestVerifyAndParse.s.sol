// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Script, console } from "forge-std/Script.sol";
import { KernelExecutionVerifier } from "../src/KernelExecutionVerifier.sol";

/// @title TestVerifyAndParseWithImageId
/// @notice Test script for verifying proofs using verifyAndParseWithImageId
/// @dev Uses the permissionless verification flow where caller provides imageId
contract TestVerifyAndParseWithImageId is Script {
    // Deployed contract address on Sepolia
    address constant VERIFIER_ADDRESS = 0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA;

    // Test data from e2e-tests output
    bytes32 constant IMAGE_ID = 0xb326f06dbfc60f5e72d2d7cddf94f7991cff99dfd67f69357713bb9f49c3d195;
    bytes32 constant AGENT_ID = 0x4242424242424242424242424242424242424242424242424242424242424242;

    function run() external view {
        KernelExecutionVerifier verifier = KernelExecutionVerifier(VERIFIER_ADDRESS);

        // Seal from zkVM proof (with selector prefix 0x73c457ba)
        bytes memory seal =
            hex"73c457ba14a54a4b4694dafbf4de2a28afb50e08ad058997b71fbc5f0ceee539dd63f503016e967d32903d32812f4e950fb1035750b6c448ce3ba603e6a4162c1ac78f320a6e9cbd7ff7a966d430d4b541c5621fb5075f57d73af0737770361f832a7b07225de9bba2c86a3a5026d62643570fb01293631ea28358353f6c768f101d52492d4cf2637053c900c6149937bd8fec2b08de9c3c0e1db72989b35f255da1a32b2f0bfe9c1f2e9e4795ea0a183b5302a53386c6f96880f014d78631818b69e92f1436b22c0e6213d192df183e6df6523f5693f01dc8db8088474b51328e4a54892df02090e8f7db0fb979b45655747a58a0598e54e2d5d33e695cf2acee0a60a9";

        // Journal from zkVM proof (209 bytes)
        bytes memory journal =
            hex"01000000010000004242424242424242424242424242424242424242424242424242424242424242943395a6221a2b9c6f62bac3a07f1fb05980f48e00f8b6bdb5eb738ac98499eebbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000000000008b9f6c2e7972d334d9347953b2ad91c5283a5dc9f68e5f1309f1e012ece73334a4b1f22de8149ff8156f11d5aa0585e03844cc76b1d52f5e11b420312d64037101";

        console.log("=== Test verifyAndParseWithImageId ===");
        console.log("Verifier address:", VERIFIER_ADDRESS);
        console.log("Image ID:");
        console.logBytes32(IMAGE_ID);
        console.log("Agent ID:");
        console.logBytes32(AGENT_ID);
        console.log("Journal length:", journal.length);
        console.log("Seal length:", seal.length);

        // Call verifyAndParseWithImageId (view function, no broadcast needed)
        // In the permissionless model, the caller provides the imageId directly
        console.log("\nCalling verifyAndParseWithImageId with caller-provided imageId...");

        try verifier.verifyAndParseWithImageId(IMAGE_ID, journal, seal) returns (
            KernelExecutionVerifier.ParsedJournal memory parsed
        ) {
            console.log("\n=== Verification SUCCESS ===");
            console.log("Agent ID:");
            console.logBytes32(parsed.agentId);
            console.log("Agent Code Hash:");
            console.logBytes32(parsed.agentCodeHash);
            console.log("Constraint Set Hash:");
            console.logBytes32(parsed.constraintSetHash);
            console.log("Input Root:");
            console.logBytes32(parsed.inputRoot);
            console.log("Execution Nonce:", parsed.executionNonce);
            console.log("Input Commitment:");
            console.logBytes32(parsed.inputCommitment);
            console.log("Action Commitment:");
            console.logBytes32(parsed.actionCommitment);
        } catch Error(string memory reason) {
            console.log("\n=== Verification FAILED ===");
            console.log("Reason:", reason);
        } catch (bytes memory lowLevelData) {
            console.log("\n=== Verification FAILED (low-level) ===");
            console.logBytes(lowLevelData);
        }
    }
}
