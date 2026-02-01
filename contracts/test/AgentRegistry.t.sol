// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { IAgentRegistry } from "../src/interfaces/IAgentRegistry.sol";

/// @title AgentRegistry Tests
/// @notice Comprehensive test suite for AgentRegistry
contract AgentRegistryTest is Test {
    AgentRegistry public registry;

    address public author1 = address(0x1111111111111111111111111111111111111111);
    address public author2 = address(0x2222222222222222222222222222222222222222);

    bytes32 public constant SALT_1 = bytes32(uint256(0x1));
    bytes32 public constant SALT_2 = bytes32(uint256(0x2));
    bytes32 public constant IMAGE_ID_1 = bytes32(uint256(0x1234));
    bytes32 public constant IMAGE_ID_2 = bytes32(uint256(0x5678));
    bytes32 public constant CODE_HASH_1 = bytes32(uint256(0xC0DE1));
    bytes32 public constant CODE_HASH_2 = bytes32(uint256(0xC0DE2));
    string public constant METADATA_URI_1 = "ipfs://QmTest1";
    string public constant METADATA_URI_2 = "ipfs://QmTest2";

    function setUp() public {
        registry = new AgentRegistry();
    }

    // ============ computeAgentId Tests ============

    function test_computeAgentId_deterministic() public view {
        bytes32 id1 = registry.computeAgentId(author1, SALT_1);
        bytes32 id2 = registry.computeAgentId(author1, SALT_1);

        assertEq(id1, id2, "Same inputs should produce same agentId");
    }

    function test_computeAgentId_differentAuthors() public view {
        bytes32 id1 = registry.computeAgentId(author1, SALT_1);
        bytes32 id2 = registry.computeAgentId(author2, SALT_1);

        assertTrue(id1 != id2, "Different authors should produce different agentIds");
    }

    function test_computeAgentId_differentSalts() public view {
        bytes32 id1 = registry.computeAgentId(author1, SALT_1);
        bytes32 id2 = registry.computeAgentId(author1, SALT_2);

        assertTrue(id1 != id2, "Different salts should produce different agentIds");
    }

    function test_computeAgentId_matchesKeccak256() public view {
        bytes32 id = registry.computeAgentId(author1, SALT_1);
        bytes32 expected = keccak256(abi.encodePacked(author1, SALT_1));

        assertEq(id, expected, "Should match keccak256(author, salt)");
    }

    // ============ register Tests ============

    function test_register_success() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        // Verify agentId matches expected
        bytes32 expectedId = registry.computeAgentId(author1, SALT_1);
        assertEq(agentId, expectedId, "AgentId should match computed value");

        // Verify stored data
        IAgentRegistry.AgentInfo memory info = registry.get(agentId);
        assertEq(info.author, author1, "Author should match");
        assertEq(info.imageId, IMAGE_ID_1, "ImageId should match");
        assertEq(info.agentCodeHash, CODE_HASH_1, "CodeHash should match");
        assertEq(info.metadataURI, METADATA_URI_1, "MetadataURI should match");
        assertTrue(info.exists, "Agent should exist");
    }

    function test_register_emitsEvent() public {
        bytes32 expectedAgentId = registry.computeAgentId(author1, SALT_1);

        vm.expectEmit(true, true, true, true);
        emit IAgentRegistry.AgentRegistered(
            expectedAgentId, author1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1
        );

        vm.prank(author1);
        registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);
    }

    function test_register_zeroImageId_reverts() public {
        vm.prank(author1);
        vm.expectRevert(IAgentRegistry.InvalidImageId.selector);
        registry.register(SALT_1, bytes32(0), CODE_HASH_1, METADATA_URI_1);
    }

    function test_register_zeroCodeHash_reverts() public {
        vm.prank(author1);
        vm.expectRevert(IAgentRegistry.InvalidAgentCodeHash.selector);
        registry.register(SALT_1, IMAGE_ID_1, bytes32(0), METADATA_URI_1);
    }

    function test_register_alreadyExists_reverts() public {
        vm.prank(author1);
        registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        bytes32 agentId = registry.computeAgentId(author1, SALT_1);

        vm.prank(author1);
        vm.expectRevert(abi.encodeWithSelector(IAgentRegistry.AgentAlreadyExists.selector, agentId));
        registry.register(SALT_1, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);
    }

    function test_register_sameAuthorDifferentSalt_succeeds() public {
        vm.startPrank(author1);
        bytes32 id1 = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);
        bytes32 id2 = registry.register(SALT_2, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);
        vm.stopPrank();

        assertTrue(id1 != id2, "Different salts should produce different agentIds");
        assertTrue(registry.agentExists(id1), "First agent should exist");
        assertTrue(registry.agentExists(id2), "Second agent should exist");
    }

    function test_register_differentAuthorsSameSalt_succeeds() public {
        vm.prank(author1);
        bytes32 id1 = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.prank(author2);
        bytes32 id2 = registry.register(SALT_1, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);

        assertTrue(id1 != id2, "Different authors should produce different agentIds");
        assertTrue(registry.agentExists(id1), "First agent should exist");
        assertTrue(registry.agentExists(id2), "Second agent should exist");
    }

    // ============ update Tests ============

    function test_update_success() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.prank(author1);
        registry.update(agentId, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);

        IAgentRegistry.AgentInfo memory info = registry.get(agentId);
        assertEq(info.imageId, IMAGE_ID_2, "ImageId should be updated");
        assertEq(info.agentCodeHash, CODE_HASH_2, "CodeHash should be updated");
        assertEq(info.metadataURI, METADATA_URI_2, "MetadataURI should be updated");
        assertEq(info.author, author1, "Author should remain unchanged");
    }

    function test_update_emitsEvent() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.expectEmit(true, true, false, true);
        emit IAgentRegistry.AgentUpdated(agentId, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);

        vm.prank(author1);
        registry.update(agentId, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);
    }

    function test_update_notAuthor_reverts() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.prank(author2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAgentRegistry.NotAgentAuthor.selector, agentId, author2, author1
            )
        );
        registry.update(agentId, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);
    }

    function test_update_nonExistentAgent_reverts() public {
        bytes32 fakeAgentId = bytes32(uint256(0xDEAD));

        vm.prank(author1);
        vm.expectRevert(abi.encodeWithSelector(IAgentRegistry.AgentNotFound.selector, fakeAgentId));
        registry.update(fakeAgentId, IMAGE_ID_2, CODE_HASH_2, METADATA_URI_2);
    }

    function test_update_zeroImageId_reverts() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.prank(author1);
        vm.expectRevert(IAgentRegistry.InvalidImageId.selector);
        registry.update(agentId, bytes32(0), CODE_HASH_2, METADATA_URI_2);
    }

    function test_update_zeroCodeHash_reverts() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        vm.prank(author1);
        vm.expectRevert(IAgentRegistry.InvalidAgentCodeHash.selector);
        registry.update(agentId, IMAGE_ID_2, bytes32(0), METADATA_URI_2);
    }

    // ============ get Tests ============

    function test_get_returnsCorrectInfo() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        IAgentRegistry.AgentInfo memory info = registry.get(agentId);

        assertEq(info.author, author1);
        assertEq(info.imageId, IMAGE_ID_1);
        assertEq(info.agentCodeHash, CODE_HASH_1);
        assertEq(info.metadataURI, METADATA_URI_1);
        assertTrue(info.exists);
    }

    function test_get_nonExistent_returnsDefaultInfo() public view {
        bytes32 fakeAgentId = bytes32(uint256(0xDEAD));

        IAgentRegistry.AgentInfo memory info = registry.get(fakeAgentId);

        assertEq(info.author, address(0));
        assertEq(info.imageId, bytes32(0));
        assertEq(info.agentCodeHash, bytes32(0));
        assertEq(info.metadataURI, "");
        assertFalse(info.exists);
    }

    // ============ agentExists Tests ============

    function test_agentExists_returnsTrueForExisting() public {
        vm.prank(author1);
        bytes32 agentId = registry.register(SALT_1, IMAGE_ID_1, CODE_HASH_1, METADATA_URI_1);

        assertTrue(registry.agentExists(agentId));
    }

    function test_agentExists_returnsFalseForNonExisting() public view {
        bytes32 fakeAgentId = bytes32(uint256(0xDEAD));

        assertFalse(registry.agentExists(fakeAgentId));
    }
}
