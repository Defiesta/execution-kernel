// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { VaultFactory } from "../src/VaultFactory.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { KernelVault } from "../src/KernelVault.sol";
import { KernelExecutionVerifier } from "../src/KernelExecutionVerifier.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";
import { IVaultFactory } from "../src/interfaces/IVaultFactory.sol";
import { IAgentRegistry } from "../src/interfaces/IAgentRegistry.sol";

/// @title VaultFactory Tests
/// @notice Comprehensive test suite for VaultFactory
contract VaultFactoryTest is Test {
    VaultFactory public factory;
    AgentRegistry public registry;
    KernelExecutionVerifier public verifier;
    MockVerifier public mockRiscZeroVerifier;
    MockERC20 public token;

    address public author = address(0x1111111111111111111111111111111111111111);
    address public nonAuthor = address(0x2222222222222222222222222222222222222222);

    bytes32 public constant SALT = bytes32(uint256(0x1));
    bytes32 public constant IMAGE_ID = bytes32(uint256(0x1234));
    bytes32 public constant CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 public constant USER_SALT = bytes32(uint256(0xABCD));
    string public constant METADATA_URI = "ipfs://QmTest";

    bytes32 public agentId;

    function setUp() public {
        // Deploy mock RISC Zero verifier
        mockRiscZeroVerifier = new MockVerifier();

        // Deploy contracts
        registry = new AgentRegistry();
        verifier = new KernelExecutionVerifier(address(mockRiscZeroVerifier));
        factory = new VaultFactory(address(registry), address(verifier));

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST", 18);

        // Register an agent
        vm.prank(author);
        agentId = registry.register(SALT, IMAGE_ID, CODE_HASH, METADATA_URI);
    }

    // ============ Constructor Tests ============

    function test_constructor_setsRegistryAndVerifier() public view {
        assertEq(factory.registry(), address(registry));
        assertEq(factory.verifier(), address(verifier));
    }

    // ============ computeVaultAddress Tests ============

    function test_computeVaultAddress_deterministic() public view {
        (address vault1, bytes32 salt1) =
            factory.computeVaultAddress(author, agentId, address(token), USER_SALT);
        (address vault2, bytes32 salt2) =
            factory.computeVaultAddress(author, agentId, address(token), USER_SALT);

        assertEq(vault1, vault2, "Same inputs should produce same vault address");
        assertEq(salt1, salt2, "Same inputs should produce same salt");
    }

    function test_computeVaultAddress_differentOwners() public view {
        (address vault1,) = factory.computeVaultAddress(author, agentId, address(token), USER_SALT);
        (address vault2,) = factory.computeVaultAddress(nonAuthor, agentId, address(token), USER_SALT);

        assertTrue(vault1 != vault2, "Different owners should produce different addresses");
    }

    function test_computeVaultAddress_differentAgents() public {
        // Register another agent
        vm.prank(author);
        bytes32 agentId2 = registry.register(bytes32(uint256(0x2)), IMAGE_ID, CODE_HASH, METADATA_URI);

        (address vault1,) = factory.computeVaultAddress(author, agentId, address(token), USER_SALT);
        (address vault2,) = factory.computeVaultAddress(author, agentId2, address(token), USER_SALT);

        assertTrue(vault1 != vault2, "Different agents should produce different addresses");
    }

    function test_computeVaultAddress_differentAssets() public view {
        (address vault1,) = factory.computeVaultAddress(author, agentId, address(token), USER_SALT);
        (address vault2,) = factory.computeVaultAddress(author, agentId, address(0), USER_SALT);

        assertTrue(vault1 != vault2, "Different assets should produce different addresses");
    }

    function test_computeVaultAddress_differentUserSalts() public view {
        (address vault1,) = factory.computeVaultAddress(author, agentId, address(token), USER_SALT);
        (address vault2,) =
            factory.computeVaultAddress(author, agentId, address(token), bytes32(uint256(0x9999)));

        assertTrue(vault1 != vault2, "Different user salts should produce different addresses");
    }

    function test_computeVaultAddress_agentNotRegistered_reverts() public {
        bytes32 fakeAgentId = bytes32(uint256(0xDEAD));

        vm.expectRevert(
            abi.encodeWithSelector(IVaultFactory.AgentNotRegistered.selector, fakeAgentId)
        );
        factory.computeVaultAddress(author, fakeAgentId, address(token), USER_SALT);
    }

    // ============ deployVault Tests ============

    function test_deployVault_success() public {
        vm.prank(author);
        address vault = factory.deployVault(agentId, address(token), USER_SALT);

        assertTrue(vault != address(0), "Vault should be deployed");
        assertTrue(factory.isDeployedVault(vault), "Vault should be tracked");

        // Verify vault configuration
        KernelVault deployedVault = KernelVault(payable(vault));
        assertEq(deployedVault.agentId(), agentId, "AgentId should match");
        assertEq(deployedVault.trustedImageId(), IMAGE_ID, "TrustedImageId should match");
        assertEq(address(deployedVault.asset()), address(token), "Asset should match");
        assertEq(address(deployedVault.verifier()), address(verifier), "Verifier should match");
    }

    function test_deployVault_emitsEvent() public {
        (address expectedVault, bytes32 expectedSalt) =
            factory.computeVaultAddress(author, agentId, address(token), USER_SALT);

        vm.expectEmit(true, true, true, true);
        emit IVaultFactory.VaultDeployed(
            expectedVault, author, agentId, address(token), IMAGE_ID, expectedSalt
        );

        vm.prank(author);
        factory.deployVault(agentId, address(token), USER_SALT);
    }

    function test_deployVault_agentNotRegistered_reverts() public {
        bytes32 fakeAgentId = bytes32(uint256(0xDEAD));

        vm.prank(author);
        vm.expectRevert(
            abi.encodeWithSelector(IVaultFactory.AgentNotRegistered.selector, fakeAgentId)
        );
        factory.deployVault(fakeAgentId, address(token), USER_SALT);
    }

    function test_deployVault_notAgentAuthor_reverts() public {
        vm.prank(nonAuthor);
        vm.expectRevert(
            abi.encodeWithSelector(
                IVaultFactory.NotAgentAuthor.selector, agentId, nonAuthor, author
            )
        );
        factory.deployVault(agentId, address(token), USER_SALT);
    }

    function test_deployVault_CREATE2_addressMatches() public {
        (address expectedVault,) =
            factory.computeVaultAddress(author, agentId, address(token), USER_SALT);

        vm.prank(author);
        address actualVault = factory.deployVault(agentId, address(token), USER_SALT);

        assertEq(actualVault, expectedVault, "Deployed address should match computed address");
    }

    function test_deployVault_sameParamsTwice_reverts() public {
        vm.prank(author);
        factory.deployVault(agentId, address(token), USER_SALT);

        // Second deployment with same params should fail (CREATE2 collision)
        vm.prank(author);
        vm.expectRevert(); // CREATE2 will fail with zero address
        factory.deployVault(agentId, address(token), USER_SALT);
    }

    function test_deployVault_differentUserSalt_succeeds() public {
        vm.prank(author);
        address vault1 = factory.deployVault(agentId, address(token), USER_SALT);

        vm.prank(author);
        address vault2 =
            factory.deployVault(agentId, address(token), bytes32(uint256(0x9999)));

        assertTrue(vault1 != vault2, "Different user salts should produce different vaults");
        assertTrue(factory.isDeployedVault(vault1), "First vault should be tracked");
        assertTrue(factory.isDeployedVault(vault2), "Second vault should be tracked");
    }

    function test_deployVault_ETHVault() public {
        vm.prank(author);
        address vault = factory.deployVault(agentId, address(0), USER_SALT);

        KernelVault deployedVault = KernelVault(payable(vault));
        assertEq(address(deployedVault.asset()), address(0), "Asset should be address(0) for ETH");
    }

    // ============ isDeployedVault Tests ============

    function test_isDeployedVault_returnsFalseForUndeployed() public view {
        assertFalse(factory.isDeployedVault(address(0x1234)));
    }

    function test_isDeployedVault_returnsTrueForDeployed() public {
        vm.prank(author);
        address vault = factory.deployVault(agentId, address(token), USER_SALT);

        assertTrue(factory.isDeployedVault(vault));
    }

    // ============ Integration Tests ============

    function test_deployedVault_usesCorrectImageId() public {
        // Deploy vault
        vm.prank(author);
        address vault = factory.deployVault(agentId, address(token), USER_SALT);

        // Verify the vault has the correct imageId pinned
        KernelVault deployedVault = KernelVault(payable(vault));
        assertEq(
            deployedVault.trustedImageId(),
            IMAGE_ID,
            "Deployed vault should have correct imageId"
        );

        // Update the registry (simulate author updating agent)
        bytes32 newImageId = bytes32(uint256(0x5678));
        vm.prank(author);
        registry.update(agentId, newImageId, CODE_HASH, METADATA_URI);

        // Verify the vault's imageId is NOT affected by registry update
        assertEq(
            deployedVault.trustedImageId(),
            IMAGE_ID,
            "Vault imageId should NOT change after registry update"
        );
    }

    function test_multipleVaultsFromSameAuthor() public {
        // Author deploys multiple vaults with different salts
        vm.startPrank(author);
        address vault1 = factory.deployVault(agentId, address(token), USER_SALT);
        address vault2 = factory.deployVault(agentId, address(token), bytes32(uint256(0x9999)));
        vm.stopPrank();

        assertTrue(vault1 != vault2, "Different salts should produce different vaults");

        // Both vaults should have the same imageId
        KernelVault v1 = KernelVault(payable(vault1));
        KernelVault v2 = KernelVault(payable(vault2));
        assertEq(v1.trustedImageId(), v2.trustedImageId(), "Both vaults should have same imageId");
        assertEq(v1.agentId(), v2.agentId(), "Both vaults should have same agentId");
    }

    function test_differentAuthors_canDeployForTheirOwnAgents() public {
        // Second author registers their own agent
        address author2 = address(0x3333333333333333333333333333333333333333);
        vm.prank(author2);
        bytes32 agentId2 = registry.register(bytes32(uint256(0x999)), IMAGE_ID, CODE_HASH, "ipfs://QmOther");

        // Each author deploys vault for their own agent
        vm.prank(author);
        address vault1 = factory.deployVault(agentId, address(token), USER_SALT);

        vm.prank(author2);
        address vault2 = factory.deployVault(agentId2, address(token), USER_SALT);

        assertTrue(vault1 != vault2, "Different agents should produce different vaults");
        assertTrue(factory.isDeployedVault(vault1), "First vault should be tracked");
        assertTrue(factory.isDeployedVault(vault2), "Second vault should be tracked");
    }
}
