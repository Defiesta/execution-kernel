// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { VaultFactory } from "../src/VaultFactory.sol";
import { AgentRegistry } from "../src/AgentRegistry.sol";
import { KernelVault } from "../src/KernelVault.sol";
import { KernelOutputParser } from "../src/KernelOutputParser.sol";
import { MockKernelExecutionVerifier } from "./mocks/MockKernelExecutionVerifier.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";
import { IAgentRegistry } from "../src/interfaces/IAgentRegistry.sol";
import { IVaultFactory } from "../src/interfaces/IVaultFactory.sol";

/// @title Permissionless Integration Tests
/// @notice Full flow tests for the permissionless agent registry and vault factory
contract PermissionlessIntegrationTest is Test {
    VaultFactory public factory;
    AgentRegistry public registry;
    MockKernelExecutionVerifier public mockVerifier;
    MockERC20 public token;

    address public author = address(0x1111111111111111111111111111111111111111);
    address public user = address(0x2222222222222222222222222222222222222222);
    address public recipient = address(0x3333333333333333333333333333333333333333);

    bytes32 public constant SALT = bytes32(uint256(0x1));
    bytes32 public constant IMAGE_ID = bytes32(uint256(0x1234));
    bytes32 public constant CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 public constant USER_SALT = bytes32(uint256(0xABCD));
    string public constant METADATA_URI = "ipfs://QmTest";

    bytes32 public agentId;
    address public vaultAddr;

    // Dummy journal/seal - mock verifier ignores these
    bytes public constant DUMMY_JOURNAL = hex"00";
    bytes public constant DUMMY_SEAL = hex"00";

    function setUp() public {
        // Deploy mock verifier
        mockVerifier = new MockKernelExecutionVerifier();

        // Deploy contracts
        registry = new AgentRegistry();
        factory = new VaultFactory(address(registry), address(mockVerifier));

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST", 18);

        // Step 1: Register agent in AgentRegistry (permissionless)
        vm.prank(author);
        agentId = registry.register(SALT, IMAGE_ID, CODE_HASH, METADATA_URI);

        // Step 2: Deploy vault via VaultFactory (only author can deploy)
        vm.prank(author);
        vaultAddr = factory.deployVault(agentId, address(token), USER_SALT);

        // Configure mock verifier with agent info
        mockVerifier.setEssentials(agentId, 1, bytes32(0)); // commitment set per test
        mockVerifier.setExpectedImageId(IMAGE_ID, true); // Enable imageId validation

        // Fund vault and user
        token.mint(address(vaultAddr), 1000 ether);
        token.mint(user, 1000 ether);

        // Approve vault for user deposits
        vm.prank(user);
        token.approve(vaultAddr, type(uint256).max);
    }

    // ============ Helper Functions ============

    /// @notice Build AgentOutput with a single TRANSFER_ERC20 action
    function _buildTransferAction(address tokenAddr, address to, uint256 amount)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload = abi.encode(tokenAddr, to, amount);

        KernelOutputParser.Action[] memory actions = new KernelOutputParser.Action[](1);
        actions[0] = KernelOutputParser.Action({
            actionType: KernelOutputParser.ACTION_TYPE_TRANSFER_ERC20,
            target: bytes32(0),
            payload: payload
        });

        return KernelOutputParser.encodeAgentOutput(actions);
    }

    // ============ Full Flow Tests ============

    /// @notice Test complete flow: register agent → deploy vault → deposit → execute
    function test_fullFlow_registerDeployDepositExecute() public {
        KernelVault vault = KernelVault(payable(vaultAddr));

        // Verify vault configuration
        assertEq(vault.agentId(), agentId, "Agent ID should match");
        assertEq(vault.trustedImageId(), IMAGE_ID, "Trusted imageId should match");

        // Step 3: Deposit funds (any user can deposit)
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        assertEq(vault.shares(user), 100 ether, "User should have shares");
        assertEq(vault.totalShares(), 100 ether, "Total shares should be updated");

        // Step 4: Execute with valid proof
        uint256 transferAmount = 50 ether;
        bytes memory agentOutput = _buildTransferAction(address(token), recipient, transferAmount);
        bytes32 actionCommitment = sha256(agentOutput);

        mockVerifier.setActionCommitment(actionCommitment);
        mockVerifier.setExecutionNonce(1);

        uint256 recipientBefore = token.balanceOf(recipient);
        uint256 vaultBefore = token.balanceOf(address(vault));

        vault.execute(DUMMY_JOURNAL, DUMMY_SEAL, agentOutput);

        // Verify transfer occurred
        assertEq(
            token.balanceOf(recipient), recipientBefore + transferAmount, "Recipient should receive"
        );
        assertEq(
            token.balanceOf(address(vault)),
            vaultBefore - transferAmount,
            "Vault should decrease"
        );
        assertEq(vault.lastExecutionNonce(), 1, "Nonce should be updated");
    }

    /// @notice Test that registry updates don't affect existing vaults
    function test_registryUpdate_doesNotAffectExistingVault() public {
        KernelVault vault = KernelVault(payable(vaultAddr));

        // Verify initial imageId
        assertEq(vault.trustedImageId(), IMAGE_ID, "Initial imageId should match");

        // Author updates the agent in registry
        bytes32 newImageId = bytes32(uint256(0x5678));
        vm.prank(author);
        registry.update(agentId, newImageId, CODE_HASH, METADATA_URI);

        // Verify registry is updated
        IAgentRegistry.AgentInfo memory info = registry.get(agentId);
        assertEq(info.imageId, newImageId, "Registry should have new imageId");

        // Verify vault's imageId is NOT affected
        assertEq(
            vault.trustedImageId(), IMAGE_ID, "Vault imageId should NOT change after registry update"
        );

        // Vault can still execute with the ORIGINAL imageId
        bytes memory agentOutput = _buildTransferAction(address(token), recipient, 10 ether);
        bytes32 actionCommitment = sha256(agentOutput);

        // Configure mock to expect the original imageId (not the new one)
        mockVerifier.setExpectedImageId(IMAGE_ID, true);
        mockVerifier.setActionCommitment(actionCommitment);
        mockVerifier.setExecutionNonce(1);

        // Execute should succeed with original imageId
        vault.execute(DUMMY_JOURNAL, DUMMY_SEAL, agentOutput);
        assertEq(vault.lastExecutionNonce(), 1);
    }

    /// @notice Test that execution fails when imageId doesn't match
    function test_execute_wrongImageId_reverts() public {
        KernelVault vault = KernelVault(payable(vaultAddr));

        bytes memory agentOutput = _buildTransferAction(address(token), recipient, 10 ether);
        bytes32 actionCommitment = sha256(agentOutput);

        // Configure mock to expect a DIFFERENT imageId
        bytes32 wrongImageId = bytes32(uint256(0x9999));
        mockVerifier.setExpectedImageId(wrongImageId, true); // Will fail on mismatch
        mockVerifier.setActionCommitment(actionCommitment);
        mockVerifier.setExecutionNonce(1);

        // Execute should revert because vault's trustedImageId (IMAGE_ID)
        // doesn't match the mock's expected imageId (wrongImageId)
        vm.expectRevert(
            abi.encodeWithSelector(
                MockKernelExecutionVerifier.ImageIdMismatch.selector, wrongImageId, IMAGE_ID
            )
        );
        vault.execute(DUMMY_JOURNAL, DUMMY_SEAL, agentOutput);
    }

    /// @notice Test new vault after registry update gets new imageId
    function test_newVaultAfterUpdate_getsNewImageId() public {
        // Author updates the agent in registry
        bytes32 newImageId = bytes32(uint256(0x5678));
        vm.prank(author);
        registry.update(agentId, newImageId, CODE_HASH, METADATA_URI);

        // Author deploys a NEW vault (different salt)
        bytes32 newUserSalt = bytes32(uint256(0xBEEF));
        vm.prank(author);
        address newVaultAddr = factory.deployVault(agentId, address(token), newUserSalt);

        KernelVault newVault = KernelVault(payable(newVaultAddr));

        // New vault should have the UPDATED imageId
        assertEq(
            newVault.trustedImageId(),
            newImageId,
            "New vault should have updated imageId"
        );

        // Old vault should still have the original imageId
        KernelVault oldVault = KernelVault(payable(vaultAddr));
        assertEq(
            oldVault.trustedImageId(),
            IMAGE_ID,
            "Old vault should still have original imageId"
        );
    }

    /// @notice Test multiple agents can be registered and used independently
    function test_multipleAgents_independent() public {
        // Register a second agent (by the same author)
        bytes32 agent2ImageId = bytes32(uint256(0x9999));
        bytes32 agent2CodeHash = bytes32(uint256(0xDEAD));
        vm.prank(author);
        bytes32 agent2Id = registry.register(
            bytes32(uint256(0x2)),
            agent2ImageId,
            agent2CodeHash,
            "ipfs://QmTest2"
        );

        // Author deploys vault for second agent
        vm.prank(author);
        address vault2Addr = factory.deployVault(agent2Id, address(token), USER_SALT);

        KernelVault vault1 = KernelVault(payable(vaultAddr));
        KernelVault vault2 = KernelVault(payable(vault2Addr));

        // Verify different imageIds
        assertEq(vault1.trustedImageId(), IMAGE_ID);
        assertEq(vault2.trustedImageId(), agent2ImageId);
        assertTrue(vault1.trustedImageId() != vault2.trustedImageId());

        // Verify different agentIds
        assertEq(vault1.agentId(), agentId);
        assertEq(vault2.agentId(), agent2Id);
        assertTrue(vault1.agentId() != vault2.agentId());
    }

    /// @notice Test permissionless registration - anyone can register
    function test_permissionless_anyoneCanRegister() public {
        address randomUser = address(0x4444444444444444444444444444444444444444);

        vm.prank(randomUser);
        bytes32 newAgentId = registry.register(
            bytes32(uint256(0x123)),
            bytes32(uint256(0xABCD)),
            bytes32(uint256(0xEF01)),
            "ipfs://QmRandom"
        );

        assertTrue(registry.agentExists(newAgentId), "Agent should be registered");

        IAgentRegistry.AgentInfo memory info = registry.get(newAgentId);
        assertEq(info.author, randomUser, "Author should be the registrant");
    }

    /// @notice Test only agent author can deploy vaults for their agent
    function test_onlyAuthorCanDeployVault() public {
        address randomUser = address(0x5555555555555555555555555555555555555555);

        // Non-author should not be able to deploy vault for author's agent
        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IVaultFactory.NotAgentAuthor.selector, agentId, randomUser, author
            )
        );
        factory.deployVault(agentId, address(token), bytes32(uint256(0x999)));
    }

    /// @notice Test author can deploy their own vault after registering
    function test_authorCanDeployAfterRegistering() public {
        address newAuthor = address(0x6666666666666666666666666666666666666666);

        // New author registers their agent
        vm.prank(newAuthor);
        bytes32 newAgentId = registry.register(
            bytes32(uint256(0x456)),
            bytes32(uint256(0x7890)),
            bytes32(uint256(0xABCD)),
            "ipfs://QmNewAgent"
        );

        // New author can deploy vault for their agent
        vm.prank(newAuthor);
        address newVaultAddr = factory.deployVault(newAgentId, address(token), bytes32(uint256(0x999)));

        assertTrue(factory.isDeployedVault(newVaultAddr), "Vault should be deployed");

        KernelVault newVault = KernelVault(payable(newVaultAddr));
        assertEq(newVault.agentId(), newAgentId, "Agent ID should match");
    }
}
