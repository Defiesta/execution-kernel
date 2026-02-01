// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { KernelVault } from "../src/KernelVault.sol";
import { KernelExecutionVerifier } from "../src/KernelExecutionVerifier.sol";
import { KernelOutputParser } from "../src/KernelOutputParser.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";

/// @title KernelVaultTest
/// @notice Comprehensive test suite for KernelVault
contract KernelVaultTest is Test {
    KernelVault public vault;
    KernelExecutionVerifier public executionVerifier;
    MockVerifier public mockRiscZeroVerifier;
    MockERC20 public token;

    address public owner = address(this);
    address public user = address(0x1111111111111111111111111111111111111111);
    address public recipient = address(0x2222222222222222222222222222222222222222);

    bytes32 public constant TEST_AGENT_ID = bytes32(uint256(0xA6E17));
    bytes32 public constant TEST_IMAGE_ID = bytes32(uint256(0x1234));
    bytes32 public constant TEST_CODE_HASH = bytes32(uint256(0xC0DE));
    bytes32 public constant TEST_CONSTRAINT_HASH = bytes32(uint256(0xC0175A1));
    bytes32 public constant TEST_INPUT_ROOT = bytes32(uint256(0x1200700));
    bytes32 public constant TEST_INPUT_COMMITMENT = bytes32(uint256(0x11207));

    uint256 public constant INITIAL_BALANCE = 1000 ether;
    uint256 public constant DEPOSIT_AMOUNT = 100 ether;

    function setUp() public {
        // Deploy mock RISC Zero verifier
        mockRiscZeroVerifier = new MockVerifier();

        // Deploy KernelExecutionVerifier with mock
        executionVerifier = new KernelExecutionVerifier(address(mockRiscZeroVerifier));

        // Deploy mock ERC20 token
        token = new MockERC20("Test Token", "TEST", 18);

        // Deploy KernelVault with trustedImageId
        vault = new KernelVault(address(token), address(executionVerifier), TEST_AGENT_ID, TEST_IMAGE_ID);

        // Mint tokens to user
        token.mint(user, INITIAL_BALANCE);

        // Approve vault to spend user tokens
        vm.prank(user);
        token.approve(address(vault), type(uint256).max);
    }

    // ============ Helper Functions ============

    /// @notice Build a valid 209-byte KernelJournalV1 with specified parameters
    function _buildJournal(bytes32 agentId, uint64 nonce, bytes32 actionCommitment)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory journal = new bytes(209);

        // protocol_version = 1 (u32 LE at offset 0)
        journal[0] = 0x01;
        journal[1] = 0x00;
        journal[2] = 0x00;
        journal[3] = 0x00;

        // kernel_version = 1 (u32 LE at offset 4)
        journal[4] = 0x01;
        journal[5] = 0x00;
        journal[6] = 0x00;
        journal[7] = 0x00;

        // agent_id (bytes32 at offset 8-40)
        for (uint256 i = 0; i < 32; i++) {
            journal[8 + i] = agentId[i];
        }

        // agent_code_hash (bytes32 at offset 40-72)
        bytes32 codeHash = TEST_CODE_HASH;
        for (uint256 i = 0; i < 32; i++) {
            journal[40 + i] = codeHash[i];
        }

        // constraint_set_hash (bytes32 at offset 72-104)
        bytes32 constraintHash = TEST_CONSTRAINT_HASH;
        for (uint256 i = 0; i < 32; i++) {
            journal[72 + i] = constraintHash[i];
        }

        // input_root (bytes32 at offset 104-136)
        bytes32 inputRoot = TEST_INPUT_ROOT;
        for (uint256 i = 0; i < 32; i++) {
            journal[104 + i] = inputRoot[i];
        }

        // execution_nonce (u64 LE at offset 136-144)
        journal[136] = bytes1(uint8(nonce & 0xFF));
        journal[137] = bytes1(uint8((nonce >> 8) & 0xFF));
        journal[138] = bytes1(uint8((nonce >> 16) & 0xFF));
        journal[139] = bytes1(uint8((nonce >> 24) & 0xFF));
        journal[140] = bytes1(uint8((nonce >> 32) & 0xFF));
        journal[141] = bytes1(uint8((nonce >> 40) & 0xFF));
        journal[142] = bytes1(uint8((nonce >> 48) & 0xFF));
        journal[143] = bytes1(uint8((nonce >> 56) & 0xFF));

        // input_commitment (bytes32 at offset 144-176)
        bytes32 inputCommitment = TEST_INPUT_COMMITMENT;
        for (uint256 i = 0; i < 32; i++) {
            journal[144 + i] = inputCommitment[i];
        }

        // action_commitment (bytes32 at offset 176-208)
        for (uint256 i = 0; i < 32; i++) {
            journal[176 + i] = actionCommitment[i];
        }

        // execution_status = 0x01 (success) at offset 208
        journal[208] = 0x01;

        return journal;
    }

    /// @notice Build AgentOutput with a single TRANSFER_ERC20 action
    function _buildTransferAction(address tokenAddr, address to, uint256 amount)
        internal
        pure
        returns (bytes memory)
    {
        // Create payload: abi.encode(token, to, amount)
        bytes memory payload = abi.encode(tokenAddr, to, amount);

        // Create action
        KernelOutputParser.Action[] memory actions = new KernelOutputParser.Action[](1);
        actions[0] = KernelOutputParser.Action({
            actionType: KernelOutputParser.ACTION_TYPE_TRANSFER_ERC20,
            target: bytes32(uint256(uint160(tokenAddr))), // target can be token address
            payload: payload
        });

        return KernelOutputParser.encodeAgentOutput(actions);
    }

    /// @notice Build AgentOutput with multiple actions
    function _buildMultipleTransferActions(
        address tokenAddr,
        address[] memory recipients,
        uint256[] memory amounts
    ) internal pure returns (bytes memory) {
        require(recipients.length == amounts.length, "Length mismatch");

        KernelOutputParser.Action[] memory actions =
            new KernelOutputParser.Action[](recipients.length);

        for (uint256 i = 0; i < recipients.length; i++) {
            bytes memory payload = abi.encode(tokenAddr, recipients[i], amounts[i]);
            actions[i] = KernelOutputParser.Action({
                actionType: KernelOutputParser.ACTION_TYPE_TRANSFER_ERC20,
                target: bytes32(uint256(uint160(tokenAddr))),
                payload: payload
            });
        }

        return KernelOutputParser.encodeAgentOutput(actions);
    }

    // ============ Deposit Tests ============

    function test_deposit_success() public {
        vm.prank(user);
        uint256 sharesMinted = vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        assertEq(sharesMinted, DEPOSIT_AMOUNT);
        assertEq(vault.shares(user), DEPOSIT_AMOUNT);
        assertEq(vault.totalShares(), DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(address(vault)), DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(user), INITIAL_BALANCE - DEPOSIT_AMOUNT);
    }

    function test_deposit_zeroAmount_reverts() public {
        vm.prank(user);
        vm.expectRevert(KernelVault.ZeroDeposit.selector);
        vault.depositERC20Tokens(0);
    }

    function test_deposit_multipleDeposits() public {
        vm.startPrank(user);

        vault.depositERC20Tokens(DEPOSIT_AMOUNT);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        vm.stopPrank();

        assertEq(vault.shares(user), DEPOSIT_AMOUNT * 2);
        assertEq(vault.totalShares(), DEPOSIT_AMOUNT * 2);
    }

    // ============ Withdraw Tests ============

    function test_withdraw_success() public {
        vm.startPrank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        uint256 balanceBefore = token.balanceOf(user);
        uint256 amount = vault.withdraw(DEPOSIT_AMOUNT);
        vm.stopPrank();

        assertEq(amount, DEPOSIT_AMOUNT);
        assertEq(vault.shares(user), 0);
        assertEq(vault.totalShares(), 0);
        assertEq(token.balanceOf(user), balanceBefore + DEPOSIT_AMOUNT);
    }

    function test_withdraw_partial() public {
        vm.startPrank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        vault.withdraw(withdrawAmount);
        vm.stopPrank();

        assertEq(vault.shares(user), DEPOSIT_AMOUNT - withdrawAmount);
    }

    function test_withdraw_zeroAmount_reverts() public {
        vm.prank(user);
        vm.expectRevert(KernelVault.ZeroWithdraw.selector);
        vault.withdraw(0);
    }

    function test_withdraw_insufficientShares_reverts() public {
        vm.startPrank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        vm.expectRevert(
            abi.encodeWithSelector(
                KernelVault.InsufficientShares.selector, DEPOSIT_AMOUNT + 1, DEPOSIT_AMOUNT
            )
        );
        vault.withdraw(DEPOSIT_AMOUNT + 1);
        vm.stopPrank();
    }

    // ============ Execute Tests ============

    function test_execute_transferAction_success() public {
        // Setup: deposit tokens to vault
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        uint256 transferAmount = 10 ether;

        // Build agent output with transfer action
        bytes memory agentOutputBytes =
            _buildTransferAction(address(token), recipient, transferAmount);

        // Compute action commitment
        bytes32 actionCommitment = sha256(agentOutputBytes);

        // Build journal
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);

        // Execute
        bytes memory seal = hex"deadbeef"; // Mock verifier ignores this

        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        vault.execute(journal, seal, agentOutputBytes);

        // Verify transfer occurred
        assertEq(token.balanceOf(recipient), recipientBalanceBefore + transferAmount);
        assertEq(token.balanceOf(address(vault)), vaultBalanceBefore - transferAmount);

        // Verify nonce updated
        assertEq(vault.lastExecutionNonce(), nonce);
    }

    function test_execute_multipleTransfers_success() public {
        // Setup: deposit tokens to vault
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        // Build multiple transfer actions
        address[] memory recipients = new address[](3);
        recipients[0] = address(0x1111);
        recipients[1] = address(0x2222);
        recipients[2] = address(0x3333);

        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 5 ether;
        amounts[1] = 10 ether;
        amounts[2] = 15 ether;

        bytes memory agentOutputBytes =
            _buildMultipleTransferActions(address(token), recipients, amounts);
        bytes32 actionCommitment = sha256(agentOutputBytes);

        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        vault.execute(journal, seal, agentOutputBytes);

        // Verify all transfers
        assertEq(token.balanceOf(recipients[0]), amounts[0]);
        assertEq(token.balanceOf(recipients[1]), amounts[1]);
        assertEq(token.balanceOf(recipients[2]), amounts[2]);
    }

    function test_execute_replayProtection_reverts() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        bytes memory agentOutputBytes = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        // First execution should succeed
        vault.execute(journal, seal, agentOutputBytes);

        // Second execution with same nonce should fail
        vm.expectRevert(abi.encodeWithSelector(KernelVault.InvalidNonce.selector, nonce, nonce));
        vault.execute(journal, seal, agentOutputBytes);
    }

    function test_execute_nonceGap_withinLimit_succeeds() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        // Execute with nonce 1 (correct - lastNonce is 0)
        bytes memory agentOutputBytes1 = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 actionCommitment1 = sha256(agentOutputBytes1);
        uint64 nonce1 = 1;
        bytes memory journal1 = _buildJournal(TEST_AGENT_ID, nonce1, actionCommitment1);
        bytes memory seal = hex"deadbeef";

        vault.execute(journal1, seal, agentOutputBytes1);
        assertEq(vault.lastExecutionNonce(), 1);

        // Execute with nonce 3 (skipping nonce 2 - allowed with gap tolerance)
        bytes memory agentOutputBytes2 = _buildTransferAction(address(token), recipient, 2 ether);
        bytes32 actionCommitment2 = sha256(agentOutputBytes2);
        uint64 nonce2 = 3;
        bytes memory journal2 = _buildJournal(TEST_AGENT_ID, nonce2, actionCommitment2);

        // Gap of 2 is within MAX_NONCE_GAP (100), so this should succeed
        vault.execute(journal2, seal, agentOutputBytes2);
        assertEq(vault.lastExecutionNonce(), 3);
    }

    function test_execute_nonceGap_exceedsLimit_reverts() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        // Execute with nonce 1
        bytes memory agentOutputBytes1 = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 actionCommitment1 = sha256(agentOutputBytes1);
        uint64 nonce1 = 1;
        bytes memory journal1 = _buildJournal(TEST_AGENT_ID, nonce1, actionCommitment1);
        bytes memory seal = hex"deadbeef";

        vault.execute(journal1, seal, agentOutputBytes1);

        // Try to execute with nonce 102 (gap of 101 exceeds MAX_NONCE_GAP of 100)
        bytes memory agentOutputBytes2 = _buildTransferAction(address(token), recipient, 2 ether);
        bytes32 actionCommitment2 = sha256(agentOutputBytes2);
        uint64 nonce2 = 102;
        bytes memory journal2 = _buildJournal(TEST_AGENT_ID, nonce2, actionCommitment2);

        vm.expectRevert(
            abi.encodeWithSelector(KernelVault.NonceGapTooLarge.selector, nonce1, nonce2, 100)
        );
        vault.execute(journal2, seal, agentOutputBytes2);
    }

    function test_execute_actionCommitmentMismatch_reverts() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        bytes memory agentOutputBytes = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 wrongCommitment = bytes32(uint256(0xBADBAD));
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, wrongCommitment);
        bytes memory seal = hex"deadbeef";

        bytes32 actualCommitment = sha256(agentOutputBytes);

        vm.expectRevert(
            abi.encodeWithSelector(
                KernelVault.ActionCommitmentMismatch.selector, wrongCommitment, actualCommitment
            )
        );
        vault.execute(journal, seal, agentOutputBytes);
    }

    function test_execute_wrongAgentId_reverts() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        bytes memory agentOutputBytes = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;

        // Use wrong agent ID
        bytes32 wrongAgentId = bytes32(uint256(0xBADA6E17));
        bytes memory journal = _buildJournal(wrongAgentId, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        // With verifyAndParseWithImageId, the vault checks agentId match after parsing
        // The verifier no longer checks agent registration - it uses the caller-provided imageId
        vm.expectRevert(
            abi.encodeWithSelector(
                KernelVault.AgentIdMismatch.selector, TEST_AGENT_ID, wrongAgentId
            )
        );
        vault.execute(journal, seal, agentOutputBytes);
    }

    function test_execute_emitsEvent() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        bytes memory agentOutputBytes = _buildTransferAction(address(token), recipient, 1 ether);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        vm.expectEmit(true, true, false, true);
        emit KernelVault.ExecutionApplied(TEST_AGENT_ID, nonce, actionCommitment, 1);

        vault.execute(journal, seal, agentOutputBytes);
    }

    function test_execute_incrementingNonces_success() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        bytes memory seal = hex"deadbeef";

        // Execute multiple times with incrementing nonces
        for (uint64 i = 1; i <= 5; i++) {
            bytes memory agentOutputBytes = _buildTransferAction(address(token), recipient, 1 ether);
            bytes32 actionCommitment = sha256(agentOutputBytes);
            bytes memory journal = _buildJournal(TEST_AGENT_ID, i, actionCommitment);

            vault.execute(journal, seal, agentOutputBytes);
            assertEq(vault.lastExecutionNonce(), i);
        }

        assertEq(token.balanceOf(recipient), 5 ether);
    }

    // ============ Edge Cases ============

    function test_execute_emptyActions() public {
        // Setup
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        // Build empty action output
        KernelOutputParser.Action[] memory actions = new KernelOutputParser.Action[](0);
        bytes memory agentOutputBytes = KernelOutputParser.encodeAgentOutput(actions);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        // Should succeed with no actions executed
        vault.execute(journal, seal, agentOutputBytes);
        assertEq(vault.lastExecutionNonce(), nonce);
    }

    function test_constants() public view {
        assertEq(vault.ACTION_TYPE_CALL(), 0x00000002);
        assertEq(vault.ACTION_TYPE_TRANSFER_ERC20(), 0x00000003);
        assertEq(vault.agentId(), TEST_AGENT_ID);
        assertEq(vault.trustedImageId(), TEST_IMAGE_ID);
    }

    function test_constructor_zeroImageId_reverts() public {
        vm.expectRevert(KernelVault.InvalidTrustedImageId.selector);
        new KernelVault(address(token), address(executionVerifier), TEST_AGENT_ID, bytes32(0));
    }

    function test_execute_usesVerifyAndParseWithImageId() public {
        // This test verifies that execute() uses verifyAndParseWithImageId with the pinned trustedImageId
        // We can verify this by checking that execution works correctly when the vault is configured
        // with a trustedImageId that matches the mock verifier's expectations

        // Setup: deposit tokens to vault
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);

        uint256 transferAmount = 10 ether;
        bytes memory agentOutputBytes =
            _buildTransferAction(address(token), recipient, transferAmount);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        uint256 recipientBalanceBefore = token.balanceOf(recipient);

        // Execute - this will use verifyAndParseWithImageId internally
        vault.execute(journal, seal, agentOutputBytes);

        // Verify transfer occurred
        assertEq(token.balanceOf(recipient), recipientBalanceBefore + transferAmount);
        assertEq(vault.lastExecutionNonce(), nonce);
    }

    // ============ PPS Accounting Tests ============

    function test_totalAssets_returnsBalance() public {
        // Initially zero
        assertEq(vault.totalAssets(), 0);

        // After deposit
        vm.prank(user);
        vault.depositERC20Tokens(DEPOSIT_AMOUNT);
        assertEq(vault.totalAssets(), DEPOSIT_AMOUNT);
        assertEq(vault.totalAssets(), token.balanceOf(address(vault)));
    }

    function test_convertToShares_whenEmpty_returnsOneToOne() public view {
        // When totalShares == 0, should return 1:1
        assertEq(vault.convertToShares(100 ether), 100 ether);
        assertEq(vault.convertToShares(1), 1);
    }

    function test_convertToAssets_whenEmpty_returnsOneToOne() public view {
        // When totalShares == 0, should return 1:1
        assertEq(vault.convertToAssets(100 ether), 100 ether);
        assertEq(vault.convertToAssets(1), 1);
    }

    function test_deposit_whenEmpty_mintsOneToOne() public {
        // totalShares=0, deposit 100 → 100 shares (1:1)
        vm.prank(user);
        uint256 sharesMinted = vault.depositERC20Tokens(100 ether);

        assertEq(sharesMinted, 100 ether);
        assertEq(vault.shares(user), 100 ether);
        assertEq(vault.totalShares(), 100 ether);
        assertEq(vault.totalAssets(), 100 ether);
    }

    function test_deposit_withYield_mintsPPS() public {
        // User1 deposits 100 assets → gets 100 shares (1:1 when empty)
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        assertEq(vault.shares(user), 100 ether);
        assertEq(vault.totalShares(), 100 ether);
        assertEq(vault.totalAssets(), 100 ether);

        // Simulate yield: mint 100 tokens directly to vault (doubling assets)
        token.mint(address(vault), 100 ether);

        // Now totalAssets = 200 ether, totalShares = 100 ether
        // PPS = 200/100 = 2
        assertEq(vault.totalAssets(), 200 ether);
        assertEq(vault.totalShares(), 100 ether);

        // User2 deposits 100 assets → should get 50 shares
        // shares = assets * totalShares / totalAssets = 100 * 100 / 200 = 50
        address user2 = address(0x3333333333333333333333333333333333333333);
        token.mint(user2, 100 ether);
        vm.startPrank(user2);
        token.approve(address(vault), type(uint256).max);
        uint256 sharesMinted = vault.depositERC20Tokens(100 ether);
        vm.stopPrank();

        assertEq(sharesMinted, 50 ether);
        assertEq(vault.shares(user2), 50 ether);
        assertEq(vault.totalShares(), 150 ether);
        assertEq(vault.totalAssets(), 300 ether);
    }

    function test_withdraw_reflectsPPS() public {
        // User1 deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Simulate yield: double the assets
        token.mint(address(vault), 100 ether);

        // Now totalAssets = 200, totalShares = 100
        assertEq(vault.totalAssets(), 200 ether);
        assertEq(vault.totalShares(), 100 ether);

        // User1 withdraws 100 shares → should get 200 assets
        // assets = shares * totalAssets / totalShares = 100 * 200 / 100 = 200
        uint256 balanceBefore = token.balanceOf(user);
        vm.prank(user);
        uint256 assetsOut = vault.withdraw(100 ether);

        assertEq(assetsOut, 200 ether);
        assertEq(token.balanceOf(user), balanceBefore + 200 ether);
        assertEq(vault.shares(user), 0);
        assertEq(vault.totalShares(), 0);
        assertEq(vault.totalAssets(), 0);
    }

    function test_withdraw_partialAfterYield() public {
        // User deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Simulate yield: double the assets
        token.mint(address(vault), 100 ether);

        // Now totalAssets = 200, totalShares = 100
        // User withdraws 50 shares → should get 100 assets
        // assets = 50 * 200 / 100 = 100
        uint256 balanceBefore = token.balanceOf(user);
        vm.prank(user);
        uint256 assetsOut = vault.withdraw(50 ether);

        assertEq(assetsOut, 100 ether);
        assertEq(token.balanceOf(user), balanceBefore + 100 ether);
        assertEq(vault.shares(user), 50 ether);
        assertEq(vault.totalShares(), 50 ether);
        assertEq(vault.totalAssets(), 100 ether);
    }

    function test_execute_changesPPS_notShares() public {
        // User deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        assertEq(vault.totalShares(), 100 ether);
        assertEq(vault.totalAssets(), 100 ether);

        // Execute transfers 40 tokens out of vault
        uint256 transferAmount = 40 ether;
        bytes memory agentOutputBytes =
            _buildTransferAction(address(token), recipient, transferAmount);
        bytes32 actionCommitment = sha256(agentOutputBytes);
        uint64 nonce = 1;
        bytes memory journal = _buildJournal(TEST_AGENT_ID, nonce, actionCommitment);
        bytes memory seal = hex"deadbeef";

        vault.execute(journal, seal, agentOutputBytes);

        // Shares should NOT change
        assertEq(vault.totalShares(), 100 ether);
        assertEq(vault.shares(user), 100 ether);

        // Assets should decrease
        assertEq(vault.totalAssets(), 60 ether);

        // User withdraws all 100 shares → should get only 60 assets
        // assets = 100 * 60 / 100 = 60
        uint256 balanceBefore = token.balanceOf(user);
        vm.prank(user);
        uint256 assetsOut = vault.withdraw(100 ether);

        assertEq(assetsOut, 60 ether);
        assertEq(token.balanceOf(user), balanceBefore + 60 ether);
    }

    function test_convertToShares_afterYield() public {
        // User deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Simulate yield: double the assets
        token.mint(address(vault), 100 ether);

        // Now totalAssets = 200, totalShares = 100
        // convertToShares(100) = 100 * 100 / 200 = 50
        assertEq(vault.convertToShares(100 ether), 50 ether);
        assertEq(vault.convertToShares(200 ether), 100 ether);
        assertEq(vault.convertToShares(50 ether), 25 ether);
    }

    function test_convertToAssets_afterYield() public {
        // User deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Simulate yield: double the assets
        token.mint(address(vault), 100 ether);

        // Now totalAssets = 200, totalShares = 100
        // convertToAssets(100) = 100 * 200 / 100 = 200
        assertEq(vault.convertToAssets(100 ether), 200 ether);
        assertEq(vault.convertToAssets(50 ether), 100 ether);
        assertEq(vault.convertToAssets(25 ether), 50 ether);
    }

    function test_pps_multipleUsersWithYield() public {
        // User1 deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Yield: +50 assets (now 150 assets, 100 shares, PPS = 1.5)
        token.mint(address(vault), 50 ether);

        // User2 deposits 150 assets → gets 100 shares (150 * 100 / 150 = 100)
        address user2 = address(0x4444444444444444444444444444444444444444);
        token.mint(user2, 150 ether);
        vm.startPrank(user2);
        token.approve(address(vault), type(uint256).max);
        uint256 user2Shares = vault.depositERC20Tokens(150 ether);
        vm.stopPrank();

        assertEq(user2Shares, 100 ether);

        // State: totalAssets = 300, totalShares = 200, PPS = 1.5
        assertEq(vault.totalAssets(), 300 ether);
        assertEq(vault.totalShares(), 200 ether);

        // More yield: +60 assets (now 360 assets, 200 shares, PPS = 1.8)
        token.mint(address(vault), 60 ether);

        // User1 withdraws 100 shares → gets 180 assets (100 * 360 / 200 = 180)
        uint256 user1BalanceBefore = token.balanceOf(user);
        vm.prank(user);
        uint256 user1Out = vault.withdraw(100 ether);
        assertEq(user1Out, 180 ether);
        assertEq(token.balanceOf(user), user1BalanceBefore + 180 ether);

        // User2 withdraws 100 shares → gets 180 assets (100 * 180 / 100 = 180)
        uint256 user2BalanceBefore = token.balanceOf(user2);
        vm.prank(user2);
        uint256 user2Out = vault.withdraw(100 ether);
        assertEq(user2Out, 180 ether);
        assertEq(token.balanceOf(user2), user2BalanceBefore + 180 ether);

        // Vault should be empty
        assertEq(vault.totalAssets(), 0);
        assertEq(vault.totalShares(), 0);
    }

    function test_execute_assetsIncrease_ppsGoesUp() public {
        // User deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Simulate an execute that brings assets INTO the vault
        // We'll do this by minting directly (simulating a profitable trade)
        token.mint(address(vault), 50 ether);

        // Now totalAssets = 150, totalShares = 100
        // User's 100 shares are now worth 150 assets
        assertEq(vault.convertToAssets(100 ether), 150 ether);

        vm.prank(user);
        uint256 assetsOut = vault.withdraw(100 ether);
        assertEq(assetsOut, 150 ether);
    }

    function test_rounding_depositorGetsFewer() public {
        // User1 deposits 100 assets → gets 100 shares
        vm.prank(user);
        vault.depositERC20Tokens(100 ether);

        // Add 1 wei of yield
        token.mint(address(vault), 1);

        // totalAssets = 100 ether + 1, totalShares = 100 ether
        // User2 deposits 100 ether
        // shares = 100 ether * 100 ether / (100 ether + 1)
        // Due to floor rounding, depositor gets slightly fewer shares
        address user2 = address(0x5555555555555555555555555555555555555555);
        token.mint(user2, 100 ether);
        vm.startPrank(user2);
        token.approve(address(vault), type(uint256).max);
        uint256 sharesMinted = vault.depositERC20Tokens(100 ether);
        vm.stopPrank();

        // shares should be slightly less than 100 ether due to rounding
        assertLt(sharesMinted, 100 ether);
    }
}
