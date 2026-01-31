// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title MockYieldSource
/// @notice Mock yield source for testing that returns 10% yield on withdrawals
/// @dev Only the designated vault can withdraw funds
contract MockYieldSource {
    // ============ State ============

    /// @notice The vault address that can withdraw
    address public immutable vault;

    /// @notice Deposited amounts per depositor
    mapping(address => uint256) public deposits;

    // ============ Events ============

    /// @notice Emitted when ETH is deposited
    event Deposited(address indexed depositor, uint256 amount);

    /// @notice Emitted when ETH is withdrawn with yield
    event Withdrawn(address indexed depositor, uint256 principal, uint256 yield);

    // ============ Errors ============

    /// @notice Caller is not the vault
    error OnlyVault();

    /// @notice No deposit found for the depositor
    error NoDeposit();

    /// @notice Transfer failed
    error TransferFailed();

    // ============ Constructor ============

    /// @notice Initialize the mock yield source
    /// @param _vault The vault address that can withdraw
    constructor(address _vault) {
        vault = _vault;
    }

    // ============ Receive ============

    /// @notice Receive ETH and track the deposit
    receive() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // ============ Withdraw ============

    /// @notice Withdraw deposited amount plus 10% yield
    /// @param depositor The address whose deposit to withdraw
    /// @dev Only callable by the vault. Transfers principal + 10% yield.
    function withdraw(address depositor) external {
        if (msg.sender != vault) revert OnlyVault();

        uint256 principal = deposits[depositor];
        if (principal == 0) revert NoDeposit();

        // Clear deposit before transfer (CEI pattern)
        deposits[depositor] = 0;

        // Calculate 10% yield
        uint256 yieldAmount = principal / 10;
        uint256 totalAmount = principal + yieldAmount;

        // Transfer to vault
        (bool success,) = vault.call{ value: totalAmount }("");
        if (!success) revert TransferFailed();

        emit Withdrawn(depositor, principal, yieldAmount);
    }

    // ============ View Functions ============

    /// @notice Get the deposit amount for an address
    /// @param depositor The address to check
    /// @return The deposited amount
    function getDeposit(address depositor) external view returns (uint256) {
        return deposits[depositor];
    }

    /// @notice Get the projected withdrawal amount (principal + 10% yield)
    /// @param depositor The address to check
    /// @return The total amount that would be withdrawn
    function getProjectedWithdrawal(address depositor) external view returns (uint256) {
        uint256 principal = deposits[depositor];
        return principal + (principal / 10);
    }
}
