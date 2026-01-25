// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IERC20
/// @notice Minimal ERC20 interface for vault operations
interface IERC20 {
    /// @notice Returns the amount of tokens owned by `account`
    function balanceOf(address account) external view returns (uint256);

    /// @notice Moves `amount` tokens from the caller's account to `to`
    /// @return success True if the transfer succeeded
    function transfer(address to, uint256 amount) external returns (bool);

    /// @notice Moves `amount` tokens from `from` to `to` using the allowance mechanism
    /// @return success True if the transfer succeeded
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    /// @notice Sets `amount` as the allowance of `spender` over the caller's tokens
    /// @return success True if the approval succeeded
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice Returns the remaining number of tokens that `spender` can spend on behalf of `owner`
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice Returns the total token supply
    function totalSupply() external view returns (uint256);

    /// @notice Emitted when `value` tokens are moved from one account to another
    event Transfer(address indexed from, address indexed to, uint256 value);

    /// @notice Emitted when the allowance of a `spender` for an `owner` is set
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
