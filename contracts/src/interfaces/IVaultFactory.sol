// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IVaultFactory
/// @notice Interface for CREATE2 vault deployment factory
interface IVaultFactory {
    /// @notice Compute the deterministic vault address before deployment
    /// @param owner The vault owner's address
    /// @param agentId The agent ID from AgentRegistry
    /// @param asset The ERC20 asset address (or address(0) for ETH)
    /// @param userSalt A unique salt chosen by the user
    /// @return vault The computed vault address
    /// @return salt The CREATE2 salt used for deployment
    function computeVaultAddress(
        address owner,
        bytes32 agentId,
        address asset,
        bytes32 userSalt
    ) external view returns (address vault, bytes32 salt);

    /// @notice Deploy a new vault with pinned imageId from registry
    /// @param agentId The agent ID from AgentRegistry
    /// @param asset The ERC20 asset address (or address(0) for ETH)
    /// @param userSalt A unique salt for deterministic deployment
    /// @return vault The deployed vault address
    function deployVault(
        bytes32 agentId,
        address asset,
        bytes32 userSalt
    ) external returns (address vault);

    /// @notice Get the AgentRegistry address
    /// @return The registry contract address
    function registry() external view returns (address);

    /// @notice Get the KernelExecutionVerifier address
    /// @return The verifier contract address
    function verifier() external view returns (address);

    /// @notice Check if an address is a vault deployed by this factory
    /// @param vault The address to check
    /// @return True if the vault was deployed by this factory
    function isDeployedVault(address vault) external view returns (bool);

    /// @notice Emitted when a vault is deployed
    event VaultDeployed(
        address indexed vault,
        address indexed owner,
        bytes32 indexed agentId,
        address asset,
        bytes32 trustedImageId,
        bytes32 salt
    );

    /// @notice Agent not registered in the registry
    error AgentNotRegistered(bytes32 agentId);

    /// @notice Caller is not the agent author
    error NotAgentAuthor(bytes32 agentId, address caller, address author);

    /// @notice Vault already exists at computed address
    error VaultAlreadyExists(address vault);
}
