// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IVaultFactory } from "./interfaces/IVaultFactory.sol";
import { IAgentRegistry } from "./interfaces/IAgentRegistry.sol";
import { KernelVault } from "./KernelVault.sol";

/// @title VaultFactory
/// @notice Factory for deploying KernelVault instances with CREATE2
/// @dev Deploys vaults with imageId pinned from AgentRegistry at deployment time.
///      Registry updates do NOT affect already-deployed vaults.
contract VaultFactory is IVaultFactory {
    // ============ Immutables ============

    /// @notice The AgentRegistry contract
    IAgentRegistry public immutable _registry;

    /// @notice The KernelExecutionVerifier contract address
    address public immutable _verifier;

    // ============ State ============

    /// @notice Mapping of deployed vault addresses
    mapping(address => bool) public isDeployedVault;

    // ============ Constructor ============

    /// @notice Initialize the factory
    /// @param registry_ The AgentRegistry contract address
    /// @param verifier_ The KernelExecutionVerifier contract address
    constructor(address registry_, address verifier_) {
        _registry = IAgentRegistry(registry_);
        _verifier = verifier_;
    }

    // ============ External Functions ============

    /// @inheritdoc IVaultFactory
    function registry() external view returns (address) {
        return address(_registry);
    }

    /// @inheritdoc IVaultFactory
    function verifier() external view returns (address) {
        return _verifier;
    }

    /// @inheritdoc IVaultFactory
    function computeVaultAddress(
        address owner,
        bytes32 agentId,
        address asset,
        bytes32 userSalt
    ) external view returns (address vault, bytes32 salt) {
        // Compute CREATE2 salt
        salt = _computeSalt(owner, agentId, asset, userSalt);

        // Get agent info to include imageId in bytecode
        IAgentRegistry.AgentInfo memory agentInfo = _registry.get(agentId);
        if (!agentInfo.exists) {
            revert AgentNotRegistered(agentId);
        }

        // Compute CREATE2 address
        bytes memory bytecode = _getCreationBytecode(asset, agentId, agentInfo.imageId);
        bytes32 bytecodeHash = keccak256(bytecode);

        vault = address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash))
                )
            )
        );

        return (vault, salt);
    }

    /// @inheritdoc IVaultFactory
    function deployVault(
        bytes32 agentId,
        address asset,
        bytes32 userSalt
    ) external returns (address vault) {
        // Get agent info from registry
        IAgentRegistry.AgentInfo memory agentInfo = _registry.get(agentId);
        if (!agentInfo.exists) {
            revert AgentNotRegistered(agentId);
        }

        // Only the agent author can deploy vaults for their agent
        if (msg.sender != agentInfo.author) {
            revert NotAgentAuthor(agentId, msg.sender, agentInfo.author);
        }

        // Compute CREATE2 salt
        bytes32 salt = _computeSalt(msg.sender, agentId, asset, userSalt);

        // Get creation bytecode with constructor args
        bytes memory bytecode = _getCreationBytecode(asset, agentId, agentInfo.imageId);

        // Deploy with CREATE2
        assembly {
            vault := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        // Verify deployment succeeded
        if (vault == address(0)) {
            revert VaultAlreadyExists(vault);
        }

        // Track deployment
        isDeployedVault[vault] = true;

        emit VaultDeployed(vault, msg.sender, agentId, asset, agentInfo.imageId, salt);

        return vault;
    }

    // ============ Internal Functions ============

    /// @notice Compute CREATE2 salt from deployment parameters
    /// @param owner The vault owner
    /// @param agentId The agent ID
    /// @param asset The asset address
    /// @param userSalt User-provided salt for uniqueness
    /// @return The CREATE2 salt
    function _computeSalt(
        address owner,
        bytes32 agentId,
        address asset,
        bytes32 userSalt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, agentId, asset, userSalt));
    }

    /// @notice Get the creation bytecode for KernelVault with constructor arguments
    /// @param asset The asset address
    /// @param agentId The agent ID
    /// @param imageId The trusted image ID
    /// @return The creation bytecode
    function _getCreationBytecode(
        address asset,
        bytes32 agentId,
        bytes32 imageId
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(KernelVault).creationCode,
            abi.encode(asset, _verifier, agentId, imageId)
        );
    }
}
