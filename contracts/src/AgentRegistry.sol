// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IAgentRegistry } from "./interfaces/IAgentRegistry.sol";

/// @title AgentRegistry
/// @notice Permissionless registry for agent registration
/// @dev Agents are identified by a deterministic ID: keccak256(author, salt)
///      Only the original author can update an agent's configuration.
contract AgentRegistry is IAgentRegistry {
    // ============ State ============

    /// @notice Mapping from agentId to agent information
    mapping(bytes32 => AgentInfo) internal _agents;

    // ============ External Functions ============

    /// @inheritdoc IAgentRegistry
    function computeAgentId(address author, bytes32 salt) external pure returns (bytes32) {
        return _computeAgentId(author, salt);
    }

    /// @inheritdoc IAgentRegistry
    function register(
        bytes32 salt,
        bytes32 imageId,
        bytes32 agentCodeHash,
        string calldata metadataURI
    ) external returns (bytes32 agentId) {
        // Validate inputs
        if (imageId == bytes32(0)) revert InvalidImageId();
        if (agentCodeHash == bytes32(0)) revert InvalidAgentCodeHash();

        // Compute deterministic agentId
        agentId = _computeAgentId(msg.sender, salt);

        // Check agent doesn't already exist
        if (_agents[agentId].exists) {
            revert AgentAlreadyExists(agentId);
        }

        // Store agent info
        _agents[agentId] = AgentInfo({
            author: msg.sender,
            imageId: imageId,
            agentCodeHash: agentCodeHash,
            metadataURI: metadataURI,
            exists: true
        });

        emit AgentRegistered(agentId, msg.sender, imageId, agentCodeHash, metadataURI);

        return agentId;
    }

    /// @inheritdoc IAgentRegistry
    function update(
        bytes32 agentId,
        bytes32 newImageId,
        bytes32 newAgentCodeHash,
        string calldata newMetadataURI
    ) external {
        // Check agent exists
        AgentInfo storage agent = _agents[agentId];
        if (!agent.exists) {
            revert AgentNotFound(agentId);
        }

        // Check caller is the author
        if (msg.sender != agent.author) {
            revert NotAgentAuthor(agentId, msg.sender, agent.author);
        }

        // Validate inputs
        if (newImageId == bytes32(0)) revert InvalidImageId();
        if (newAgentCodeHash == bytes32(0)) revert InvalidAgentCodeHash();

        // Update agent info
        agent.imageId = newImageId;
        agent.agentCodeHash = newAgentCodeHash;
        agent.metadataURI = newMetadataURI;

        emit AgentUpdated(agentId, newImageId, newAgentCodeHash, newMetadataURI);
    }

    /// @inheritdoc IAgentRegistry
    function get(bytes32 agentId) external view returns (AgentInfo memory info) {
        return _agents[agentId];
    }

    /// @inheritdoc IAgentRegistry
    function agentExists(bytes32 agentId) external view returns (bool) {
        return _agents[agentId].exists;
    }

    // ============ Internal Functions ============

    /// @notice Compute deterministic agent ID
    /// @param author The agent author's address
    /// @param salt A unique salt chosen by the author
    /// @return The deterministic agent ID
    function _computeAgentId(address author, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(author, salt));
    }
}
