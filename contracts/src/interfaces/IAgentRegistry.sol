// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IAgentRegistry
/// @notice Interface for permissionless agent registration
interface IAgentRegistry {
    /// @notice Agent information stored in the registry
    struct AgentInfo {
        address author;
        bytes32 imageId;
        bytes32 agentCodeHash;
        string metadataURI;
        bool exists;
    }

    /// @notice Compute deterministic agent ID from author and salt
    /// @param author The agent author's address
    /// @param salt A unique salt chosen by the author
    /// @return The deterministic agent ID
    function computeAgentId(address author, bytes32 salt) external pure returns (bytes32);

    /// @notice Register a new agent (permissionless)
    /// @param salt A unique salt for deterministic ID generation
    /// @param imageId The RISC Zero image ID for this agent
    /// @param agentCodeHash The agent code hash
    /// @param metadataURI URI pointing to agent metadata (IPFS, etc.)
    /// @return agentId The registered agent's deterministic ID
    function register(
        bytes32 salt,
        bytes32 imageId,
        bytes32 agentCodeHash,
        string calldata metadataURI
    ) external returns (bytes32 agentId);

    /// @notice Update an existing agent's configuration (author only)
    /// @param agentId The agent ID to update
    /// @param newImageId The new RISC Zero image ID
    /// @param newAgentCodeHash The new agent code hash
    /// @param newMetadataURI The new metadata URI
    function update(
        bytes32 agentId,
        bytes32 newImageId,
        bytes32 newAgentCodeHash,
        string calldata newMetadataURI
    ) external;

    /// @notice Get agent information
    /// @param agentId The agent ID to query
    /// @return info The agent information
    function get(bytes32 agentId) external view returns (AgentInfo memory info);

    /// @notice Check if an agent exists
    /// @param agentId The agent ID to check
    /// @return True if the agent exists
    function agentExists(bytes32 agentId) external view returns (bool);

    /// @notice Emitted when an agent is registered
    event AgentRegistered(
        bytes32 indexed agentId,
        address indexed author,
        bytes32 indexed imageId,
        bytes32 agentCodeHash,
        string metadataURI
    );

    /// @notice Emitted when an agent is updated
    event AgentUpdated(
        bytes32 indexed agentId,
        bytes32 indexed newImageId,
        bytes32 newAgentCodeHash,
        string newMetadataURI
    );

    /// @notice Agent with this ID already exists
    error AgentAlreadyExists(bytes32 agentId);

    /// @notice Agent not found
    error AgentNotFound(bytes32 agentId);

    /// @notice Caller is not the agent author
    error NotAgentAuthor(bytes32 agentId, address caller, address author);

    /// @notice Invalid image ID (zero)
    error InvalidImageId();

    /// @notice Invalid agent code hash (zero)
    error InvalidAgentCodeHash();
}
