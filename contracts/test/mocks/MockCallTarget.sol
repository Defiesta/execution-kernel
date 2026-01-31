// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title MockCallTarget
/// @notice A simple contract to test CALL action execution
/// @dev Records calls for test assertions, can be configured to revert
contract MockCallTarget {
    // ============ State ============

    /// @notice Whether to revert on calls
    bool public shouldRevert;

    /// @notice Last function call data received
    bytes public lastCallData;

    /// @notice Last ETH value received
    uint256 public lastValue;

    /// @notice Total ETH received
    uint256 public totalReceived;

    /// @notice Call count for tracking
    uint256 public callCount;

    /// @notice Storage value set by setStorage function
    uint256 public storageValue;

    // ============ Events ============

    /// @notice Emitted when any function is called
    event Called(address indexed caller, uint256 value, bytes data);

    /// @notice Emitted when storage is set
    event StorageSet(uint256 value);

    // ============ Errors ============

    error MockTargetRevert();

    // ============ Configuration ============

    /// @notice Configure whether to revert on calls
    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    /// @notice Reset tracking state
    function reset() external {
        lastCallData = "";
        lastValue = 0;
        callCount = 0;
    }

    // ============ Test Functions ============

    /// @notice A simple function that can be called via CALL action
    /// @param value A value to store
    function setStorage(uint256 value) external payable {
        if (shouldRevert) revert MockTargetRevert();

        storageValue = value;
        lastValue = msg.value;
        callCount++;

        emit StorageSet(value);
    }

    /// @notice A function that simply accepts ETH
    function acceptETH() external payable {
        if (shouldRevert) revert MockTargetRevert();

        totalReceived += msg.value;
        lastValue = msg.value;
        callCount++;

        emit Called(msg.sender, msg.value, msg.data);
    }

    /// @notice Fallback to handle any call
    fallback() external payable {
        if (shouldRevert) revert MockTargetRevert();

        lastCallData = msg.data;
        lastValue = msg.value;
        totalReceived += msg.value;
        callCount++;

        emit Called(msg.sender, msg.value, msg.data);
    }

    /// @notice Receive ETH without data
    receive() external payable {
        if (shouldRevert) revert MockTargetRevert();

        totalReceived += msg.value;
        lastValue = msg.value;
        callCount++;

        emit Called(msg.sender, msg.value, "");
    }
}
