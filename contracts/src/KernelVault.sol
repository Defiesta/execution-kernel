// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IKernelExecutionVerifier } from "./interfaces/IKernelExecutionVerifier.sol";
import { IERC20 } from "./interfaces/IERC20.sol";
import { KernelOutputParser } from "./KernelOutputParser.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title KernelVault
/// @notice MVP vault that executes agent actions verified by RISC Zero proofs
/// @dev This contract:
///      1. Holds a single ERC20 asset
///      2. Allows deposits/withdrawals with ERC4626-like PPS (price-per-share) accounting
///      3. Executes agent actions only when valid proof + journal are provided
///      4. Verifies action commitment and parses actions from AgentOutput bytes
///      5. Share price adjusts automatically based on totalAssets/totalShares ratio
contract KernelVault is ReentrancyGuard {
    // ============ Constants ============

    /// @notice Action type for generic contract call
    uint32 public constant ACTION_TYPE_CALL = 0x00000002;

    /// @notice Action type for ERC20 transfer
    uint32 public constant ACTION_TYPE_TRANSFER_ERC20 = 0x00000003;

    /// @notice Action type for no-op
    uint32 public constant ACTION_TYPE_NO_OP = 0x00000004;

    /// @notice Maximum allowed gap between nonces for liveness (prevents stuck execution)
    /// @dev Allows operators to skip intermediate executions if needed (e.g., if nonce N is lost/stuck,
    ///      executions N+1 through N+MAX_NONCE_GAP can still proceed). This weakens strict ordering
    ///      but improves liveness. Document: skipped nonces are permanently lost.
    uint64 public constant MAX_NONCE_GAP = 100;

    // ============ Immutables ============

    /// @notice The ERC20 asset this vault holds
    IERC20 public immutable asset;

    /// @notice The KernelExecutionVerifier contract
    IKernelExecutionVerifier public immutable verifier;

    /// @notice The agent ID this vault is bound to
    bytes32 public immutable agentId;

    /// @notice The trusted imageId pinned at vault deployment (immutable)
    /// @dev This is read from AgentRegistry at deployment time and never changes.
    ///      Registry updates do NOT affect this vault's imageId.
    bytes32 public immutable trustedImageId;

    // ============ State ============

    /// @notice Total shares outstanding
    uint256 public totalShares;

    /// @notice Last execution timestamp
    uint256 public lastExecutionTimestamp;

    /// @notice Last execution nonce processed (for replay protection)
    uint64 public lastExecutionNonce;

    /// @notice Shares balance per account
    mapping(address => uint256) public shares;

    // ============ Events ============

    /// @notice Emitted when tokens are deposited
    event Deposit(address indexed sender, uint256 amount, uint256 shares);

    /// @notice Emitted when tokens are withdrawn
    event Withdraw(address indexed sender, uint256 amount, uint256 shares);

    /// @notice Emitted when an execution is applied
    event ExecutionApplied(
        bytes32 indexed agentId,
        uint64 indexed executionNonce,
        bytes32 actionCommitment,
        uint256 actionCount
    );

    /// @notice Emitted when an action is executed
    event ActionExecuted(
        uint256 indexed actionIndex, uint32 actionType, bytes32 target, bool success
    );

    /// @notice Emitted when a no-op action is executed
    event NoOpActionExecuted(uint256 indexed actionIndex, uint32 actionType);

    /// @notice Emitted when a transfer action is executed (more detailed than ActionExecuted)
    /// @dev For transfers, `to` is the meaningful recipient (ActionExecuted.target is the token address)
    event TransferExecuted(
        uint256 indexed actionIndex, address indexed token, address indexed to, uint256 amount
    );

    /// @notice Emitted when nonces are skipped (gap in sequence)
    event NoncesSkipped(uint64 indexed fromNonce, uint64 indexed toNonce, uint64 skippedCount);

    // ============ Errors ============

    /// @notice Agent ID in journal doesn't match vault's agent ID
    error AgentIdMismatch(bytes32 expected, bytes32 actual);

    /// @notice Execution nonce is not valid (must be > lastNonce and <= lastNonce + MAX_NONCE_GAP)
    error InvalidNonce(uint64 lastNonce, uint64 providedNonce);

    /// @notice Nonce gap too large (exceeds MAX_NONCE_GAP)
    error NonceGapTooLarge(uint64 lastNonce, uint64 providedNonce, uint64 maxGap);

    /// @notice Action commitment doesn't match sha256(agentOutputBytes)
    error ActionCommitmentMismatch(bytes32 expected, bytes32 actual);

    /// @notice Deposit amount is zero
    error ZeroDeposit();

    /// @notice Withdraw amount exceeds balance
    error InsufficientShares(uint256 requested, uint256 available);

    /// @notice Withdraw amount is zero
    error ZeroWithdraw();

    /// @notice ERC20 transfer failed
    error TransferFailed();

    /// @notice External call failed
    error CallFailed(bytes32 target, bytes returnData);

    /// @notice Unknown action type
    error UnknownActionType(uint32 actionType);

    /// @notice Invalid transfer payload
    error InvalidTransferPayload();

    /// @notice Invalid call payload
    error InvalidCallPayload();

    /// @notice Zero shares provided
    error ZeroShares();

    /// @notice Zero assets provided
    error ZeroAssets();

    /// @notice Zero assets out calculated
    error ZeroAssetsOut();

    /// @notice ETH deposit amount doesn't match msg.value
    error ETHDepositMismatch(uint256 expected, uint256 actual);

    /// @notice ETH transfer failed
    error ETHTransferFailed();

    /// @notice Wrong deposit function called for this vault type
    error WrongDepositFunction();

    /// @notice Invalid trusted image ID (zero)
    error InvalidTrustedImageId();

    // ============ Constructor ============

    /// @notice Initialize the vault
    /// @param _asset The ERC20 asset this vault holds
    /// @param _verifier The KernelExecutionVerifier contract address
    /// @param _agentId The agent ID this vault is bound to
    /// @param _trustedImageId The trusted RISC Zero image ID (pinned at deployment)
    constructor(address _asset, address _verifier, bytes32 _agentId, bytes32 _trustedImageId) {
        if (_trustedImageId == bytes32(0)) revert InvalidTrustedImageId();
        asset = IERC20(_asset);
        verifier = IKernelExecutionVerifier(_verifier);
        agentId = _agentId;
        trustedImageId = _trustedImageId;
    }

    // ============ Deposit/Withdraw ============

    /// @notice Deposit ERC20 tokens and receive shares based on current PPS
    /// @param assets Amount of ERC20 tokens to deposit
    /// @return sharesMinted Number of shares minted based on current exchange rate
    /// @dev MVP uses simple PPS math. First deposit is 1:1, subsequent deposits use
    ///      shares = assets * totalShares / totalAssets.
    function depositERC20Tokens(uint256 assets)
        external
        nonReentrant
        returns (uint256 sharesMinted)
    {
        if (address(asset) == address(0)) revert WrongDepositFunction();
        if (assets == 0) revert ZeroDeposit();

        // Calculate shares BEFORE transfer (use pre-transfer totalAssets)
        uint256 supply = totalShares;
        uint256 assetsBefore = asset.balanceOf(address(this));

        if (supply == 0) {
            // First deposit: 1:1 ratio
            sharesMinted = assets;
        } else {
            // Subsequent deposits: standard PPS calculation
            if (assetsBefore == 0) revert ZeroAssets();
            sharesMinted = (assets * supply) / assetsBefore;
            if (sharesMinted == 0) revert ZeroShares();
        }

        // Transfer tokens from sender
        bool success = asset.transferFrom(msg.sender, address(this), assets);
        if (!success) revert TransferFailed();

        // Update state
        shares[msg.sender] += sharesMinted;
        totalShares += sharesMinted;

        emit Deposit(msg.sender, assets, sharesMinted);
    }

    /// @notice Deposit ETH and receive shares based on current PPS
    /// @return sharesMinted Number of shares minted based on current exchange rate
    /// @dev MVP uses simple PPS math. First deposit is 1:1, subsequent deposits use
    ///      shares = msg.value * totalShares / totalAssets.
    ///      Only works when vault asset is address(0) (ETH vault).
    function depositETH() external payable nonReentrant returns (uint256 sharesMinted) {
        if (address(asset) != address(0)) revert WrongDepositFunction();
        if (msg.value == 0) revert ZeroDeposit();

        // Calculate shares BEFORE transfer
        // msg.value is already added to balance, so subtract it for pre-transfer calculation
        uint256 supply = totalShares;
        uint256 assetsBefore = address(this).balance - msg.value;

        if (supply == 0) {
            // First deposit: 1:1 ratio
            sharesMinted = msg.value;
        } else {
            // Subsequent deposits: standard PPS calculation
            if (assetsBefore == 0) revert ZeroAssets();
            sharesMinted = (msg.value * supply) / assetsBefore;
            if (sharesMinted == 0) revert ZeroShares();
        }

        // Update state
        shares[msg.sender] += sharesMinted;
        totalShares += sharesMinted;

        emit Deposit(msg.sender, msg.value, sharesMinted);
    }

    /// @notice Withdraw tokens (or ETH if asset is address(0)) by burning shares based on current PPS
    /// @param shareAmount Number of shares to burn
    /// @return assetsOut Amount of tokens returned based on current exchange rate
    function withdraw(uint256 shareAmount) external nonReentrant returns (uint256 assetsOut) {
        if (shareAmount == 0) revert ZeroWithdraw();
        if (shares[msg.sender] < shareAmount) {
            revert InsufficientShares(shareAmount, shares[msg.sender]);
        }

        // Calculate assets BEFORE burning shares (use pre-burn totalShares)
        uint256 assetsBefore = totalAssets();
        uint256 supply = totalShares;
        if (supply == 0) revert ZeroShares();

        assetsOut = (shareAmount * assetsBefore) / supply;
        if (assetsOut == 0) revert ZeroAssetsOut();

        // Burn shares
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        // Transfer tokens or ETH
        bool isETH = address(asset) == address(0);
        if (isETH) {
            (bool success,) = msg.sender.call{ value: assetsOut }("");
            if (!success) revert ETHTransferFailed();
        } else {
            bool success = asset.transfer(msg.sender, assetsOut);
            if (!success) revert TransferFailed();
        }

        emit Withdraw(msg.sender, assetsOut, shareAmount);
    }

    // ============ Execution ============

    /// @notice Execute agent actions from a verified proof (atomic - all actions must succeed)
    /// @param journal The raw journal bytes (209 bytes)
    /// @param seal The RISC Zero proof seal
    /// @param agentOutputBytes The agent output bytes containing actions
    function execute(bytes calldata journal, bytes calldata seal, bytes calldata agentOutputBytes)
        external
        nonReentrant
    {
        // 1. Verify proof and parse journal using pinned trustedImageId
        IKernelExecutionVerifier.ParsedJournal memory parsed =
            verifier.verifyAndParseWithImageId(trustedImageId, journal, seal);

        // 2. Verify agent ID matches
        if (parsed.agentId != agentId) {
            revert AgentIdMismatch(agentId, parsed.agentId);
        }

        // 3. Verify nonce is valid (must be > lastNonce and within MAX_NONCE_GAP)
        // This allows gaps for liveness while preventing replay and unbounded skips
        uint64 lastNonce = lastExecutionNonce;
        uint64 providedNonce = parsed.executionNonce;

        if (providedNonce <= lastNonce) {
            revert InvalidNonce(lastNonce, providedNonce);
        }

        uint64 gap = providedNonce - lastNonce;
        if (gap > MAX_NONCE_GAP) {
            revert NonceGapTooLarge(lastNonce, providedNonce, MAX_NONCE_GAP);
        }

        // Emit event if nonces were skipped
        if (gap > 1) {
            emit NoncesSkipped(lastNonce + 1, providedNonce - 1, gap - 1);
        }

        // 4. Verify action commitment
        bytes32 computedCommitment = sha256(agentOutputBytes);
        if (computedCommitment != parsed.actionCommitment) {
            revert ActionCommitmentMismatch(parsed.actionCommitment, computedCommitment);
        }

        // 5. Update last execution nonce
        lastExecutionNonce = providedNonce;

        // 6. Parse actions from agentOutputBytes
        KernelOutputParser.Action[] memory actions =
            KernelOutputParser.parseActions(agentOutputBytes);

        // 7. Execute actions in order (atomic - any failure reverts entire execution)
        for (uint256 i = 0; i < actions.length; i++) {
            _executeAction(i, actions[i]);
        }

        // 8. Emit execution event
        emit ExecutionApplied(
            parsed.agentId, parsed.executionNonce, parsed.actionCommitment, actions.length
        );
    }

    // ============ Internal ============

    /// @notice Execute a single action
    /// @param index Action index (for events)
    /// @param action The action to execute
    function _executeAction(uint256 index, KernelOutputParser.Action memory action) internal {
        lastExecutionTimestamp = block.timestamp;

        if (action.actionType == ACTION_TYPE_TRANSFER_ERC20) {
            _executeTransferERC20(index, action);
        } else if (action.actionType == ACTION_TYPE_CALL) {
            _executeCall(index, action);
        } else if (action.actionType == ACTION_TYPE_NO_OP) {
            emit NoOpActionExecuted(index, action.actionType);
        } else {
            revert UnknownActionType(action.actionType);
        }
    }

    /// @notice Execute a TRANSFER_ERC20 action (also handles ETH if token is address(0))
    /// @dev Payload format: abi.encode(address token, address to, uint256 amount)
    ///      MVP: only allows transfers of the vault's single asset
    function _executeTransferERC20(uint256 index, KernelOutputParser.Action memory action)
        internal
    {
        // Decode payload: (address token, address to, uint256 amount)
        if (action.payload.length != 96) {
            revert InvalidTransferPayload();
        }

        (address token, address to, uint256 amount) =
            abi.decode(action.payload, (address, address, uint256));

        // MVP: enforce single-asset - only allow transfers of the vault's asset
        if (token != address(asset)) {
            revert InvalidTransferPayload();
        }

        // Execute transfer (ETH or ERC20)
        if (token == address(0)) {
            // ETH transfer
            (bool success,) = to.call{ value: amount }("");
            if (!success) revert ETHTransferFailed();
        } else {
            // ERC20 transfer
            bool success = IERC20(token).transfer(to, amount);
            if (!success) revert TransferFailed();
        }

        // Emit detailed transfer event (includes recipient `to` for better observability)
        emit TransferExecuted(index, token, to, amount);
    }

    /// @notice Execute a CALL action
    /// @dev Payload format: abi.encode(uint256 value, bytes callData)
    function _executeCall(uint256 index, KernelOutputParser.Action memory action) internal {
        // Decode payload: (uint256 value, bytes callData)
        if (action.payload.length < 64) {
            revert InvalidCallPayload();
        }

        // Validate target is a valid EVM address (upper 12 bytes must be zero)
        if (uint256(action.target) >> 160 != 0) {
            revert InvalidCallPayload();
        }

        (uint256 value, bytes memory callData) = abi.decode(action.payload, (uint256, bytes));

        // Convert target bytes32 to address (safe after validation above)
        address target = address(uint160(uint256(action.target)));

        // Execute call
        (bool success, bytes memory returnData) = target.call{ value: value }(callData);
        if (!success) {
            revert CallFailed(action.target, returnData);
        }

        emit ActionExecuted(index, action.actionType, action.target, true);
    }

    // ============ View Functions ============

    /// @notice Returns total assets held by the vault
    /// @return Total balance of the vault's asset (ETH balance if asset is address(0))
    function totalAssets() public view returns (uint256) {
        if (address(asset) == address(0)) {
            return address(this).balance;
        }
        return asset.balanceOf(address(this));
    }

    /// @notice Convert assets to shares using current exchange rate
    /// @param assets Amount of assets to convert
    /// @return shares Amount of shares that would be minted
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) return assets;

        if (totalAssets() == 0) return 0; // Prevent division by zero
        return (assets * supply) / totalAssets();
    }

    /// @notice Convert shares to assets using current exchange rate
    /// @param _shares Amount of shares to convert
    /// @return assets Amount of assets that would be returned
    function convertToAssets(uint256 _shares) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return _shares; // 1:1 when empty
        }
        return (_shares * totalAssets()) / supply;
    }

    /// @notice Allow receiving ETH for CALL actions with value
    receive() external payable { }
}
