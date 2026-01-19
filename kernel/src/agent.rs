use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::{VaultState, MarketState, Result};

/// Core trait that all financial agents must implement
/// 
/// Agents are pure functions that read state and produce proposed actions
/// without side effects. All computation must be deterministic and bounded.
pub trait Agent {
    /// Execute the agent with current vault and market state
    /// 
    /// # Arguments
    /// * `vault_state` - Current vault state including positions and assets
    /// * `market_state` - Current market data including prices and volatility  
    /// * `params` - Agent-specific configuration parameters
    /// 
    /// # Returns
    /// * `AgentAction` - The proposed action to take (or NoAction)
    fn execute(
        &self,
        vault_state: &VaultState,
        market_state: &MarketState,
        params: &AgentParams,
    ) -> Result<AgentAction>;
    
    /// Validate that the agent can execute with given constraints
    /// Called before execution to check compatibility
    fn validate_constraints(&self, constraints: &crate::ConstraintSet) -> Result<()>;
    
    /// Return the agent's unique identifier hash
    fn agent_hash(&self) -> [u8; 32];
    
    /// Return human-readable agent metadata
    fn metadata(&self) -> AgentMetadata;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentParams {
    pub risk_tolerance: u64,      // Risk tolerance (0-10000)
    pub max_position_size: U256,  // Maximum position size in wei
    pub target_leverage: u64,     // Target leverage (100 = 1x, 200 = 2x)
    pub rebalance_threshold: u64, // Rebalancing threshold percentage
    pub stop_loss: u64,           // Stop loss percentage (0-10000)
    pub take_profit: u64,         // Take profit percentage (0-10000)
    pub custom_params: Vec<(String, String)>, // Agent-specific parameters
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentAction {
    pub action_type: ActionType,
    pub asset: Address,
    pub amount: U256,
    pub target_price: Option<U256>,
    pub expiry: u64,
    pub metadata: ActionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType {
    /// No action required
    NoAction,
    /// Open a long position
    OpenLong,
    /// Open a short position  
    OpenShort,
    /// Close existing position
    ClosePosition,
    /// Rebalance existing position
    Rebalance { new_size: U256 },
    /// Emergency liquidation
    Liquidate,
    /// Withdraw available assets
    Withdraw { recipient: Address },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionMetadata {
    pub confidence: u64,          // Confidence score (0-10000)
    pub reasoning: String,        // Human-readable reasoning
    pub risk_score: u64,          // Risk assessment (0-10000)
    pub expected_return: U256,    // Expected return in wei
    pub max_loss: U256,           // Maximum potential loss
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub strategy_type: StrategyType,
    pub supported_assets: Vec<Address>,
    pub min_vault_size: U256,
    pub max_vault_size: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StrategyType {
    Trend,
    MeanReversion,
    Arbitrage,
    MarketMaking,
    Portfolio,
    RiskManagement,
    Custom(String),
}

impl Default for AgentParams {
    fn default() -> Self {
        Self {
            risk_tolerance: 5000,      // 50% risk tolerance
            max_position_size: U256::from(1000000000000000000u64), // 1 ETH
            target_leverage: 100,      // 1x leverage
            rebalance_threshold: 500,  // 5% rebalancing threshold
            stop_loss: 1000,          // 10% stop loss
            take_profit: 2000,        // 20% take profit
            custom_params: Vec::new(),
        }
    }
}

impl AgentAction {
    pub fn no_action() -> Self {
        Self {
            action_type: ActionType::NoAction,
            asset: Address::ZERO,
            amount: U256::ZERO,
            target_price: None,
            expiry: 0,
            metadata: ActionMetadata::default(),
        }
    }
    
    pub fn open_long(asset: Address, amount: U256, confidence: u64) -> Self {
        Self {
            action_type: ActionType::OpenLong,
            asset,
            amount,
            target_price: None,
            expiry: 0,
            metadata: ActionMetadata {
                confidence,
                reasoning: "Agent decision to open long position".to_string(),
                risk_score: 5000,
                expected_return: U256::ZERO,
                max_loss: amount,
            },
        }
    }
    
    pub fn close_position(asset: Address, confidence: u64) -> Self {
        Self {
            action_type: ActionType::ClosePosition,
            asset,
            amount: U256::ZERO,
            target_price: None,
            expiry: 0,
            metadata: ActionMetadata {
                confidence,
                reasoning: "Agent decision to close position".to_string(),
                risk_score: 2000,
                expected_return: U256::ZERO,
                max_loss: U256::ZERO,
            },
        }
    }
    
    pub fn is_no_action(&self) -> bool {
        matches!(self.action_type, ActionType::NoAction)
    }
    
    pub fn requires_capital(&self) -> bool {
        matches!(self.action_type, ActionType::OpenLong | ActionType::OpenShort | ActionType::Rebalance { .. })
    }
}

impl Default for ActionMetadata {
    fn default() -> Self {
        Self {
            confidence: 5000,
            reasoning: "Default action".to_string(),
            risk_score: 5000,
            expected_return: U256::ZERO,
            max_loss: U256::ZERO,
        }
    }
}

/// Example implementation of a simple trend-following agent
#[derive(Debug)]
pub struct TrendFollowingAgent {
    hash: [u8; 32],
}

impl TrendFollowingAgent {
    pub fn new() -> Self {
        // Simple hash for demo - in practice this would be derived from agent code
        let hash = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ];
        Self { hash }
    }
}

impl Agent for TrendFollowingAgent {
    fn execute(
        &self,
        vault_state: &VaultState,
        market_state: &MarketState,
        params: &AgentParams,
    ) -> Result<AgentAction> {
        // Simple trend following logic
        if market_state.assets.is_empty() {
            return Ok(AgentAction::no_action());
        }
        
        let asset = &market_state.assets[0]; // Use first asset for demo
        
        // Check if we have enough available assets
        if vault_state.available_assets < params.max_position_size {
            return Ok(AgentAction::no_action());
        }
        
        // Simple trend detection based on volatility
        if asset.volatility > 500 { // High volatility indicates potential trend
            let position_size = params.max_position_size.min(vault_state.available_assets / U256::from(2));
            Ok(AgentAction::open_long(asset.asset, position_size, 7000))
        } else {
            Ok(AgentAction::no_action())
        }
    }
    
    fn validate_constraints(&self, _constraints: &crate::ConstraintSet) -> Result<()> {
        // Basic validation - in practice would check agent compatibility
        Ok(())
    }
    
    fn agent_hash(&self) -> [u8; 32] {
        self.hash
    }
    
    fn metadata(&self) -> AgentMetadata {
        AgentMetadata {
            name: "TrendFollowingAgent".to_string(),
            version: "1.0.0".to_string(),
            description: "Simple trend following strategy based on volatility".to_string(),
            author: "Execution Kernel Team".to_string(),
            strategy_type: StrategyType::Trend,
            supported_assets: vec![Address::ZERO], // Support all assets for demo
            min_vault_size: U256::from(100000000000000000u64), // 0.1 ETH minimum
            max_vault_size: U256::from_str("1000000000000000000000").unwrap(), // 1000 ETH maximum
        }
    }
}