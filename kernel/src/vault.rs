use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultState {
    pub vault_id: u64,
    pub owner: Address,
    pub total_assets: U256,
    pub available_assets: U256,
    pub locked_assets: U256,
    pub current_positions: Vec<Position>,
    pub performance_metrics: PerformanceMetrics,
    pub last_update_timestamp: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Position {
    pub asset: Address,
    pub size: U256,
    pub entry_price: U256,
    pub position_type: PositionType,
    pub timestamp: u64,
    pub unrealized_pnl: I256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PositionType {
    Long,
    Short,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceMetrics {
    pub total_return: I256,        // Total return in wei
    pub max_drawdown: u64,         // Max drawdown percentage (0-10000)
    pub sharpe_ratio: u64,         // Sharpe ratio * 10000
    pub win_rate: u64,             // Win rate percentage (0-10000)
    pub total_trades: u64,
    pub last_trade_timestamp: u64,
}

// Signed 256-bit integer for PnL calculations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct I256 {
    pub value: U256,
    pub is_negative: bool,
}

impl VaultState {
    pub fn new(vault_id: u64, owner: Address, initial_assets: U256) -> Self {
        Self {
            vault_id,
            owner,
            total_assets: initial_assets,
            available_assets: initial_assets,
            locked_assets: U256::ZERO,
            current_positions: Vec::new(),
            performance_metrics: PerformanceMetrics::default(),
            last_update_timestamp: 0,
            nonce: 0,
        }
    }
    
    pub fn calculate_total_value(&self, market_state: &crate::MarketState) -> U256 {
        let mut total_value = self.available_assets;
        
        for position in &self.current_positions {
            if let Some(asset_price) = market_state.get_asset_price(&position.asset) {
                let position_value = position.size * asset_price.price / U256::from(10u64.pow(asset_price.decimals as u32));
                total_value += position_value;
            }
        }
        
        total_value
    }
    
    pub fn get_position(&self, asset: &Address) -> Option<&Position> {
        self.current_positions.iter().find(|p| p.asset == *asset)
    }
    
    pub fn add_position(&mut self, position: Position) {
        let position_size = position.size;
        if let Some(existing) = self.current_positions.iter_mut().find(|p| p.asset == position.asset) {
            *existing = position;
        } else {
            self.current_positions.push(position);
        }
        self.locked_assets += position_size;
        self.available_assets = self.available_assets.saturating_sub(position_size);
    }
    
    pub fn remove_position(&mut self, asset: &Address) -> Option<Position> {
        if let Some(index) = self.current_positions.iter().position(|p| p.asset == *asset) {
            let position = self.current_positions.remove(index);
            self.locked_assets = self.locked_assets.saturating_sub(position.size);
            self.available_assets += position.size;
            Some(position)
        } else {
            None
        }
    }
    
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            total_return: I256 { value: U256::ZERO, is_negative: false },
            max_drawdown: 0,
            sharpe_ratio: 0,
            win_rate: 0,
            total_trades: 0,
            last_trade_timestamp: 0,
        }
    }
}

impl I256 {
    pub fn new(value: U256, is_negative: bool) -> Self {
        Self { value, is_negative }
    }
    
    pub fn zero() -> Self {
        Self { value: U256::ZERO, is_negative: false }
    }
    
    pub fn is_positive(&self) -> bool {
        !self.is_negative && self.value > U256::ZERO
    }
}