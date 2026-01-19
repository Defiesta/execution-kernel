use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketState {
    pub timestamp: u64,
    pub block_number: u64,
    pub assets: Vec<AssetPrice>,
    pub gas_price: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetPrice {
    pub asset: Address,
    pub price: U256,
    pub decimals: u8,
    pub last_update: u64,
    pub volume_24h: U256,
    pub volatility: u64, // Volatility percentage (0-10000 for 0.00%-100.00%)
}

impl MarketState {
    pub fn new(timestamp: u64, block_number: u64) -> Self {
        Self {
            timestamp,
            block_number,
            assets: Vec::new(),
            gas_price: U256::ZERO,
        }
    }
    
    pub fn add_asset(&mut self, asset_price: AssetPrice) {
        if let Some(existing) = self.assets.iter_mut().find(|a| a.asset == asset_price.asset) {
            *existing = asset_price;
        } else {
            self.assets.push(asset_price);
        }
    }
    
    pub fn get_asset_price(&self, asset: &Address) -> Option<&AssetPrice> {
        self.assets.iter().find(|a| a.asset == *asset)
    }
    
    pub fn is_stale(&self, max_age_seconds: u64) -> bool {
        self.assets.iter().any(|asset| {
            self.timestamp.saturating_sub(asset.last_update) > max_age_seconds
        })
    }
}