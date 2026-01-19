use execution_kernel::{
    Agent, AgentParams, TrendFollowingAgent, VaultState, MarketState, AssetPrice,
    ConstraintSet, ExecutionKernel, ExecutionContext,
};
use alloy_primitives::{Address, U256};
use std::str::FromStr;
use std::time::Duration;

fn main() -> execution_kernel::Result<()> {
    println!("🚀 Execution Kernel Demo");
    
    // Create a sample agent
    let agent = TrendFollowingAgent::new();
    println!("Agent created: {}", agent.metadata().name);
    
    // Create vault state
    let vault_owner = Address::from([1u8; 20]);
    let initial_assets = U256::from(10000000000000000000u64); // 10 ETH
    let mut vault_state = VaultState::new(1, vault_owner, initial_assets);
    vault_state.nonce = 0;
    
    // Create market state with ETH price
    let mut market_state = MarketState::new(1640995200, 12345); // Timestamp and block number
    let eth_address = Address::from([0xe; 20]); // Mock ETH address
    market_state.add_asset(AssetPrice {
        asset: eth_address,
        price: U256::from_str("3200000000000000000000").unwrap(), // $3200 with 18 decimals
        decimals: 18,
        last_update: 1640995200,
        volume_24h: U256::from_str("1000000000000000000000").unwrap(),
        volatility: 750, // 7.5% volatility
    });
    
    // Create agent parameters
    let params = AgentParams {
        max_position_size: U256::from(1000000000000000000u64), // 1 ETH
        risk_tolerance: 7000, // 70%
        ..Default::default()
    };
    
    // Create constraint set
    let constraints = ConstraintSet::default();
    
    // Create execution kernel
    let mut kernel = ExecutionKernel::new(constraints);
    
    // Create execution context
    let context = ExecutionContext::new(
        vault_state.vault_id,
        agent.agent_hash(),
        vault_state.nonce + 1,
        market_state.timestamp,
    ).with_timeout(Duration::from_secs(10));
    
    // Execute the agent
    println!("🎯 Executing agent...");
    let result = kernel.execute_agent(&agent, &vault_state, &market_state, &params, context)?;
    
    // Display results
    println!("✅ Execution completed!");
    println!("Success: {}", result.execution_metadata.success);
    println!("Action type: {:?}", result.action.action_type);
    println!("Asset: {:?}", result.action.asset);
    println!("Amount: {} wei", result.action.amount);
    println!("Confidence: {}%", result.action.metadata.confidence as f64 / 100.0);
    println!("Execution time: {:?}", result.resource_usage.execution_time);
    println!("Constraint violations: {}", result.constraint_violations.len());
    
    if !result.constraint_violations.is_empty() {
        println!("⚠️  Constraint violations:");
        for violation in result.constraint_violations {
            println!("  - {:?}: {}", violation.constraint_type, violation.description);
        }
    }
    
    Ok(())
}