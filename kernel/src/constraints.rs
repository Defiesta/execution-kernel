use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use crate::{VaultState, MarketState, AgentAction, Result, KernelError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstraintSet {
    pub financial: FinancialConstraints,
    pub operational: OperationalConstraints,
    pub safety: SafetyConstraints,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinancialConstraints {
    pub max_position_size: U256,     // Maximum position size in wei
    pub max_leverage: u64,           // Maximum leverage ratio (e.g., 300 = 3x)
    pub max_drawdown: u64,           // Maximum drawdown percentage (0-10000)
    pub max_loss_per_step: U256,     // Maximum loss per execution step
    pub asset_whitelist: Vec<Address>, // Allowed assets for trading
    pub min_vault_balance: U256,     // Minimum vault balance to maintain
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperationalConstraints {
    pub max_compute_cycles: u64,     // Maximum computation cycles
    pub max_memory_usage: u64,       // Maximum memory usage in bytes
    pub execution_timeout: u64,      // Execution timeout in seconds
    pub cooldown_period: u64,        // Minimum time between executions
    pub max_actions_per_hour: u32,   // Rate limiting
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SafetyConstraints {
    pub no_external_calls: bool,     // Prevent external contract calls
    pub no_dynamic_assets: bool,     // Prevent dynamic asset creation
    pub no_recursion: bool,          // Prevent recursive execution
    pub max_loop_iterations: u64,    // Maximum loop iterations
    pub deterministic_only: bool,    // Only allow deterministic operations
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstraintViolation {
    pub constraint_type: ConstraintType,
    pub description: String,
    pub severity: ViolationSeverity,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintType {
    Financial,
    Operational,
    Safety,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationSeverity {
    Critical,  // Execution must halt
    Warning,   // Log warning but continue
    Info,      // Informational only
}

pub struct ConstraintEngine {
    constraints: ConstraintSet,
    violations: Vec<ConstraintViolation>,
}

impl ConstraintEngine {
    pub fn new(constraints: ConstraintSet) -> Self {
        Self {
            constraints,
            violations: Vec::new(),
        }
    }
    
    /// Validate agent action against all constraints
    pub fn validate_action(
        &mut self,
        action: &AgentAction,
        vault_state: &VaultState,
        market_state: &MarketState,
    ) -> Result<()> {
        self.violations.clear();
        
        self.validate_financial_constraints(action, vault_state, market_state)?;
        self.validate_operational_constraints(action)?;
        self.validate_safety_constraints(action)?;
        
        // Check for critical violations
        let critical_violations: Vec<_> = self.violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Critical)
            .collect();
            
        if !critical_violations.is_empty() {
            let descriptions: Vec<_> = critical_violations
                .iter()
                .map(|v| v.description.as_str())
                .collect();
            return Err(KernelError::ConstraintViolation(descriptions.join("; ")));
        }
        
        Ok(())
    }
    
    fn validate_financial_constraints(
        &mut self,
        action: &AgentAction,
        vault_state: &VaultState,
        _market_state: &MarketState,
    ) -> Result<()> {
        // Check position size limit
        if action.amount > self.constraints.financial.max_position_size {
            self.violations.push(ConstraintViolation {
                constraint_type: ConstraintType::Financial,
                description: format!(
                    "Position size {} exceeds maximum {}", 
                    action.amount, 
                    self.constraints.financial.max_position_size
                ),
                severity: ViolationSeverity::Critical,
                suggested_action: "Reduce position size".to_string(),
            });
        }
        
        // Check asset whitelist
        if !self.constraints.financial.asset_whitelist.is_empty() 
            && !self.constraints.financial.asset_whitelist.contains(&action.asset) {
            self.violations.push(ConstraintViolation {
                constraint_type: ConstraintType::Financial,
                description: format!("Asset {:?} not in whitelist", action.asset),
                severity: ViolationSeverity::Critical,
                suggested_action: "Use whitelisted asset".to_string(),
            });
        }
        
        // Check minimum vault balance
        if action.requires_capital() {
            let remaining_balance = vault_state.available_assets.saturating_sub(action.amount);
            if remaining_balance < self.constraints.financial.min_vault_balance {
                self.violations.push(ConstraintViolation {
                    constraint_type: ConstraintType::Financial,
                    description: format!(
                        "Action would reduce vault balance below minimum {}", 
                        self.constraints.financial.min_vault_balance
                    ),
                    severity: ViolationSeverity::Critical,
                    suggested_action: "Reduce position size or add capital".to_string(),
                });
            }
        }
        
        Ok(())
    }
    
    fn validate_operational_constraints(&mut self, _action: &AgentAction) -> Result<()> {
        // These would be enforced during execution in the zkVM
        // For now, just placeholder validation
        Ok(())
    }
    
    fn validate_safety_constraints(&mut self, action: &AgentAction) -> Result<()> {
        // Check for safety violations
        if self.constraints.safety.no_dynamic_assets && action.asset == Address::ZERO {
            self.violations.push(ConstraintViolation {
                constraint_type: ConstraintType::Safety,
                description: "Dynamic asset creation not allowed".to_string(),
                severity: ViolationSeverity::Critical,
                suggested_action: "Use predefined asset address".to_string(),
            });
        }
        
        Ok(())
    }
    
    pub fn get_violations(&self) -> &[ConstraintViolation] {
        &self.violations
    }
    
    pub fn get_constraints(&self) -> &ConstraintSet {
        &self.constraints
    }
}

impl Default for ConstraintSet {
    fn default() -> Self {
        Self {
            financial: FinancialConstraints::default(),
            operational: OperationalConstraints::default(),
            safety: SafetyConstraints::default(),
        }
    }
}

impl Default for FinancialConstraints {
    fn default() -> Self {
        Self {
            max_position_size: U256::from(1000000000000000000u64), // 1 ETH
            max_leverage: 300, // 3x
            max_drawdown: 2000, // 20%
            max_loss_per_step: U256::from(100000000000000000u64), // 0.1 ETH
            asset_whitelist: Vec::new(),
            min_vault_balance: U256::from(10000000000000000u64), // 0.01 ETH
        }
    }
}

impl Default for OperationalConstraints {
    fn default() -> Self {
        Self {
            max_compute_cycles: 1_000_000,
            max_memory_usage: 10_000_000, // 10MB
            execution_timeout: 300, // 5 minutes
            cooldown_period: 60, // 1 minute
            max_actions_per_hour: 100,
        }
    }
}

impl Default for SafetyConstraints {
    fn default() -> Self {
        Self {
            no_external_calls: true,
            no_dynamic_assets: true,
            no_recursion: true,
            max_loop_iterations: 10_000,
            deterministic_only: true,
        }
    }
}