use std::time::{Duration, Instant};
use crate::{
    Agent, AgentAction, AgentParams, VaultState, MarketState, 
    ConstraintSet, ConstraintEngine, Result, KernelError
};

/// Execution context for agent runs
#[derive(Debug)]
pub struct ExecutionContext {
    pub vault_id: u64,
    pub agent_hash: [u8; 32],
    pub nonce: u64,
    pub timestamp: u64,
    pub max_execution_time: Duration,
}

/// Resource usage tracking during execution
#[derive(Debug, Default)]
pub struct ResourceUsage {
    pub cycles_used: u64,
    pub memory_used: u64,
    pub execution_time: Duration,
    pub start_time: Option<Instant>,
}

/// Result of agent execution including action and metadata
#[derive(Debug)]
pub struct ExecutionResult {
    pub action: AgentAction,
    pub resource_usage: ResourceUsage,
    pub constraint_violations: Vec<crate::ConstraintViolation>,
    pub execution_metadata: ExecutionMetadata,
}

#[derive(Debug)]
pub struct ExecutionMetadata {
    pub success: bool,
    pub error_message: Option<String>,
    pub agent_version: String,
    pub kernel_version: String,
    pub deterministic_hash: [u8; 32],
}

/// Sandboxed execution environment for agents
pub struct ExecutionKernel {
    constraint_engine: ConstraintEngine,
    resource_tracker: ResourceTracker,
}

struct ResourceTracker {
    constraints: crate::OperationalConstraints,
    usage: ResourceUsage,
}

impl ExecutionKernel {
    pub fn new(constraints: ConstraintSet) -> Self {
        let operational_constraints = constraints.operational.clone();
        Self {
            constraint_engine: ConstraintEngine::new(constraints),
            resource_tracker: ResourceTracker::new(operational_constraints),
        }
    }
    
    /// Execute an agent with full constraint checking and resource tracking
    pub fn execute_agent<A: Agent>(
        &mut self,
        agent: &A,
        vault_state: &VaultState,
        market_state: &MarketState,
        params: &AgentParams,
        context: ExecutionContext,
    ) -> Result<ExecutionResult> {
        // Pre-execution validation
        self.validate_pre_execution(agent, vault_state, market_state, &context)?;
        
        // Start resource tracking
        self.resource_tracker.start_execution();
        
        // Execute agent within timeout
        let action_result = self.execute_with_timeout(agent, vault_state, market_state, params, &context);
        
        // Stop resource tracking
        self.resource_tracker.stop_execution();
        
        // Handle execution result
        match action_result {
            Ok(action) => {
                // Post-execution validation
                self.validate_post_execution(&action, vault_state, market_state)?;
                
                Ok(ExecutionResult {
                    action,
                    resource_usage: self.resource_tracker.get_usage(),
                    constraint_violations: self.constraint_engine.get_violations().to_vec(),
                    execution_metadata: ExecutionMetadata {
                        success: true,
                        error_message: None,
                        agent_version: agent.metadata().version,
                        kernel_version: "0.1.0".to_string(),
                        deterministic_hash: self.compute_execution_hash(&context),
                    },
                })
            }
            Err(error) => {
                Ok(ExecutionResult {
                    action: AgentAction::no_action(),
                    resource_usage: self.resource_tracker.get_usage(),
                    constraint_violations: self.constraint_engine.get_violations().to_vec(),
                    execution_metadata: ExecutionMetadata {
                        success: false,
                        error_message: Some(error.to_string()),
                        agent_version: agent.metadata().version,
                        kernel_version: "0.1.0".to_string(),
                        deterministic_hash: self.compute_execution_hash(&context),
                    },
                })
            }
        }
    }
    
    fn validate_pre_execution<A: Agent>(
        &mut self,
        agent: &A,
        vault_state: &VaultState,
        market_state: &MarketState,
        context: &ExecutionContext,
    ) -> Result<()> {
        // Validate agent hash matches context
        if agent.agent_hash() != context.agent_hash {
            return Err(KernelError::AgentExecutionFailed(
                "Agent hash mismatch".to_string()
            ));
        }
        
        // Validate vault state
        if vault_state.vault_id != context.vault_id {
            return Err(KernelError::InvalidVaultState(
                "Vault ID mismatch".to_string()
            ));
        }
        
        // Validate nonce
        if vault_state.nonce + 1 != context.nonce {
            return Err(KernelError::InvalidVaultState(
                format!("Invalid nonce: expected {}, got {}", vault_state.nonce + 1, context.nonce)
            ));
        }
        
        // Check market state freshness
        if market_state.is_stale(300) { // 5 minutes max age
            return Err(KernelError::InvalidMarketState(
                "Market data is stale".to_string()
            ));
        }
        
        // Validate agent against constraints
        agent.validate_constraints(self.constraint_engine.get_constraints())?;
        
        Ok(())
    }
    
    fn execute_with_timeout<A: Agent>(
        &mut self,
        agent: &A,
        vault_state: &VaultState,
        market_state: &MarketState,
        params: &AgentParams,
        context: &ExecutionContext,
    ) -> Result<AgentAction> {
        let start = Instant::now();
        
        // Check if execution would exceed timeout before starting
        if start.elapsed() > context.max_execution_time {
            return Err(KernelError::ResourceLimitExceeded(
                "Execution timeout before start".to_string()
            ));
        }
        
        // Execute agent (in practice this would be in zkVM)
        let action = agent.execute(vault_state, market_state, params)?;
        
        // Check execution time
        let execution_time = start.elapsed();
        if execution_time > context.max_execution_time {
            return Err(KernelError::ResourceLimitExceeded(
                format!("Execution timeout: {:?} > {:?}", execution_time, context.max_execution_time)
            ));
        }
        
        // Update resource usage
        self.resource_tracker.update_cycles(1000); // Placeholder cycle count
        self.resource_tracker.update_memory(1024); // Placeholder memory usage
        
        Ok(action)
    }
    
    fn validate_post_execution(
        &mut self,
        action: &AgentAction,
        vault_state: &VaultState,
        market_state: &MarketState,
    ) -> Result<()> {
        // Validate action against constraints
        self.constraint_engine.validate_action(action, vault_state, market_state)?;
        
        // Additional post-execution checks
        if action.requires_capital() && action.amount > vault_state.available_assets {
            return Err(KernelError::InvalidAction(
                "Insufficient available assets for action".to_string()
            ));
        }
        
        Ok(())
    }
    
    fn compute_execution_hash(&self, context: &ExecutionContext) -> [u8; 32] {
        // In practice, this would be a proper hash of execution context + state
        // For now, just use the agent hash
        context.agent_hash
    }
}

impl ResourceTracker {
    fn new(constraints: crate::OperationalConstraints) -> Self {
        Self {
            constraints,
            usage: ResourceUsage::default(),
        }
    }
    
    fn start_execution(&mut self) {
        self.usage.start_time = Some(Instant::now());
    }
    
    fn stop_execution(&mut self) {
        if let Some(start_time) = self.usage.start_time {
            self.usage.execution_time = start_time.elapsed();
        }
    }
    
    fn update_cycles(&mut self, cycles: u64) {
        self.usage.cycles_used += cycles;
    }
    
    fn update_memory(&mut self, memory: u64) {
        self.usage.memory_used = self.usage.memory_used.max(memory);
    }
    
    fn get_usage(&self) -> ResourceUsage {
        ResourceUsage {
            cycles_used: self.usage.cycles_used,
            memory_used: self.usage.memory_used,
            execution_time: self.usage.execution_time,
            start_time: None, // Don't copy start_time
        }
    }
    
    fn _check_limits(&self) -> Result<()> {
        if self.usage.cycles_used > self.constraints.max_compute_cycles {
            return Err(KernelError::ResourceLimitExceeded(
                "Compute cycle limit exceeded".to_string()
            ));
        }
        
        if self.usage.memory_used > self.constraints.max_memory_usage {
            return Err(KernelError::ResourceLimitExceeded(
                "Memory limit exceeded".to_string()
            ));
        }
        
        Ok(())
    }
}

impl ExecutionContext {
    pub fn new(vault_id: u64, agent_hash: [u8; 32], nonce: u64, timestamp: u64) -> Self {
        Self {
            vault_id,
            agent_hash,
            nonce,
            timestamp,
            max_execution_time: Duration::from_secs(30), // Default 30 second timeout
        }
    }
    
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.max_execution_time = timeout;
        self
    }
}