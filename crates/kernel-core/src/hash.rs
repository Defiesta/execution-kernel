use sha2::{Sha256, Digest};

pub fn compute_input_commitment(input_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input_bytes);
    hasher.finalize().into()
}

pub fn compute_action_commitment(agent_output_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(agent_output_bytes);
    hasher.finalize().into()
}