#[cfg(feature = "risc0")]
fn main() {
    use risc0_zkvm::guest::env;
    
    let input_bytes: Vec<u8> = env::read();
    
    match kernel_guest::kernel_main(&input_bytes) {
        Ok(journal_bytes) => {
            env::commit(&journal_bytes);
        }
        Err(_) => {
            panic!("Kernel execution failed");
        }
    }
}

#[cfg(not(feature = "risc0"))]
fn main() {
    println!("This binary is intended to run inside RISC Zero zkVM");
    std::process::exit(1);
}