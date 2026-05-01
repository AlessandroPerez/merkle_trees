mod benchmarks;
mod hasher;
mod merkle_ops;
mod utils;

use crate::merkle_ops::run_merkle_comparison;
use crate::utils::{RUNS, TOTAL_LEAVES, find_leaf_size, random_leaves};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let leaf_size = find_leaf_size();
    let leaves_owned: Vec<String> = random_leaves(TOTAL_LEAVES, leaf_size);
    let leaf_values: Vec<&str> = leaves_owned.iter().map(|s| s.as_str()).collect();

    let (blake_duration, sha_duration) = run_merkle_comparison(&leaf_values)?;

    println!(
        "\n\nAverage time across {} runs of Blake3 MT: {:?}",
        RUNS, blake_duration
    );
    println!(
        "Average time across {} runs of SHA256 MT: {:?}",
        RUNS, sha_duration
    );

    Ok(())
}
