use crate::hasher::Blake3Algorithm;
use rand::{Rng, SeedableRng};
use rs_merkle::{Hasher, MerkleProof, MerkleTree, algorithms::Sha256};
use std::time::{Duration, Instant};
mod hasher;

// Parameters to tweak
const RUNS: u32 = 10;
const TOTAL_LEAVES: usize = 100_000;
const SIZE_OF_LEAVES: usize = 1024;

fn random_leaves(n: usize, size: usize) -> Vec<String> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    (0..n)
        .map(|_| {
            (0..size)
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect()
        })
        .collect()
}

fn merkle_tree<H: Hasher<Hash = [u8; 32]>>(
    leaf_values: &Vec<&str>,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();

    let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| H::hash(x.as_bytes())).collect();

    let merkle_tree = MerkleTree::<H>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove")?;
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root")?;

    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<H>::try_from(proof_bytes)?;

    assert!(proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));

    Ok(Instant::now().duration_since(start))
}

fn average_merkle_time<H: Hasher<Hash = [u8; 32]>>(
    leaf_values: &Vec<&str>,
    n: u32,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let total: Duration = (0..n)
        .map(|_| merkle_tree::<H>(leaf_values))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum();

    Ok(total / n)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Creation of random laaves
    let leaves_owned: Vec<String> = random_leaves(TOTAL_LEAVES, SIZE_OF_LEAVES);
    let leaf_values: Vec<&str> = leaves_owned.iter().map(|s| s.as_str()).collect();

    // Testing Blake
    let blake_duration = average_merkle_time::<Blake3Algorithm>(&leaf_values, RUNS)?;
    println!(
        "Average time across {} runs of Blake3 MT: {:?}",
        RUNS, blake_duration
    );

    // Testing Sha256
    let sha_duration = average_merkle_time::<Sha256>(&leaf_values, RUNS)?;
    println!(
        "Average time across {} runs of SHA256 MT: {:?}",
        RUNS, sha_duration
    );
    Ok(())
}
