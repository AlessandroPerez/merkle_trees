use crate::hasher::Blake3Algorithm;
use rs_merkle::{Hasher, MerkleProof, MerkleTree, algorithms::Sha256};
use std::time::{Duration, Instant};
use tqdm::tqdm;

use crate::utils::RUNS;

pub fn merkle_tree<H: Hasher<Hash = [u8; 32]>>(
    leaf_values: &Vec<&str>,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();

    let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| H::hash(x.as_bytes())).collect();

    let merkle_tree = MerkleTree::<H>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove")?;
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root")?;

    let proof_bytes = merkle_proof.to_bytes();
    let proof = MerkleProof::<H>::try_from(proof_bytes)?;

    assert!(proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));

    Ok(Instant::now().duration_since(start))
}

pub fn average_merkle_time<H: Hasher<Hash = [u8; 32]>>(
    leaf_values: &Vec<&str>,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let total: Duration = tqdm(0..RUNS)
        .map(|_| merkle_tree::<H>(leaf_values))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum();

    Ok(total / RUNS)
}

pub fn run_merkle_comparison(leaf_values: &Vec<&str>) -> Result<(Duration, Duration), Box<dyn std::error::Error>> {
    println!("Testing MT built using Blake3");
    let blake_duration = average_merkle_time::<Blake3Algorithm>(leaf_values)?;

    println!("Testing MT built using Sha256");
    let sha_duration = average_merkle_time::<Sha256>(leaf_values)?;

    Ok((blake_duration, sha_duration))
}
