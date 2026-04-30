use crate::hasher::Blake3Algorithm;
use rand::{Rng, SeedableRng};
use rs_merkle::{Hasher, MerkleProof, MerkleTree, algorithms::Sha256};
use std::time::{Duration, Instant};
mod hasher;
use blake3::hash;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use std::fs::File;
use std::io::BufWriter;
use tqdm::tqdm;

// Parameters to tweak
const RUNS: u32 = 10;
const TOTAL_LEAVES: usize = 100_000;

#[derive(Debug)]
enum HashAlgorithms {
    Sha256,
    Blake3,
}

#[derive(Serialize, Deserialize)]
struct TimingEntry {
    size: usize,
    duration: u128,
}

#[derive(Serialize, Deserialize)]
struct HashTiming {
    function: String,
    entries: Vec<TimingEntry>,
}

impl HashAlgorithms {
    fn hash(&self, input: &str) -> Duration {
        match self {
            HashAlgorithms::Sha256 => hash_sha256(input),
            HashAlgorithms::Blake3 => hash_blake3(input),
        }
    }
}

fn hashing_time(string_to_test: &str, algorithm: HashAlgorithms) -> HashTiming {
    let entries: Vec<TimingEntry> = tqdm(256..string_to_test.len())
        .map(|x| TimingEntry {
            size: x,
            duration: algorithm.hash(&string_to_test[..=x]).as_nanos(),
        })
        .collect();

    HashTiming {
        function: format!("{:?}", algorithm),
        entries,
    }
}

fn hash_sha256(test_string: &str) -> Duration {
    let start = Instant::now();
    digest(test_string);
    Instant::now().duration_since(start)
}

fn hash_blake3(test_string: &str) -> Duration {
    let start = Instant::now();
    hash(test_string.as_bytes());
    Instant::now().duration_since(start)
}

fn find_switch_point(sha_timings: Vec<Duration>, blake_timings: Vec<Duration>) -> Option<usize> {
    sha_timings
        .iter()
        .zip(blake_timings.iter())
        .enumerate()
        .find_map(|(i, (sha, blake))| (sha > blake).then_some(i + 257))
}

fn find_leaf_size() -> usize {
    let size = 100_000;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let random_string: String = (0..size)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    let string_to_test: &str = random_string.as_str();

    println!("Hashing with sha256 different sizes of strings:");
    let sha_timings = hashing_time(string_to_test, HashAlgorithms::Sha256);

    println!("Hashing with blake3 different sizes of strings:");
    let blake_timings = hashing_time(string_to_test, HashAlgorithms::Blake3);

    let sha_durations: Vec<Duration> = sha_timings
        .entries
        .iter()
        .map(|timing| Duration::from_nanos(timing.duration as u64))
        .collect();
    let blake_durations: Vec<Duration> = blake_timings
        .entries
        .iter()
        .map(|timing| Duration::from_nanos(timing.duration as u64))
        .collect();

    let results = json!({
        "sha256": sha_timings,
        "blake3": blake_timings
    });

    let file = File::create("data.json").expect("Creation failed.");
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &results).expect("Failed to write JSON to file");

    match find_switch_point(sha_durations, blake_durations) {
        Some(point) => {
            println!("The switch point is at length {}\n\n", point);
            point
        }
        None => {
            println!("No switch point found Blake3 is always faster\n\n");
            0
        }
    }
}

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
    let total: Duration = tqdm(0..n)
        .map(|_| merkle_tree::<H>(leaf_values))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum();

    Ok(total / n)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let leaf_size = find_leaf_size();
    // Creation of random laaves
    let leaves_owned: Vec<String> = random_leaves(TOTAL_LEAVES, leaf_size);
    let leaf_values: Vec<&str> = leaves_owned.iter().map(|s| s.as_str()).collect();

    // Testing Blake
    println!("Testing MT built using Blake3");
    let blake_duration = average_merkle_time::<Blake3Algorithm>(&leaf_values, RUNS)?;

    // Testing Sha256
    println!("Testing MT built using Sha256");
    let sha_duration = average_merkle_time::<Sha256>(&leaf_values, RUNS)?;

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
