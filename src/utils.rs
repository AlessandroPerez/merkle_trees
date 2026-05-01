use rand::{Rng, SeedableRng};
use serde_json;
use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use crate::benchmarks::{HashTiming, find_switch_points, hashing_time};

// Parameters to tweak
pub const RUNS: u32 = 10;
pub const TOTAL_LEAVES: usize = 100_000;
pub const MIN_SIZE: usize = 256;
pub const MAX_SIZE: usize = 10_000;

pub fn random_leaves(n: usize, size: usize) -> Vec<String> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    (0..n)
        .map(|_| {
            (0..size)
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect()
        })
        .collect()
}

pub fn generate_test_data() -> String {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    (0..MAX_SIZE)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

pub fn save_results(sha_timings: &HashTiming, blake_timings: &HashTiming) {
    let results = serde_json::json!({
        "sha256": sha_timings,
        "blake3": blake_timings
    });

    let file = File::create("data.json").expect("Creation failed.");
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &results).expect("Failed to write JSON to file");
}

pub fn find_leaf_size() -> usize {
    let string_to_test = generate_test_data();

    println!("Running Criterion benchmarks for SHA256...");
    let sha_timings = hashing_time(&string_to_test, "sha256");

    println!("Running Criterion benchmarks for Blake3...");
    let blake_timings = hashing_time(&string_to_test, "blake3");

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

    save_results(&sha_timings, &blake_timings);

    let switch_points = find_switch_points(sha_durations, blake_durations);

    if let Some(&last_sha_faster) = switch_points.last() {
        let switch_point = last_sha_faster + 1;
        println!(
            "SHA256 is faster up to length {}, Blake3 becomes faster at length {}\n\n",
            last_sha_faster, switch_point
        );
        switch_point
    } else {
        println!("Blake3 is faster at all tested lengths (no switch point found)\n\n");
        1024 * 4
    }
}
