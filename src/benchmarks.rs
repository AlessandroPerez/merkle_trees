use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tqdm::tqdm;

use crate::utils::MIN_SIZE;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimingEntry {
    pub size: usize,
    pub duration: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashTiming {
    pub function: String,
    pub entries: Vec<TimingEntry>,
}

pub fn run_benchmark(test_data: &str, algorithm: &str, size: usize) -> u128 {
    let input = &test_data[..size];
    if algorithm == "sha256" {
        let warmup_start = Instant::now();
        while warmup_start.elapsed() < Duration::from_millis(100) {
            let _ = sha256::digest(input);
        }
        let mut best_time: u128 = u128::MAX;
        for _ in 0..500 {
            let start = Instant::now();
            let _ = sha256::digest(input);
            let elapsed = start.elapsed().as_nanos();
            if elapsed < best_time {
                best_time = elapsed;
            }
        }
        best_time
    } else {
        let warmup_start = Instant::now();
        while warmup_start.elapsed() < Duration::from_millis(100) {
            let _ = blake3::hash(input.as_bytes());
        }
        let mut best_time: u128 = u128::MAX;
        for _ in 0..500 {
            let start = Instant::now();
            let _ = blake3::hash(input.as_bytes());
            let elapsed = start.elapsed().as_nanos();
            if elapsed < best_time {
                best_time = elapsed;
            }
        }
        best_time
    }
}

pub fn hashing_time(test_data: &str, algorithm_name: &str) -> HashTiming {
    let sizes: Vec<usize> = (MIN_SIZE..=test_data.len()).collect();
    let entries: Vec<TimingEntry> = tqdm(sizes)
        .map(|size| {
            let best_ns = run_benchmark(test_data, algorithm_name, size);
            TimingEntry {
                size,
                duration: best_ns,
            }
        })
        .collect();
    HashTiming {
        function: algorithm_name.to_string(),
        entries,
    }
}

pub fn find_switch_points(sha_timings: Vec<Duration>, blake_timings: Vec<Duration>) -> Vec<usize> {
    sha_timings
        .iter()
        .zip(blake_timings.iter())
        .enumerate()
        .filter_map(|(i, (sha, blake))| (blake > sha).then_some(i + 257))
        .collect()
}
