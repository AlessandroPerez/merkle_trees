use criterion::{BatchSize, Criterion, black_box};
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

    // Criterion will read .criterion.toml and use "quiet" output format
    let mut criterion = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_millis(100))
        .warm_up_time(Duration::from_millis(50))
        .without_plots();

    if algorithm == "sha256" {
        let mut group = criterion.benchmark_group(format!("sha256_{}", size));
        group.bench_function("hash", |b| {
            b.iter_batched(
                || input,
                |data| {
                    black_box(sha256::digest(black_box(data)));
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    } else {
        let mut group = criterion.benchmark_group(format!("blake3_{}", size));
        group.bench_function("hash", |b| {
            b.iter_batched(
                || input,
                |data| {
                    black_box(blake3::hash(black_box(data.as_bytes())));
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    }

    // Criterion doesn't expose the median directly through its API,
    // so we measure it using the same methodology
    if algorithm == "sha256" {
        measure_median_criterion_style(|| {
            black_box(sha256::digest(black_box(input)));
        })
    } else {
        measure_median_criterion_style(|| {
            black_box(blake3::hash(black_box(input.as_bytes())));
        })
    }
}

/// Replicates Criterion's measurement methodology:
/// - Warm-up: 50ms of iterations
/// - Measurement: 100 samples
/// - Statistic: Median
fn measure_median_criterion_style<F>(f: F) -> u128
where
    F: Fn(),
{
    let warmup_start = Instant::now();
    while warmup_start.elapsed() < Duration::from_millis(50) {
        f();
    }
    let mut times: Vec<u128> = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        f();
        times.push(start.elapsed().as_nanos());
    }
    times.sort_unstable();
    let mid = times.len() / 2;
    if times.len() % 2 == 0 {
        (times[mid - 1] + times[mid]) / 2
    } else {
        times[mid]
    }
}

pub fn hashing_time(test_data: &str, algorithm_name: &str) -> HashTiming {
    let sizes: Vec<usize> = (MIN_SIZE..=test_data.len()).collect();
    let entries: Vec<TimingEntry> = tqdm(sizes)
        .map(|size| {
            let median_ns = run_benchmark(test_data, algorithm_name, size);
            TimingEntry {
                size,
                duration: median_ns,
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
