//! Benchmarks for `Xor16` construction and lookups.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngExt;
use xorf::{Filter, Xor16};

const SAMPLE_SIZE: u32 = 500_000;

fn from(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor16");
    group.sample_size(10);

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();

    group.bench_with_input(BenchmarkId::new("from", SAMPLE_SIZE), &keys, |b, keys| {
        b.iter(|| Xor16::from(keys));
    });
}

fn contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor16");

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();
    let filter = Xor16::from(&keys);

    group.bench_function(BenchmarkId::new("contains", SAMPLE_SIZE), |b| {
        let key = rng.random();
        b.iter(|| filter.contains(&key));
    });
}

criterion_group!(xor16, from, contains);
criterion_main!(xor16);
