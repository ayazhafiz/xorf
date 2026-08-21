//! Benchmarks for `Xor8` construction and lookups.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngExt;
use xorf::{Filter, Xor8};

const SAMPLE_SIZE: u32 = 500_000;

fn from(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor8");
    group.sample_size(10);

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();

    group.bench_with_input(BenchmarkId::new("from", SAMPLE_SIZE), &keys, |b, keys| {
        b.iter(|| Xor8::from(keys));
    });
}

fn contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor8");

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();
    let filter = Xor8::from(&keys);

    group.bench_function(BenchmarkId::new("contains", SAMPLE_SIZE), |b| {
        let key = rng.random();
        b.iter(|| filter.contains(&key));
    });
}

criterion_group!(xor8, from, contains);
criterion_main!(xor8);
