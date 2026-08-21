//! Benchmarks for `BinaryFuse32` construction and lookups.

use core::convert::TryFrom;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngExt;
use xorf::{BinaryFuse32, Filter};

const SAMPLE_SIZE: u32 = 500_000;

fn from(c: &mut Criterion) {
    let mut group = c.benchmark_group("BinaryFuse32");
    group.sample_size(10);

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();

    group.bench_with_input(BenchmarkId::new("from", SAMPLE_SIZE), &keys, |b, keys| {
        b.iter(|| BinaryFuse32::try_from(keys).unwrap());
    });
}

fn contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("BinaryFuse32");

    let mut rng = rand::rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.random()).collect();
    let filter = BinaryFuse32::try_from(&keys).unwrap();

    group.bench_function(BenchmarkId::new("contains", SAMPLE_SIZE), |b| {
        let key = rng.random();
        b.iter(|| filter.contains(&key));
    });
}

criterion_group!(bfuse32, from, contains);
criterion_main!(bfuse32);
