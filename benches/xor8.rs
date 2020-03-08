#[macro_use]
extern crate criterion;
extern crate rand;
extern crate xorf;

use criterion::{BenchmarkId, Criterion};
use rand::Rng;
use xorf::{Filter, Xor8};

const SAMPLE_SIZE: u32 = 500_000;

fn from(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor8");
    let group = group.sample_size(10);

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

    group.bench_with_input(BenchmarkId::new("from", SAMPLE_SIZE), &keys, |b, keys| {
        b.iter(|| Xor8::from(keys));
    });
}

fn contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xor8");

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
    let filter = Xor8::from(&keys);

    group.bench_function(BenchmarkId::new("contains", SAMPLE_SIZE), |b| {
        let key = rng.gen();
        b.iter(|| filter.contains(&key));
    });
}

criterion_group!(xor8, from, contains);
criterion_main!(xor8);
