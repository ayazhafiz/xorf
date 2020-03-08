#[macro_use]
extern crate criterion;
extern crate core;
extern crate rand;
extern crate xorf;

use core::convert::TryFrom;
use criterion::{BenchmarkId, Criterion};
use rand::Rng;
use xorf::{Filter, Fuse16};

const SAMPLE_SIZE: u32 = 500_000;

fn from(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fuse16");
    let group = group.sample_size(10);

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

    group.bench_with_input(BenchmarkId::new("from", SAMPLE_SIZE), &keys, |b, keys| {
        b.iter(|| Fuse16::try_from(keys).unwrap());
    });
}

fn contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fuse16");

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
    let filter = Fuse16::try_from(&keys).unwrap();

    group.bench_function(BenchmarkId::new("contains", SAMPLE_SIZE), |b| {
        let key = rng.gen();
        b.iter(|| filter.contains(&key));
    });
}

criterion_group!(fuse16, from, contains);
criterion_main!(fuse16);
