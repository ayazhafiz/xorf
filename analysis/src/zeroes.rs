// See analysis/plot_zeroes

#![allow(deprecated)] // Fuse filters are deprecated

extern crate core;
extern crate rand;
extern crate xorf;

use core::convert::TryFrom;
use rand::Rng;
use xorf::*;

const SIZE: usize = 1_000_000;

macro_rules! print_zeroes {
    ($filter:ident) => {{
        let mut keys: Vec<u64> = Vec::with_capacity(SIZE);

        for _ in 0..SIZE {
            let key: u64 = rand::thread_rng().gen();
            keys.push(key);
        }
        let filter = $filter::try_from(keys).unwrap();
        let fp = filter.fingerprints;
        let window_size = 2000;
        let mut zeroes: usize = 0;
        for (i, t) in fp.iter().enumerate() {
            if *t == 0 {
                zeroes += 1;
            }
            if i > window_size && fp[i - window_size] == 0 {
                zeroes -= 1;
            }
            if i > window_size && i % 333 == 0 {
                println!("{}", zeroes);
            }
        }
    }};
}

fn main() {
    let filter_str = std::env::args()
        .collect::<Vec<_>>()
        .pop()
        .expect("Expected filter argument");

    match filter_str.as_ref() {
        "BinaryFuse8" => print_zeroes!(BinaryFuse8),
        "BinaryFuse16" => print_zeroes!(BinaryFuse16),
        "Fuse8" => {
            print_zeroes!(Fuse8)
        }
        "Fuse16" => {
            print_zeroes!(Fuse16)
        }
        "Xor8" => print_zeroes!(Xor8),
        "Xor16" => print_zeroes!(Xor16),
        _ => panic!("Filter {} is invalid", filter_str),
    };
}
