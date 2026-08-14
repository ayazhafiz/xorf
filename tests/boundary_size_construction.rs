//! Binary Fuse construction at a segment-length boundary (n = 11,515).
//!
//! Run with: cargo test --test boundary_size_construction -- --nocapture

use xorf::{BinaryFuse16, BinaryFuse32, BinaryFuse8, DmaSerializable, Filter};

/// splitmix64, replicated from src/splitmix64.rs.
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// First 11,515 splitmix64 outputs from this state; fails every default-geometry seed.
const FIXTURE_STATE: u64 = 28909;
const FIXTURE_LEN: u64 = 11_515;

fn fixture_keys() -> Vec<u64> {
    let mut state = FIXTURE_STATE;
    (0..FIXTURE_LEN).map(|_| splitmix64(&mut state)).collect()
}

fn assert_distinct(keys: &[u64]) {
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    sorted.dedup();
    assert_eq!(sorted.len(), n, "fixture keys must be distinct");
}

/// Index of the winning seed in try_from's deterministic sequence (rng starts at 1).
fn winning_iteration(filter: &BinaryFuse8) -> Option<usize> {
    let mut descriptor = [0u8; 20];
    filter.dma_copy_descriptor_to(&mut descriptor);
    let winning = u64::from_le_bytes(descriptor[0..8].try_into().unwrap());
    let mut rng = 1u64;
    (0..1000).find(|_| splitmix64(&mut rng) == winning)
}

/// This set used to fail all 1000 seeds; it must construct via halved segment length (512).
#[test]
fn distinct_keys_at_boundary_size_construct() {
    let keys = fixture_keys();
    assert_eq!(keys.len(), 11_515);
    assert_distinct(&keys);

    let filter = BinaryFuse8::try_from(&keys)
        .expect("11,515 distinct keys must construct via the segment-length fallback");
    for key in &keys {
        assert!(filter.contains(key), "no false negatives");
    }

    let mut descriptor = [0u8; 20];
    filter.dma_copy_descriptor_to(&mut descriptor);
    let segment_length = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
    assert_eq!(
        segment_length, 512,
        "fixture fails every default-geometry seed; success must use the halved length"
    );
}

#[test]
fn construction_is_fingerprint_width_independent() {
    let keys = fixture_keys();
    assert!(BinaryFuse8::try_from(&keys).is_ok());
    assert!(BinaryFuse16::try_from(&keys).is_ok());
    assert!(BinaryFuse32::try_from(&keys).is_ok());
}

/// mix64(key + seed): shifting every key is a seed-sequence shift. The set itself is fine.
#[test]
fn shifted_key_space_constructs_so_the_seed_sequence_is_the_problem() {
    let keys = fixture_keys();
    for delta in 1u64..=8 {
        let shifted: Vec<u64> = keys.iter().map(|k| k.wrapping_add(delta)).collect();
        assert!(
            BinaryFuse8::try_from(&shifted).is_ok(),
            "delta {delta}: shifted copy failed"
        );
    }
}

/// Boundary and mid-band sizes should both construct in a few iterations.
#[test]
fn construction_succeeds_quickly_at_boundary_and_midband() {
    let stats = |n: u64, sets: u64| -> (f64, usize) {
        let mut total_failed = 0usize;
        let mut worst = 0usize;
        let mut rng = 0x0123_4567_89AB_CDEFu64;
        for _ in 0..sets {
            let keys: Vec<u64> = (0..n).map(|_| splitmix64(&mut rng)).collect();
            let filter = BinaryFuse8::try_from(&keys).expect("synthetic set exhausted 1000 seeds");
            let failed = winning_iteration(&filter)
                .expect("winning seed must be in the deterministic sequence");
            total_failed += failed;
            worst = worst.max(failed);
        }
        (total_failed as f64 / sets as f64, worst)
    };

    let (mean_boundary, worst_boundary) = stats(11_515, 100);
    let (mean_mid, worst_mid) = stats(20_000, 100);
    println!(
        "failed iterations before success: n=11515 mean={mean_boundary:.1} worst={worst_boundary}; \
         n=20000 mean={mean_mid:.1} worst={worst_mid}"
    );

    assert!(
        mean_boundary < 3.0,
        "boundary size should construct on the halved-length retry (mean {mean_boundary:.1})"
    );
    assert!(
        mean_mid < 3.0,
        "mid-band size should construct almost immediately (mean {mean_mid:.1})"
    );
}
