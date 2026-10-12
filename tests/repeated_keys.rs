//! Binary Fuse construction from keys that contain repeats, and from keys that do not.

use std::borrow::Borrow;

use xorf::{BinaryFuse8, BinaryFuse16, BinaryFuse32, DmaSerializable, splitmix64};

const DESCRIPTOR: u64 = 17_304_306_350_656_170_544;

fn distinct_keys(n: usize) -> Vec<u64> {
    let mut state = 1;
    (0..n).map(|_| splitmix64(&mut state)).collect()
}

/// FNV-1a.
fn digest(bytes: impl IntoIterator<Item = impl Borrow<u8>>) -> u64 {
    bytes.into_iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b.borrow())).wrapping_mul(0x0100_0000_01b3)
    })
}

fn descriptor_digest<F: DmaSerializable>(filter: &F) -> u64 {
    let mut descriptor = vec![0u8; F::DESCRIPTOR_LEN];
    filter.dma_copy_descriptor_to(&mut descriptor);
    digest(descriptor)
}

/// The digests below were taken from the build before repeated keys were deduplicated, so they
/// pin that filters built from distinct keys did not change. The descriptor holds the seed, so
/// it also pins how many tries the build needed.
#[test]
fn distinct_keys_build_the_same_descriptor_as_before() {
    let keys = distinct_keys(100_000);
    assert_eq!(
        descriptor_digest(&BinaryFuse8::try_from(&keys).unwrap()),
        DESCRIPTOR
    );
    assert_eq!(
        descriptor_digest(&BinaryFuse16::try_from(&keys).unwrap()),
        DESCRIPTOR
    );
    assert_eq!(
        descriptor_digest(&BinaryFuse32::try_from(&keys).unwrap()),
        DESCRIPTOR
    );
}

/// Slots no key reaches are random with `uniform-random`, so the fingerprints are only
/// reproducible without it.
#[cfg(not(feature = "uniform-random"))]
#[test]
fn distinct_keys_build_the_same_fingerprints_as_before() {
    let keys = distinct_keys(100_000);
    assert_eq!(
        digest(BinaryFuse8::try_from(&keys).unwrap().dma_fingerprints()),
        5650442008549269618
    );
    assert_eq!(
        digest(BinaryFuse16::try_from(&keys).unwrap().dma_fingerprints()),
        13689399904158647186
    );
    assert_eq!(
        digest(BinaryFuse32::try_from(&keys).unwrap().dma_fingerprints()),
        4101054454483856231
    );
}

/// Release only: with repeats the debug build panics on purpose.
#[cfg(not(debug_assertions))]
mod repeats {
    use super::*;
    use std::time::{Duration, Instant};

    use xorf::Filter;

    macro_rules! repeated_keys_tests {
        ($($name:ident: $filter:ident),*) => {$(
            #[test]
            fn $name() {
                for repeats in [10, 20, 100] {
                    let mut keys = distinct_keys(100_000);
                    keys.extend_from_within(..repeats);

                    let start = Instant::now();
                    let filter = $filter::try_from(&keys)
                        .unwrap_or_else(|e| panic!("{repeats} repeats: {e}"));
                    let elapsed = start.elapsed();

                    assert!(keys.iter().all(|key| filter.contains(key)), "{repeats} repeats");
                    if repeats == 100 {
                        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
                    }
                }
            }
        )*};
    }

    repeated_keys_tests!(
        binary_fuse8_builds_from_repeated_keys: BinaryFuse8,
        binary_fuse16_builds_from_repeated_keys: BinaryFuse16,
        binary_fuse32_builds_from_repeated_keys: BinaryFuse32
    );
}
