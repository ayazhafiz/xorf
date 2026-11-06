//! Binary Fuse construction from keys that contain repeats.

use xorf::{BinaryFuse8, BinaryFuse16, BinaryFuse32, Filter, splitmix64};

macro_rules! repeated_keys_tests {
    ($($name:ident: $filter:ident),*) => {$(
        #[test]
        fn $name() {
            for repeats in [1, 10, 20, 100] {
                let mut state = 1;
                let mut keys: Vec<u64> = (0..100_000).map(|_| splitmix64(&mut state)).collect();
                keys.extend_from_within(..repeats);

                let filter = $filter::try_from(&keys)
                    .unwrap_or_else(|e| panic!("{repeats} repeats: {e}"));
                assert!(keys.iter().all(|key| filter.contains(key)), "{repeats} repeats");
            }
        }
    )*};
}

repeated_keys_tests!(
    binary_fuse8_builds_from_repeated_keys: BinaryFuse8,
    binary_fuse16_builds_from_repeated_keys: BinaryFuse16,
    binary_fuse32_builds_from_repeated_keys: BinaryFuse32
);
