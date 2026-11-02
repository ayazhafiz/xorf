//! Borrowed XOR readers preserve owning-reader behavior on pooled fingerprint slices.

use xorf::{Filter, Xor8, Xor8Ref, Xor16, Xor16Ref};

macro_rules! check_borrowed {
    ($owned:ident, $borrowed:ident) => {
        for count in [0, 1, 128] {
            let keys: Vec<_> = (0..count)
                .map(|key: u64| key.wrapping_mul(0x9e37_79b9_7f4a_7c15))
                .collect();
            let owned = $owned::from(&keys);
            // Borrow a subslice of a larger allocation, as a pooled reader does.
            let mut pool = vec![0; 7];
            pool.extend_from_slice(&owned.fingerprints);
            pool.extend_from_slice(&[0; 9]);
            let borrowed = $borrowed {
                seed: owned.seed,
                block_length: owned.block_length,
                fingerprints: &pool[7..7 + owned.fingerprints.len()],
            };
            assert_eq!(borrowed.len(), owned.len());
            for key in &keys {
                assert!(borrowed.contains(key));
            }
            for key in (0..4096_u64)
                .map(|key| key.wrapping_mul(0xd6e8_feb8_6659_fd93))
                .chain([u64::MAX])
            {
                assert_eq!(borrowed.contains(&key), owned.contains(&key));
            }
        }
    };
}

#[test]
fn xor8_borrows_pooled_fingerprints() {
    check_borrowed!(Xor8, Xor8Ref);
}

#[test]
fn xor16_borrows_pooled_fingerprints() {
    check_borrowed!(Xor16, Xor16Ref);
}
