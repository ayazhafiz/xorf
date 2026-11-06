//! Borrowed XOR readers preserve owning-reader behavior for pooled and owned fingerprints.

use xorf::{Filter, Xor8, Xor8Ref, Xor16, Xor16Ref, Xor32, Xor32Ref};

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
            let from_owned = $borrowed::from(&owned);
            assert!(std::ptr::eq(
                from_owned.fingerprints,
                owned.fingerprints.as_ref()
            ));
            // Reusing the array by value also exercises the Copy API.
            let readers = [borrowed, from_owned];
            for reader in readers {
                assert_eq!(reader.len(), owned.len());
            }
            for key in &keys {
                for reader in readers {
                    assert!(reader.contains(key));
                }
            }
            for key in (0..4096_u64)
                .map(|key| key.wrapping_mul(0xd6e8_feb8_6659_fd93))
                .chain([u64::MAX])
            {
                for reader in readers {
                    assert_eq!(reader.contains(&key), owned.contains(&key));
                }
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

#[test]
fn xor32_borrows_pooled_fingerprints() {
    check_borrowed!(Xor32, Xor32Ref);
}
