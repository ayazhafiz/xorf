//! Implements Xor8 filters as described in [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters].
//!
//! [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters]: https://arxiv.org/abs/1912.08258

use crate::{xor_contains_impl, xor_from_impl, Filter};
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Xor filter using 8-bit fingerprints.
///
/// An `Xor8` filter uses <10 bits per entry of the set is it constructed from, and has a false
/// positive rate of <0.4%. As with other probabilistic filters, a higher number of entries decreases
/// the bits per entry but increases the false positive rate.
///
/// An `Xor8` is constructed from a set of 64-bit unsigned integers and is immutable.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, Xor8};
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = Xor8::from(&keys);
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(&key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 10., "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.406, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `Xor8` filters can be enabled with the [`serde`] feature.
///
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Xor8 {
    /// The seed for the filter
    pub seed: u64,
    /// The number of blocks in the filter
    pub block_length: usize,
    /// The fingerprints for the filter
    pub fingerprints: Box<[u8]>,
}

impl Filter<u64> for Xor8 {
    /// Returns `true` if the filter contains the specified key. Has a false positive rate of <0.4%.
    fn contains(&self, key: &u64) -> bool {
        xor_contains_impl!(*key, self, fingerprint u8)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl From<&[u64]> for Xor8 {
    fn from(keys: &[u64]) -> Self {
        xor_from_impl!(keys fingerprint u8)
    }
}

impl From<&Vec<u64>> for Xor8 {
    fn from(v: &Vec<u64>) -> Self {
        Self::from(v.as_slice())
    }
}

impl From<Vec<u64>> for Xor8 {
    fn from(v: Vec<u64>) -> Self {
        Self::from(v.as_slice())
    }
}

#[cfg(test)]
mod test {
    use crate::{Filter, Xor8};

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8::from(&keys);

        for key in keys {
            assert!(filter.contains(&key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8::from(&keys);
        let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 10., "Bits per entry is {}", bpe);
    }

    #[test]
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8::from(&keys);

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.406, "False positive rate is {}", fp_rate);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(
        expected = "Xor filters must be constructed from a collection containing all distinct keys."
    )]
    fn test_debug_assert_duplicates() {
        let _ = Xor8::from(vec![1, 2, 1]);
    }
}
