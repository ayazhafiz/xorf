//! Implements Fuse16 filters.

use crate::{fuse_contains_impl, fuse_from_impl, Filter};
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Xor filter using 8-bit fingerprints in a [fuse graph]. Requires less space than an [`Xor16`].
///
/// A `Fuse16` filter uses <18.202 bits per entry of the set is it constructed from, and has a false
/// positive rate of <0.02%. As with other probabilistic filters, a higher number of entries decreases
/// the bits per entry but increases the false positive rate.
///
/// A `Fuse16` filter uses less space and is faster to construct than an [`Xor16`] filter, but
/// requires a large number of keys to be constructed. Experimentally, this number is somewhere
/// >100_000. For smaller key sets, prefer the [`Xor16`] filter.
///
/// A `Fuse16` is constructed from a set of 64-bit unsigned integers and is immutable.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, Fuse16};
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = Fuse16::from(&keys);
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 18.202, "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(*n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.02, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `Fuse16` filters can be enabled with the [`serde`] feature.
///
/// [fuse graph]: https://arxiv.org/abs/1907.04749
/// [`Xor16`]: crate::Xor16
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Fuse16 {
    seed: u64,
    segment_length: usize,
    fingerprints: Box<[u16]>,
}

impl Filter for Fuse16 {
    /// Returns `true` if the filter contains the specified key. Has a false positive rate of <0.02%.
    fn contains(&self, key: u64) -> bool {
        fuse_contains_impl!(key, self, fingerprint u16)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl From<&[u64]> for Fuse16 {
    fn from(keys: &[u64]) -> Self {
        fuse_from_impl!(keys fingerprint u16)
    }
}

impl From<&Vec<u64>> for Fuse16 {
    fn from(v: &Vec<u64>) -> Self {
        Self::from(v.as_slice())
    }
}

#[cfg(test)]
mod test {
    use crate::{Filter, Fuse16};

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse16::from(&keys);

        for key in keys {
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse16::from(&keys);
        let bpe = (filter.len() as f64) * 16.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 18.202, "Bits per entry is {}", bpe);
    }

    #[test]
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse16::from(&keys);

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(*n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.02, "False positive rate is {}", fp_rate);
    }
}
