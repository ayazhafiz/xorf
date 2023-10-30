//! Implements Xor16 filters as described in [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters].
//!
//! [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters]: https://arxiv.org/abs/1912.08258

use crate::{xor_contains_impl, xor_from_impl, Filter};
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

/// Xor filter using 16-bit fingerprints.
///
/// An `Xor16` filter uses <20 bits per entry of the set is it constructed from, and has a false
/// positive rate of <0.002%. As with other probabilistic filters, a higher number of entries decreases
/// the bits per entry but increases the false positive rate.
///
/// An `Xor16` is constructed from a set of 64-bit unsigned integers and is immutable.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, Xor16};
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = Xor16::from(&keys);
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(&key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 16.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 20., "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.0025, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `Xor16` filters can be enabled with the [`serde`] feature  (or [`bincode`] for bincode).
///
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[derive(Debug, Clone)]
pub struct Xor16 {
    /// The seed for the filter
    pub seed: u64,
    /// The number of blocks in the filter
    pub block_length: usize,
    /// The fingerprints for the filter
    pub fingerprints: Box<[u16]>,
}

impl Filter<u64> for Xor16 {
    /// Returns `true` if the filter contains the specified key. Has a false positive rate of <0.002%.
    fn contains(&self, key: &u64) -> bool {
        xor_contains_impl!(*key, self, fingerprint u16)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl Xor16 {
    /// Construct the filter from a key iterator. Can be used directly
    /// if you don't have a contiguous array of u64 keys.
    ///
    /// Note: the iterator will be iterated over multiple times while building
    /// the filter. If using a hash function to map the key, it may be cheaper
    /// just to create a scratch array of hashed keys that you pass in.
    pub fn from_iterator<T>(keys: T) -> Self
    where
        T: ExactSizeIterator<Item = u64> + Clone,
    {
        xor_from_impl!(keys fingerprint u16)
    }
}

impl From<&[u64]> for Xor16 {
    fn from(keys: &[u64]) -> Self {
        Self::from_iterator(keys.iter().copied())
    }
}

impl From<&Vec<u64>> for Xor16 {
    fn from(v: &Vec<u64>) -> Self {
        Self::from_iterator(v.iter().copied())
    }
}

impl From<Vec<u64>> for Xor16 {
    fn from(v: Vec<u64>) -> Self {
        Self::from_iterator(v.iter().copied())
    }
}

#[cfg(test)]
mod test {
    use crate::{Filter, Xor16};

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor16::from(&keys);

        for key in keys {
            assert!(filter.contains(&key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor16::from(&keys);
        let bpe = (filter.len() as f64) * 16.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 20., "Bits per entry is {}", bpe);
    }

    #[test]
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor16::from(&keys);

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.0025, "False positive rate is {}", fp_rate);
    }
}
