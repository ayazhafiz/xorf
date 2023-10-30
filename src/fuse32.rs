//! Implements Fuse32 filters.

#![allow(deprecated)] // Fuse32 filters are deprecated, but we need to implement them.

use crate::{fuse_contains_impl, fuse_from_impl, Filter};
use alloc::{boxed::Box, vec::Vec};
use core::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

/// Xor filter using 32-bit fingerprints in a [fuse graph]. Requires less space than an [`Xor32`].
///
/// A `Fuse32` filter uses <36.404 bits per entry of the set is it constructed from, and has a false
/// positive rate of effectively zero (1/2^32 =~ 1/4 billion). As with other probabilistic filters,
/// a higher number of entries decreases the bits per entry but increases the false positive rate.
///
/// A `Fuse32` filter uses less space and is faster to construct than an [`Xor32`] filter, but
/// requires a large number of keys to be constructed. Experimentally, this number is somewhere
/// >100_000. For smaller key sets, prefer the [`Xor32`] filter. A `Fuse32` filter may fail to be
/// constructed.
///
/// A `Fuse32` is constructed from a set of 64-bit unsigned integers and is immutable.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, Fuse32};
/// use core::convert::TryFrom;
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = Fuse32::try_from(&keys).unwrap();
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(&key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 32.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 36.404, "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.0000000000000001, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `Fuse32` filters can be enabled with the [`serde`] feature  (or [`bincode`] for bincode).
///
/// [fuse graph]: https://arxiv.org/abs/1907.04749
/// [`Xor32`]: crate::Xor32
/// [`serde`]: http://serde.rs
#[deprecated(since = "0.8.0", note = "prefer using a `BinaryFuse32`")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[derive(Debug, Clone)]
pub struct Fuse32 {
    /// The seed for the filter
    pub seed: u64,
    /// The number of blocks in the filter
    pub segment_length: usize,
    /// The fingerprints for the filter
    pub fingerprints: Box<[u32]>,
}

impl Filter<u64> for Fuse32 {
    /// Returns `true` if the filter contains the specified key.
    fn contains(&self, key: &u64) -> bool {
        fuse_contains_impl!(*key, self, fingerprint u32)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl Fuse32 {
    /// Try to construct the filter from a key iterator. Can be used directly
    /// if you don't have a contiguous array of u64 keys.
    ///
    /// Note: the iterator will be iterated over multiple times while building
    /// the filter. If using a hash function to map the key, it may be cheaper
    /// just to create a scratch array of hashed keys that you pass in.
    pub fn try_from_iterator<T>(keys: T) -> Result<Self, &'static str>
    where
        T: ExactSizeIterator<Item = u64> + Clone,
    {
        fuse_from_impl!(keys fingerprint u32, max iter 1_000)
    }
}

impl TryFrom<&[u64]> for Fuse32 {
    type Error = &'static str;

    fn try_from(keys: &[u64]) -> Result<Self, Self::Error> {
        Self::try_from_iterator(keys.iter().copied())
    }
}

impl TryFrom<&Vec<u64>> for Fuse32 {
    type Error = &'static str;

    fn try_from(v: &Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from_iterator(v.iter().copied())
    }
}

impl TryFrom<Vec<u64>> for Fuse32 {
    type Error = &'static str;

    fn try_from(v: Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from_iterator(v.iter().copied())
    }
}

#[cfg(test)]
mod test {
    use crate::{Filter, Fuse32};
    use core::convert::TryFrom;

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse32::try_from(&keys).unwrap();

        for key in keys {
            assert!(filter.contains(&key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse32::try_from(&keys).unwrap();
        let bpe = (filter.len() as f64) * 32.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 36.404, "Bits per entry is {}", bpe);
    }

    #[test]
    #[ignore]
    // Note: takes a long time (> 1 hour) to run, and has a high memory
    // requirement (> 32 GB), due to a 1bn sample size of crypto-random
    // numbers being generated on a single thread.
    // The test actually passes with a 10^-16 false positive rate
    // which probably means the 1bn sample size is still too small.
    // The expected false positive rate should be 1/2^32=~1/(4 billion),
    // but has not been tested / verified.
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse32::try_from(&keys).unwrap();

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(
            fp_rate < 0.0000000000000001,
            "False positive rate is {}",
            fp_rate
        );
    }

    #[test]
    fn test_fail_construction() {
        const SAMPLE_SIZE: usize = 1_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Fuse32::try_from(&keys);
        assert!(filter.expect_err("") == "Failed to construct fuse filter.");
    }
}
