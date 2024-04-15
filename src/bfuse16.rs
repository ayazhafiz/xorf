//! Implements BinaryFuse16 filters.

use crate::{
    bfuse_contains_impl, bfuse_from_impl,
    prelude::bfuse::{parse_bfuse_descriptor, serialize_bfuse_descriptor, Descriptor},
    DmaSerializable, Filter, FilterRef,
};
use alloc::{boxed::Box, vec::Vec};
use core::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

/// A `BinaryFuse16` filter is an Xor-like filter with 16-bit fingerprints arranged in a binary-partitioned [fuse graph].
/// `BinaryFuse16`s are similar to [`Fuse16`]s, but their construction is faster, uses less
/// memory, and is more likely to succeed.
///
/// A `BinaryFuse16` filter uses ≈18 bits per entry of the set is it constructed from, and has a false
/// positive rate of ≈2^-16 (<0.002%). As with other probabilistic filters, a higher number of entries decreases
/// the bits per entry but increases the false positive rate.
///
/// A `BinaryFuse16` is constructed from a set of 64-bit unsigned integers and is immutable.
/// Construction may fail, but usually only if there are duplicate keys.
///
/// ```
/// # extern crate alloc;
/// use xorf::{Filter, BinaryFuse16};
/// use core::convert::TryFrom;
/// # use alloc::vec::Vec;
/// # use rand::Rng;
///
/// # let mut rng = rand::thread_rng();
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
/// let filter = BinaryFuse16::try_from(&keys).unwrap();
///
/// // no false negatives
/// for key in keys {
///     assert!(filter.contains(&key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 16.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 18.1, "Bits per entry is {}", bpe);
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
/// Serializing and deserializing `BinaryFuse16` filters can be enabled with the [`serde`] feature (or [`bincode`] for bincode).
///
/// [fuse graph]: https://arxiv.org/abs/1907.04749
/// [`Fuse16`]: crate::Fuse16
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[derive(Debug, Clone)]
pub struct BinaryFuse16 {
    #[cfg_attr(feature = "serde", serde(flatten))]
    descriptor: Descriptor,
    /// The fingerprints for the filter
    pub fingerprints: Box<[u16]>,
}

impl Filter<u64> for BinaryFuse16 {
    /// Returns `true` if the filter contains the specified key.
    /// Has a false positive rate of <0.4%.
    /// Has no false negatives.
    fn contains(&self, key: &u64) -> bool {
        bfuse_contains_impl!(*key, self, fingerprint u16)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl BinaryFuse16 {
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
        bfuse_from_impl!(keys fingerprint u16, max iter 1_000)
    }
}

impl TryFrom<&[u64]> for BinaryFuse16 {
    type Error = &'static str;

    fn try_from(keys: &[u64]) -> Result<Self, Self::Error> {
        Self::try_from_iterator(keys.iter().copied())
    }
}

impl TryFrom<&Vec<u64>> for BinaryFuse16 {
    type Error = &'static str;

    fn try_from(v: &Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from_iterator(v.iter().copied())
    }
}

impl TryFrom<Vec<u64>> for BinaryFuse16 {
    type Error = &'static str;

    fn try_from(v: Vec<u64>) -> Result<Self, Self::Error> {
        Self::try_from_iterator(v.iter().copied())
    }
}

impl DmaSerializable for BinaryFuse16 {
    const DESCRIPTOR_LEN: usize = Descriptor::DMA_LEN;

    fn dma_copy_descriptor_to(&self, out: &mut [u8]) {
        serialize_bfuse_descriptor(&self.descriptor, out)
    }

    fn dma_fingerprints(&self) -> &[u8] {
        let fingerprints = self.fingerprints.as_ref();
        #[allow(clippy::manual_slice_size_calculation)]
        let len = fingerprints.len() * core::mem::size_of::<u16>();
        unsafe { core::slice::from_raw_parts(fingerprints.as_ptr() as *const u8, len) }
    }
}

/// Like [`BinaryFuse16`] except that it can be constructed 0-copy from external buffers.
#[derive(Debug, Clone)]
pub struct BinaryFuse16Ref<'a> {
    descriptor: Descriptor,
    fingerprints: &'a [u16],
}

impl<'a> Filter<u64> for BinaryFuse16Ref<'a> {
    /// Returns `true` if the filter contains the specified key.
    /// Has a false positive rate of <0.4%.
    /// Has no false negatives.
    fn contains(&self, key: &u64) -> bool {
        bfuse_contains_impl!(*key, self, fingerprint u16)
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

impl<'a> FilterRef<'a, u64> for BinaryFuse16Ref<'a> {
    const FINGERPRINT_ALIGNMENT: usize = 2;

    fn from_dma(descriptor: &[u8], fingerprints: &'a [u8]) -> Self {
        assert_eq!(
            fingerprints
                .as_ptr()
                .align_offset(core::mem::align_of::<u16>()),
            0,
            "Invalid fingerprint pointer provided - must be u16 aligned"
        );
        assert_eq!(
            fingerprints.len() % core::mem::align_of::<u16>(),
            0,
            "Invalid fingerprint buffer provided - length must be a multiple of u16"
        );

        // #[allow(clippy::manual_slice_size_calculation)]
        let len = fingerprints.len() / core::mem::size_of::<u16>();
        let fingerprints =
            unsafe { core::slice::from_raw_parts(fingerprints.as_ptr() as *const u16, len) };

        Self {
            descriptor: parse_bfuse_descriptor(descriptor),
            fingerprints,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{bfuse16::BinaryFuse16Ref, BinaryFuse16, DmaSerializable, Filter, FilterRef};
    use core::convert::TryFrom;

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();

        for key in keys {
            assert!(filter.contains(&key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();
        let bpe = (filter.len() as f64) * 16.0 / (SAMPLE_SIZE as f64);

        assert!(bpe < 18.1, "Bits per entry is {}", bpe);
    }

    #[test]
    fn test_false_positives() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();

        let false_positives: usize = (0..SAMPLE_SIZE)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.0025, "False positive rate is {}", fp_rate);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(
        expected = "Binary Fuse filters must be constructed from a collection containing all distinct keys."
    )]
    fn test_debug_assert_duplicates() {
        let _ = BinaryFuse16::try_from(vec![1, 2, 1]);
    }

    #[test]
    fn test_dma_roundtrip() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();

        // Unaligned descriptor is fine.
        let mut descriptor = [0; BinaryFuse16::DESCRIPTOR_LEN + 1];
        filter.dma_copy_descriptor_to(&mut descriptor[1..]);

        let filter_ref = BinaryFuse16Ref::from_dma(&descriptor[1..], filter.dma_fingerprints());
        assert_eq!(filter_ref.descriptor, filter.descriptor);

        for key in &keys {
            assert!(filter_ref.contains(key));
        }
    }

    #[test]
    #[should_panic(expected = "Invalid fingerprint pointer provided - must be u16 aligned")]
    fn test_dma_unaligned_fingerprints() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();

        let mut descriptor = [0; BinaryFuse16::DESCRIPTOR_LEN + 1];
        filter.dma_copy_descriptor_to(&mut descriptor[1..]);

        let mut as_vec = vec![1];
        as_vec.extend_from_slice(filter.dma_fingerprints());

        let filter_ref = BinaryFuse16Ref::from_dma(&descriptor[1..], &as_vec[1..]);
        assert_eq!(filter_ref.descriptor, filter.descriptor);
    }

    #[test]
    #[should_panic(
        expected = "Invalid fingerprint buffer provided - length must be a multiple of u16"
    )]
    fn test_dma_unaligned_fingerprints_len() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = BinaryFuse16::try_from(&keys).unwrap();

        let mut descriptor = [0; BinaryFuse16::DESCRIPTOR_LEN + 1];
        filter.dma_copy_descriptor_to(&mut descriptor[1..]);

        let serialized = filter.dma_fingerprints();
        let serialized = &serialized[..serialized.len() - 1];

        BinaryFuse16Ref::from_dma(&descriptor[1..], serialized);
    }
}
