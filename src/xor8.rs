//! Implements an Xor8 Xor8 as described in [Xor Xor8s: Faster and Smaller Than Bloom and Cuckoo Xor8s].
//!
//! [Xor Xor8s: Faster and Smaller Than Bloom and Cuckoo Xor8s]: https://arxiv.org/abs/1912.08258

use crate::{murmur3, splitmix64::splitmix64, Filter};
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A set of hashes indexing three blocks.
struct HashSet {
    /// Key hash
    hash: u64,
    /// Indexing hashes h_0, h_1, h_2 created with `hash`.
    hset: [usize; 3],
}

impl HashSet {
    pub const fn from(key: u64, block_length: usize, seed: u64) -> Self {
        let hash = mix(key, seed);

        Self {
            hash,
            hset: [
                h(0, hash, block_length),
                h(1, hash, block_length),
                h(2, hash, block_length),
            ],
        }
    }
}

/// The hash of a key and the index of that key in the construction array H.
#[derive(Copy, Clone)]
struct KeyIndex {
    hash: u64,
    index: usize,
}

/// A set in the construction array H. Elements are encoded via xor with the mask.
#[derive(Default)]
struct HSet {
    count: u32,
    mask: u64,
}

/// Applies a finalization mix to a randomly-seeded key, resulting in an avalanched hash. This
/// helps avoid high false-positive ratios (see Section 4 in the paper).
#[inline]
const fn mix(key: u64, seed: u64) -> u64 {
    murmur3::mix64(key.overflowing_add(seed).0)
}

#[inline]
const fn rotl64(n: u64, c: isize) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

/// [A fast alternative to the modulo reduction](http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/)
#[inline]
const fn reduce(hash: u32, n: usize) -> usize {
    ((hash as u64 * n as u64) >> 32) as usize
}

/// Computes a hash indexing the i'th filter block.
#[inline]
const fn h(i: usize, hash: u64, block_length: usize) -> usize {
    let rot = rotl64(hash, (i as isize) * 21) as u32; // shift hash to correct block interval
    reduce(rot, block_length)
}

#[inline]
const fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

/// Xor filter using 8-bit fingerprints.
///
/// An `Xor8` filter uses <10 bits per entry of the set is it constructed from, and has a false
/// positive rate of <4%. As with other probabilistic filters, a higher number of entries decreases
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
///     assert!(filter.contains(key));
/// }
///
/// // bits per entry
/// let bpe = (filter.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);
/// assert!(bpe < 10., "Bits per entry is {}", bpe);
///
/// // false positive rate
/// let false_positives: usize = (0..SAMPLE_SIZE)
///     .map(|_| rng.gen())
///     .filter(|n| filter.contains(*n))
///     .count();
/// let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
/// assert!(fp_rate < 0.4, "False positive rate is {}", fp_rate);
/// ```
///
/// Serializing and deserializing `Xor8` filters can be enabled with the [`serde`] feature.
///
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Xor8 {
    seed: u64,
    block_length: usize,
    fingerprints: Box<[u8]>,
}

impl Filter for Xor8 {
    /// Returns `true` if the filter contains the specified key. Has a false positive rate of <4%.
    fn contains(&self, key: u64) -> bool {
        let HashSet {
            hash,
            hset: [h0, h1, h2],
        } = HashSet::from(key, self.block_length, self.seed);
        let fp = fingerprint(hash) as u8;

        fp == self.fingerprints[h0]
            ^ self.fingerprints[(h1 + self.block_length)]
            ^ self.fingerprints[(h2 + 2 * self.block_length)]
    }

    fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

/// Creates a block of sets, each set being of type T.
#[inline]
fn sets_block<T>(size: usize) -> Box<[T]> {
    let mut sets_block = Vec::with_capacity(size);
    unsafe {
        sets_block.set_len(size);
    }
    sets_block.into_boxed_slice()
}

/// Enqueues a set from the temporary construction array H if the set contains only one key.
#[allow(non_snake_case)]
#[inline]
fn try_enqueue_set(
    H_block: &[HSet],
    idx: usize,
    Q_block: &mut [KeyIndex],
    qblock_size: &mut usize,
) {
    if H_block[idx].count == 1 {
        Q_block[*qblock_size].index = idx;
        // If there is only one key, the mask contains it wholly.
        Q_block[*qblock_size].hash = H_block[idx].mask;
        *qblock_size += 1;
    }
}

impl From<&[u64]> for Xor8 {
    fn from(keys: &[u64]) -> Self {
        // See Algorithm 3 in the paper.
        let num_keys = keys.len();
        let capacity = (1.23 * num_keys as f64) as usize + 32;
        let capacity = capacity / 3 * 3; // round to nearest multiple of 3
        let block_length = capacity / 3;

        #[allow(non_snake_case)]
        let mut Q: [Box<[KeyIndex]>; 3] = [
            sets_block(capacity),
            sets_block(capacity),
            sets_block(capacity),
        ];
        #[allow(non_snake_case)]
        let mut H: [Box<[HSet]>; 3] = [
            sets_block(capacity),
            sets_block(capacity),
            sets_block(capacity),
        ];
        let mut stack: Box<[KeyIndex]> = sets_block(num_keys);

        let mut rng = 1;
        let mut seed = splitmix64(&mut rng);
        loop {
            // Populate H by adding each key to its respective set.
            for key in keys.iter() {
                let HashSet { hash, hset } = HashSet::from(*key, block_length, seed);

                for b in 0..3 {
                    let setindex = hset[b];
                    H[b][setindex].mask ^= hash;
                    H[b][setindex].count += 1;
                }
            }

            // Scan for sets with a single key. Add these keys to the queue.
            let mut q_sizes: [usize; 3] = [0, 0, 0];
            for b in 0..3 {
                for idx in 0..(block_length) {
                    try_enqueue_set(&H[b], idx, &mut Q[b], &mut q_sizes[b]);
                }
            }

            let mut stack_size = 0;
            while q_sizes.iter().sum::<usize>() > 0 {
                while q_sizes[0] > 0 {
                    // Remove an element from the queue.
                    q_sizes[0] -= 1;
                    let ki = Q[0][q_sizes[0]];
                    if H[0][ki.index].count == 0 {
                        continue;
                    }
                    // If it's the only element in its respective set in H, add it to the output
                    // stack.
                    stack[stack_size] = ki;
                    stack_size += 1;

                    // Remove the element from every other set and enqueue any sets that now only
                    // have one element.
                    for j in &[1, 2] {
                        let idx = h(*j, ki.hash, block_length);
                        H[*j][idx].mask ^= ki.hash;
                        H[*j][idx].count -= 1;
                        try_enqueue_set(&H[*j], idx, &mut Q[*j], &mut q_sizes[*j]);
                    }
                }

                while q_sizes[1] > 0 {
                    q_sizes[1] -= 1;
                    let mut ki = Q[1][q_sizes[1]];
                    if H[1][ki.index].count == 0 {
                        continue;
                    }
                    ki.index += block_length;
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in &[0, 2] {
                        let idx = h(*j, ki.hash, block_length);
                        H[*j][idx].mask ^= ki.hash;
                        H[*j][idx].count -= 1;
                        try_enqueue_set(&H[*j], idx, &mut Q[*j], &mut q_sizes[*j]);
                    }
                }

                while q_sizes[2] > 0 {
                    q_sizes[2] -= 1;
                    let mut ki = Q[2][q_sizes[2]];
                    if H[2][ki.index].count == 0 {
                        continue;
                    }
                    ki.index += 2 * block_length;
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in &[0, 1] {
                        let idx = h(*j, ki.hash, block_length);
                        H[*j][idx].mask ^= ki.hash;
                        H[*j][idx].count -= 1;
                        try_enqueue_set(&H[*j], idx, &mut Q[*j], &mut q_sizes[*j]);
                    }
                }
            }

            if stack_size == num_keys {
                break;
            }

            // Filter failed to be created; reset and try again.
            for block in H.iter_mut() {
                for set in block.iter_mut() {
                    *set = HSet::default();
                }
            }
            seed = splitmix64(&mut rng)
        }

        // Construct all fingerprints (see Algorithm 4 in the paper).
        #[allow(non_snake_case)]
        let mut B = sets_block(capacity);
        for ki in stack.iter().rev() {
            B[ki.index] = fingerprint(ki.hash) as u8
                ^ B[h(0, ki.hash, block_length)]
                ^ B[(h(1, ki.hash, block_length) + block_length)]
                ^ B[(h(2, ki.hash, block_length) + 2 * block_length)];
        }

        Self {
            seed,
            block_length,
            fingerprints: B,
        }
    }
}

impl From<&Vec<u64>> for Xor8 {
    fn from(v: &Vec<u64>) -> Self {
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
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SAMPLE_SIZE: usize = 1_000_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8::from(&keys);
        let bpe = (filter.fingerprints.len() as f64) * 8.0 / (SAMPLE_SIZE as f64);

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
            .filter(|n| filter.contains(*n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / SAMPLE_SIZE as f64;
        assert!(fp_rate < 0.4, "False positive rate is {}", fp_rate);
    }
}
