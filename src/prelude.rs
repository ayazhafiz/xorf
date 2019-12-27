//! Common methods for xor filters.

use crate::murmur3;

/// A set of hashes indexing three blocks.
pub struct HashSet {
    /// Key hash
    pub hash: u64,
    /// Indexing hashes h_0, h_1, h_2 created with `hash`.
    pub hset: [usize; 3],
}

impl HashSet {
    #[inline]
    pub const fn from(key: u64, block_length: usize, seed: u64) -> Self {
        let hash = mix(key, seed);

        Self {
            hash,
            hset: [
                crate::h!(index block 0, of length block_length, using hash),
                crate::h!(index block 1, of length block_length, using hash),
                crate::h!(index block 2, of length block_length, using hash),
            ],
        }
    }
}

/// Applies a finalization mix to a randomly-seeded key, resulting in an avalanched hash. This
/// helps avoid high false-positive ratios (see Section 4 in the paper).
#[inline]
const fn mix(key: u64, seed: u64) -> u64 {
    murmur3::mix64(key.overflowing_add(seed).0)
}

/// The hash of a key and the index of that key in the construction array H.
#[derive(Copy, Clone)]
pub struct KeyIndex {
    pub hash: u64,
    pub index: usize,
}

/// A set in the construction array H. Elements are encoded via xor with the mask.
#[derive(Default)]
pub struct HSet {
    pub count: u32,
    pub mask: u64,
}

/// Computes a fingerprint.
#[doc(hidden)]
#[macro_export]
macro_rules! fingerprint(
    ($hash:expr) => {
        $hash ^ ($hash >> 32)
    };
);

/// Rotate left
#[doc(hidden)]
#[macro_export]
macro_rules! rotl64(
    ($n:expr, by $c:expr) => {
        ($n << ($c & 63)) | ($n >> ((-$c) & 63))
    };
);

/// [A fast alternative to the modulo reduction](http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/)
#[doc(hidden)]
#[macro_export]
macro_rules! reduce(
    ($hash:ident on interval $n:expr) => {
        (($hash as u64 * $n as u64) >> 32) as usize
    };
);

/// Computes a hash indexing the i'th filter block.
#[doc(hidden)]
#[macro_export]
macro_rules! h(
    (index block $i:expr, of length $block_length:expr, using $hash:expr) => {
        {
            let rot = $crate::rotl64!($hash, by (($i as isize) * 21)) as u32; // shift hash to correct block interval
            $crate::reduce!(rot on interval $block_length)
        }
    };
);

/// Creates a block of sets, each set being of type T.
#[doc(hidden)]
#[macro_export]
macro_rules! make_block(
    (with $size:ident sets) => {
        {
            let mut sets_block = Vec::with_capacity($size);
            unsafe {
                sets_block.set_len($size);
            }
            sets_block.into_boxed_slice()
        }
    };
);

/// Enqueues a set from the temporary construction array H if the set contains only one key.
#[allow(non_snake_case)]
#[inline]
pub fn try_enqueue(
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

/// Creates a `contains(u64)` implementation for an xor filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! contains_impl(
     ($key:ident, $self:expr, fingerprint $fpty:ty) => {
         {
             use $crate::prelude::HashSet;

             let HashSet {
                 hash,
                 hset: [h0, h1, h2],
             } = HashSet::from($key, $self.block_length, $self.seed);
             let fp = $crate::fingerprint!(hash) as $fpty;

             fp == $self.fingerprints[h0]
                 ^ $self.fingerprints[(h1 + $self.block_length)]
                 ^ $self.fingerprints[(h2 + 2 * $self.block_length)]
         }
     };
 );

/// Creates an `from(&[u64])` implementation for an xor filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! from_impl(
    ($keys:ident fingerprint $fpty:ty) => {
        {
            use $crate::{
                fingerprint,
                h,
                make_block,
                prelude::{HashSet, HSet, KeyIndex, try_enqueue},
                splitmix64::splitmix64,
            };

            // See Algorithm 3 in the paper.
            let num_keys = $keys.len();
            let capacity = (1.23 * num_keys as f64) as usize + 32;
            let capacity = capacity / 3 * 3; // round to nearest multiple of 3
            let block_length = capacity / 3;

            #[allow(non_snake_case)]
            let mut Q: [Box<[KeyIndex]>; 3] = [
                make_block!(with capacity sets),
                make_block!(with capacity sets),
                make_block!(with capacity sets),
            ];
            #[allow(non_snake_case)]
            let mut H: [Box<[HSet]>; 3] = [
                make_block!(with capacity sets),
                make_block!(with capacity sets),
                make_block!(with capacity sets),
            ];
            let mut stack: Box<[KeyIndex]> = make_block!(with num_keys sets);

            let mut rng = 1;
            let mut seed = splitmix64(&mut rng);
            loop {
                // Populate H by adding each key to its respective set.
                for key in $keys.iter() {
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
                        try_enqueue(&H[b], idx, &mut Q[b], &mut q_sizes[b]);
                    }
                }

                let mut stack_size = 0;
                while q_sizes.iter().sum::<usize>() > 0 {
                    macro_rules! dequeue(
                        (block $block:expr, other blocks being $a:expr, $b:expr) => {
                            while q_sizes[$block] > 0 {
                                // Remove an element from the queue.
                                q_sizes[$block] -= 1;
                                let mut ki = Q[$block][q_sizes[$block]];
                                if H[$block][ki.index].count == 0 {
                                    continue;
                                }

                                // If it's the only element in its respective set in H, add it to
                                // the output stack.
                                ki.index += $block * block_length;
                                stack[stack_size] = ki;
                                stack_size += 1;

                                // Remove the element from every other set and enqueue any sets
                                // that now only have one element.
                                for j in &[$a, $b] {
                                    let idx = h!(index block *j, of length block_length, using ki.hash);
                                    H[*j][idx].mask ^= ki.hash;
                                    H[*j][idx].count -= 1;
                                    try_enqueue(&H[*j], idx, &mut Q[*j], &mut q_sizes[*j]);
                                }
                            }
                        };
                    );

                    dequeue!(block 0, other blocks being 1, 2);
                    dequeue!(block 1, other blocks being 0, 2);
                    dequeue!(block 2, other blocks being 0, 1);
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
            let mut B = make_block!(with capacity sets);
            for ki in stack.iter().rev() {
                B[ki.index] = fingerprint!(ki.hash) as $fpty
                    ^ B[h!(index block 0, of length block_length, using ki.hash)]
                    ^ B[(h!(index block 1, of length block_length, using ki.hash) + block_length)]
                    ^ B[(h!(index block 2, of length block_length, using ki.hash) + 2 * block_length)];
            }

            Self {
                seed,
                block_length,
                fingerprints: B,
            }
        }
    };
);
