use crate::prelude::HashSet;

const H3: u64 = 0xBF58_476D_1CE4_E5B9;
const ARITY: usize = 3;
const SEGMENT_COUNT: usize = 100;
pub const SLOTS: usize = SEGMENT_COUNT + ARITY - 1;
pub const FUSE_OVERHEAD: f64 = 1.0 / 0.879;

impl HashSet {
    pub const fn fuse_from(key: u64, segment_length: usize, seed: u64) -> Self {
        let hash = crate::prelude::mix(key, seed);
        let H012 { hset } = H012::from(hash, segment_length);

        Self { hash, hset }
    }
}

/// Just the indexing hashes of a key.
pub struct H012 {
    pub hset: [usize; 3],
}

impl H012 {
    pub const fn from(hash: u64, segment_length: usize) -> Self {
        use crate::{reduce, rotl64};

        let r0 = hash as u32;
        let r1 = rotl64!(hash, by 21) as u32;
        let r2 = rotl64!(hash, by 42) as u32;
        let r3 = ((H3.overflowing_mul(hash).0) >> 32) as u32;

        let seg = reduce!(r0 on interval SEGMENT_COUNT);

        Self {
            hset: [
                seg * segment_length + reduce!(r1 on interval segment_length),
                (seg + 1) * segment_length + reduce!(r2 on interval segment_length),
                (seg + 2) * segment_length + reduce!(r3 on interval segment_length),
            ],
        }
    }
}

/// Creates a `contains(u64)` implementation for a fuse xor filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! fuse_contains_impl(
    ($key:expr, $self:expr, fingerprint $fpty:ty) => {
        {
            use $crate::prelude::HashSet;

            let HashSet {
                hash,
                hset: [h0, h1, h2],
            } = HashSet::fuse_from($key, $self.segment_length, $self.seed);
            let fp = $crate::fingerprint!(hash) as $fpty;

            fp == $self.fingerprints[h0]
                ^ $self.fingerprints[h1]
                ^ $self.fingerprints[h2]
        }
    };
);

/// Creates an `from(&[u64])` implementation for an xor filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! fuse_from_impl(
    ($keys:ident fingerprint $fpty:ty, max iter $max_iter:expr) => {
        {
            use $crate::{
                fingerprint,
                make_block,
                make_fp_block,
                prelude::{
                    HashSet, HSet, KeyIndex,
                    fuse::{H012, FUSE_OVERHEAD, SLOTS},
                },
                splitmix64::splitmix64,
                try_enqueue,
            };

            #[cfg(debug_assertions)] {
                use $crate::prelude::all_distinct;
                debug_assert!(all_distinct($keys.clone()), "Fuse filters must be constructed from a collection containing all distinct keys.");
            }

            // See Algorithm 3 in the paper.
            let num_keys = $keys.len();
            let capacity = (FUSE_OVERHEAD * num_keys as f64) as usize;
            let capacity = capacity / SLOTS * SLOTS;
            let segment_length = capacity / SLOTS;

            #[allow(non_snake_case)]
            let mut H: Box<[HSet]> = make_block!(with capacity sets);
            #[allow(non_snake_case)]
            let mut Q: Box<[KeyIndex]> = make_block!(with capacity sets);
            let mut stack: Box<[KeyIndex]> = make_block!(with num_keys sets);

            let mut rng = 1;
            let mut seed = splitmix64(&mut rng);
            let mut done = false;
            for _ in 0..$max_iter {
                // Populate H by adding each key to its respective set.
                for key in $keys.clone() {
                    let HashSet { hash, hset } = HashSet::fuse_from(key, segment_length, seed);

                    for b in 0..3 {
                        H[hset[b]].mask ^= hash;
                        H[hset[b]].count += 1;
                    }
                }

                // Scan for sets with a single key. Add these keys to the queue.
                let mut q_size = 0;
                for idx in 0..(capacity) {
                    try_enqueue!(block H, set idx;
                                 queue block Q, with size q_size);
                }

                let mut stack_size = 0;
                while q_size > 0 {
                    q_size -= 1;
                    let ki = Q[q_size];
                    if H[ki.index].count == 0 {
                        continue
                    }

                    let H012 { hset } = H012::from(ki.hash, segment_length);

                    stack[stack_size] = ki;
                    stack_size += 1;

                    for b in 0..3 {
                        let setidx = hset[b];
                        H[setidx].mask ^= ki.hash;
                        H[setidx].count -= 1;
                        try_enqueue!(block H, set setidx;
                                     queue block Q, with size q_size);
                    }
                }

                if stack_size == num_keys {
                    done = true;
                    break;
                }

                // Filter failed to be created; reset and try again.
                for set in H.iter_mut() {
                    *set = HSet::default();
                }
                seed = splitmix64(&mut rng)
            }

            if !done {
                return Err("Failed to construct fuse filter.");
            }

            // Construct all fingerprints (see Algorithm 4 in the paper).
            #[allow(non_snake_case)]
            let mut B: Box<[$fpty]> = make_fp_block!(capacity);
            for ki in stack.iter().rev() {
                let H012 { hset: [h0, h1, h2] } = H012::from(ki.hash, segment_length);
                let fp = (fingerprint!(ki.hash) as $fpty) ^ match ki.index {
                    h if h == h0 => B[h1] ^ B[h2],
                    h if h == h1 => B[h0] ^ B[h2],
                    h if h == h2 => B[h0] ^ B[h1],
                    _ => unreachable!(),
                };
                B[ki.index] = fp;
            }

            Ok(Self {
                seed,
                segment_length,
                fingerprints: B,
            })
        }
    };
);
