use crate::prelude::HashSet;

impl HashSet {
    pub const fn xor_from(key: u64, block_length: usize, seed: u64) -> Self {
        let hash = crate::prelude::mix(key, seed);

        Self {
            hash,
            hset: [
                crate::xor_h!(index block 0, of length block_length, using hash),
                crate::xor_h!(index block 1, of length block_length, using hash),
                crate::xor_h!(index block 2, of length block_length, using hash),
            ],
        }
    }
}

/// Computes a hash indexing the i'th filter block.
#[doc(hidden)]
#[macro_export]
macro_rules! xor_h(
    (index block $i:expr, of length $block_length:expr, using $hash:expr) => {
        {
            let rot = $crate::rotl64!($hash, by (($i as isize) * 21)) as u32; // shift hash to correct block interval
            $crate::reduce!(rot on interval $block_length)
        }
    };
);

/// Creates a `contains(u64)` implementation for an xor filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! xor_contains_impl(
    ($key:expr, $self:expr, fingerprint $fpty:ty) => {
        {
            use $crate::prelude::HashSet;

            let HashSet {
                hash,
                hset: [h0, h1, h2],
            } = HashSet::xor_from($key, $self.block_length, $self.seed);
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
macro_rules! xor_from_impl(
    ($keys:ident fingerprint $fpty:ty) => {
        {
            use $crate::{
                fingerprint,
                xor_h,
                make_block,
                prelude::{HashSet, HSet, KeyIndex},
                splitmix64::splitmix64,
                try_enqueue,
            };

            #[cfg(debug_assertions)] {
                use $crate::prelude::all_distinct;
                debug_assert!(all_distinct($keys.clone()), "Xor filters must be constructed from a collection containing all distinct keys.");
            }

            // See Algorithm 3 in the paper.
            let num_keys = $keys.len();
            let capacity = (1.23 * num_keys as f64) as usize + 32;
            let capacity = capacity / 3 * 3; // round to nearest multiple of 3
            let block_length = capacity / 3;

            #[allow(non_snake_case)]
            let mut H: [Box<[HSet]>; 3] = [
                make_block!(with capacity sets),
                make_block!(with capacity sets),
                make_block!(with capacity sets),
            ];
            #[allow(non_snake_case)]
            let mut Q: [Box<[KeyIndex]>; 3] = [
                make_block!(with capacity sets),
                make_block!(with capacity sets),
                make_block!(with capacity sets),
            ];
            let mut stack: Box<[KeyIndex]> = make_block!(with num_keys sets);

            let mut rng = 1;
            let mut seed = splitmix64(&mut rng);
            loop {
                // Populate H by adding each key to its respective set.
                for key in $keys.clone() {
                    let HashSet { hash, hset } = HashSet::xor_from(key, block_length, seed);

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
                        try_enqueue!(block H[b], set idx;
                                     queue block Q[b], with size q_sizes[b]);
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
                                    let idx = xor_h!(index block *j, of length block_length, using ki.hash);
                                    H[*j][idx].mask ^= ki.hash;
                                    H[*j][idx].count -= 1;
                                    try_enqueue!(block H[*j], set idx;
                                                 queue block Q[*j], with size q_sizes[*j]);
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
            let mut B: Box<[$fpty]> = make_block!(with capacity sets);
            for ki in stack.iter().rev() {
                B[ki.index] = fingerprint!(ki.hash) as $fpty
                    ^ B[xor_h!(index block 0, of length block_length, using ki.hash)]
                    ^ B[(xor_h!(index block 1, of length block_length, using ki.hash) + block_length)]
                    ^ B[(xor_h!(index block 2, of length block_length, using ki.hash) + 2 * block_length)];
            }

            Self {
                seed,
                block_length,
                fingerprints: B,
            }
        }
    };
);
