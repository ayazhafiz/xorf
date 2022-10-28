//! Implements Binary Fuse filters.
// Port of https://github.com/FastFilter/xorfilter/blob/master/binaryfusefilter.go

use libm::{floor, fmax, log};

#[inline]
pub fn segment_length(arity: u32, size: u32) -> u32 {
    if size == 0 {
        return 4;
    }

    match arity {
        3 => 1 << (floor(log(size as f64) / log(3.33_f64) + 2.25) as u32),
        4 => 1 << (floor(log(size as f64) / log(2.91_f64) - 0.5) as u32),
        _ => 65536,
    }
}

#[inline]
pub fn size_factor(arity: u32, size: u32) -> f64 {
    match arity {
        3 => fmax(
            1.125_f64,
            0.875 + 0.25 * log(1000000_f64) / log(size as f64),
        ),
        4 => fmax(1.075_f64, 0.77 + 0.305 * log(600000_f64) / log(size as f64)),
        _ => 2.0,
    }
}

#[inline]
pub const fn hash_of_hash(
    hash: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;
    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;
    (h0, h1, h2)
}

#[inline]
pub const fn mod3(x: u8) -> u8 {
    if x > 2 {
        x - 3
    } else {
        x
    }
}

/// Implements `try_from(&[u64])` for an binary fuse filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! bfuse_from_impl(
    ($keys:ident fingerprint $fpty:ty, max iter $max_iter:expr) => {
        {
            use libm::round;
            use $crate::{
                fingerprint,
                make_block,
                make_fp_block,
                prelude::{
                    mix,
                    bfuse::{segment_length, size_factor, hash_of_hash, mod3},
                },
                splitmix64::splitmix64,
            };

            #[cfg(debug_assertions)] {
                use $crate::prelude::all_distinct;
                debug_assert!(all_distinct($keys.clone()), "Binary Fuse filters must be constructed from a collection containing all distinct keys.");
            }

            let arity = 3u32;
            let size: usize = $keys.len();
            let segment_length: u32 = segment_length(arity, size as u32).min(262144);
            let segment_length_mask: u32 = segment_length - 1;
            let size_factor: f64 = size_factor(arity, size as u32);
            let capacity: u32 = if size > 1 {
                round(size as f64 * size_factor) as u32
            } else { 0 };
            let init_segment_count = (capacity + segment_length - 1) / segment_length;
            let (fp_array_len, segment_count) = {
                let array_len = init_segment_count * segment_length;
                let segment_count: u32 = {
                    let proposed = (array_len + segment_length - 1) / segment_length;
                    if proposed < arity {
                        1
                    } else {
                        proposed - (arity - 1)
                    }
                };
                let array_len: u32 = (segment_count + arity - 1) * segment_length;
                (array_len as usize, segment_count)
            };
            let segment_count_length = segment_count * segment_length;

            let mut fingerprints: Box<[$fpty]> = make_fp_block!(fp_array_len);

            let mut rng = 1;
            let mut seed = splitmix64(&mut rng);
            let capacity = fingerprints.len();
            let mut alone: Box<[u32]> = make_block!(with capacity sets);
            let mut t2count: Box<[u8]> = make_block!(with capacity sets);
            let mut t2hash: Box<[u64]> = make_block!(with capacity sets);
            let mut reverse_h: Box<[u8]> = make_block!(with size sets);
            let size_plus_1: usize = size + 1;
            let mut reverse_order: Box<[u64]> = make_block!(with size_plus_1 sets);
            reverse_order[size] = 1;

            let block_bits = {
                let mut block_bits = 1;
                while (1 << block_bits) < segment_count {
                    block_bits += 1;
                }
                block_bits
            };

            let start_pos_len: usize = 1 << block_bits;
            let mut start_pos: Box<[usize]> = make_block!(with start_pos_len sets);
            let mut h012: [u32; 6] = [0; 6];
            let mut done = false;
            let mut ultimate_size = 0;
            for _ in 0..$max_iter {
                for i in 0..start_pos_len {
                    start_pos[i] = (((i as u64) * (size as u64)) >> block_bits) as usize;
                }
                for key in $keys.clone() {
                    let hash = mix(key, seed);
                    let mut segment_index = hash >> (64 - block_bits);
                    while reverse_order[start_pos[segment_index as usize] as usize] != 0 {
                        segment_index += 1;
                        segment_index &= (1 << block_bits) - 1;
                    }
                    reverse_order[start_pos[segment_index as usize] as usize] = hash;
                    start_pos[segment_index as usize] += 1;
                }

                let mut error = false;
                let mut duplicates = 0;
                for i in 0..size {
                    let hash = reverse_order[i];
                    let (index1, index2, index3) = hash_of_hash(hash, segment_length, segment_length_mask, segment_count_length);
                    let (index1, index2, index3) = (index1 as usize, index2 as usize, index3 as usize);
                    t2count[index1] += 4;
                    // t2count[index1] ^= 0; NOOP
                    t2hash[index1] ^= hash;
			              t2count[index2] += 4;
			              t2count[index2] ^= 1;
			              t2hash[index2] ^= hash;
			              t2count[index3] += 4;
			              t2count[index3] ^= 2;
			              t2hash[index3] ^= hash;

			              if t2hash[index1] & t2hash[index2] & t2hash[index3] == 0 {
                        if ((t2hash[index1] == 0) && (t2count[index1] == 8)) ||
                           ((t2hash[index2] == 0) && (t2count[index2] == 8)) ||
                           ((t2hash[index3] == 0) && (t2count[index3] == 8)) {
                                duplicates += 1;
                                t2count[index1] -= 4;
                                // t2count[index1] ^= 0; NOOP
                                t2hash[index1] ^= hash;
                                t2count[index2] -= 4;
                                t2count[index2] ^= 1;
					                      t2hash[index2] ^= hash;
					                      t2count[index3] -= 4;
					                      t2count[index3] ^= 2;
					                      t2hash[index3] ^= hash;
                        }
                    }
                    error = t2count[index1] < 4 || t2count[index2] < 4 || t2count[index3] < 4;
                }
                if error {
                    continue;
                }

                // Key addition complete. Perform enqueing.

                let mut qsize = 0;
                for i in 0..capacity {
                    alone[qsize] = i as u32;
                    if (t2count[i] >> 2) == 1 {
                        qsize += 1;
                    }
                }
                let mut stack_size = 0;
                while qsize > 0 {
                    qsize -= 1;
                    let index = alone[qsize] as usize;
                    if (t2count[index] >> 2) == 1 {
                        let hash = t2hash[index];
                        let found: u8 = t2count[index] & 3;
                        reverse_h[stack_size] = found;
                        reverse_order[stack_size] = hash;
                        stack_size += 1;

                        let (index1, index2, index3) = hash_of_hash(hash, segment_length, segment_length_mask, segment_count_length);

                        h012[1] = index2;
                        h012[2] = index3;
                        h012[3] = index1;
                        h012[4] = h012[1];

                        let other_index1 = h012[(found + 1) as usize] as usize;
                        alone[qsize] = other_index1 as u32;
                        if (t2count[other_index1] >> 2) == 2 {
                            qsize += 1;
                        }
                        t2count[other_index1] -= 4;
                        t2count[other_index1] ^= mod3(found + 1);
                        t2hash[other_index1] ^= hash;

                        let other_index2 = h012[(found + 2) as usize] as usize;
				                alone[qsize] = other_index2 as u32;
				                if (t2count[other_index2] >> 2) == 2 {
                            qsize += 1;
                        }
                        t2count[other_index2] -= 4;
                        t2count[other_index2] ^= mod3(found + 2);
                        t2hash[other_index2] ^= hash;
                    }
                }

                if stack_size + duplicates == size {
                    ultimate_size = stack_size;
                    done = true;
                    break
                }

                // Filter failed to be created; reset for a retry.
                for i in 0..size {
                    reverse_order[i] = 0;
                }
                for i in 0..capacity {
                    t2count[i] = 0;
                    t2hash[i] = 0;
                }
                seed = splitmix64(&mut rng)
            }
            if !done {
                return Err("Failed to construct binary fuse filter.");
            }

            // Construct all fingerprints
            let size = ultimate_size;
            for i in (0..size).rev() {
                let hash = reverse_order[i];
                let xor2 = (fingerprint!(hash) as $fpty);
                let (index1, index2, index3) = hash_of_hash(hash, segment_length, segment_length_mask, segment_count_length);
                let found = reverse_h[i] as usize;
		            h012[0] = index1;
		            h012[1] = index2;
		            h012[2] = index3;
		            h012[3] = h012[0];
		            h012[4] = h012[1];
		            fingerprints[h012[found] as usize] =
                      xor2
                    ^ fingerprints[h012[found + 1] as usize]
                    ^ fingerprints[h012[found + 2] as usize];
            }

            Ok(Self {
                seed,
                segment_length,
                segment_length_mask,
                segment_count_length,
                fingerprints,
            })
        }
    };
);

/// Implements `contains(u64)` for a binary fuse filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! bfuse_contains_impl(
    ($key:expr, $self:expr, fingerprint $fpty:ty) => {
        {
            use $crate::{
                fingerprint,
                prelude::{
                    mix,
                    bfuse::hash_of_hash
                },
            };
            let hash = mix($key, $self.seed);
            let mut f = fingerprint!(hash) as $fpty;
            let (h0, h1, h2) = hash_of_hash(hash, $self.segment_length, $self.segment_length_mask, $self.segment_count_length);
            f ^= $self.fingerprints[h0 as usize]
               ^ $self.fingerprints[h1 as usize]
               ^ $self.fingerprints[h2 as usize];
            f == 0
        }
    };
);
