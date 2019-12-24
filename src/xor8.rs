use super::{murmur3::murmur3_mix64, splitmix64::splitmix64};
use alloc::{boxed::Box, vec::Vec};
use core::f64;

#[derive(Default)]
struct HashSet {
    hash: u64,
    hset: [u32; 3],
}

impl HashSet {
    pub fn from(key: u64, block_length: u32, seed: u64) -> Self {
        let hash = mix(key, seed);
        HashSet {
            hash,
            hset: [
                h(0, hash, block_length),
                h(1, hash, block_length),
                h(2, hash, block_length),
            ],
        }
    }
}

#[derive(Default, Copy, Clone)]
struct KeyIndex {
    hash: u64,
    index: u32,
}

#[derive(Default, Copy, Clone)]
struct XorSet {
    count: u32,
    mask: u64,
}

#[inline]
fn mix(key: u64, seed: u64) -> u64 {
    murmur3_mix64(key.overflowing_add(seed).0)
}

#[inline]
fn rotl64(n: u64, c: isize) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

/// http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
#[inline]
fn reduce(hash: u32, n: u32) -> u32 {
    ((hash as u64 * n as u64) >> 32) as u32
}

/// Computes a hash indexing the i'th filter block.
#[inline]
fn h(i: usize, hash: u64, block_length: u32) -> u32 {
    let r2 = rotl64(hash, (i as isize) * 21) as u32;
    reduce(r2, block_length)
}

#[inline]
fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

///
pub struct Filter {
    seed: u64,
    block_length: u32,
    fingerprints: Box<[u8]>,
}

impl Filter {
    ///
    pub fn contains(&self, key: u64) -> bool {
        let HashSet {
            hash,
            hset: [h0, h1, h2],
        } = HashSet::from(key, self.block_length, self.seed);
        let fp = fingerprint(hash) as u8;

        fp == self.fingerprints[h0 as usize]
            ^ self.fingerprints[(h1 + self.block_length) as usize]
            ^ self.fingerprints[(h2 + 2 * self.block_length) as usize]
    }
}

#[inline]
fn sets_block<T: Clone>(size: usize) -> Box<[T]> {
    let mut sets_block = Vec::with_capacity(size);
    unsafe {
        sets_block.set_len(size);
    }
    sets_block.into_boxed_slice()
}

#[allow(non_snake_case)]
#[inline]
fn try_enqueue_set(
    H_block: &Box<[XorSet]>,
    idx: &usize,
    Q_block: &mut Box<[KeyIndex]>,
    qblock_size: &mut usize,
) {
    if H_block[*idx as usize].count == 1 {
        Q_block[*qblock_size].index = *idx as u32;
        // If there is only one key, the mask contains it wholly.
        Q_block[*qblock_size].hash = H_block[*idx as usize].mask;
        *qblock_size += 1;
    }
}

impl From<&[u64]> for Filter {
    fn from(keys: &[u64]) -> Self {
        let num_keys = keys.len();
        let capacity = (1.23 * num_keys as f64) as u32 + 32;
        let capacity = capacity / 3 * 3;
        let block_length = capacity / 3;

        #[allow(non_snake_case)]
        let mut Q: [Box<[KeyIndex]>; 3] = [
            sets_block(capacity as usize),
            sets_block(capacity as usize),
            sets_block(capacity as usize),
        ];
        #[allow(non_snake_case)]
        let mut H: [Box<[XorSet]>; 3] = [
            sets_block(capacity as usize),
            sets_block(capacity as usize),
            sets_block(capacity as usize),
        ];
        let mut stack: Box<[KeyIndex]> = sets_block(num_keys as usize);

        let mut rng = 1;
        let mut seed = splitmix64(&mut rng);
        loop {
            for k in 0..num_keys {
                let key = keys[k];
                let HashSet { hash, hset } = HashSet::from(key, block_length, seed);

                for b in 0..3 {
                    let h_b = hset[b];
                    H[b][h_b as usize].mask ^= hash;
                    H[b][h_b as usize].count += 1;
                }
            }

            // Scan for sets with a single key. Add these keys to the queue.
            let mut q_sizes: [usize; 3] = [0, 0, 0];
            for b in 0..3 {
                for idx in 0..(block_length as usize) {
                    try_enqueue_set(&H[b], &(idx), &mut Q[b], &mut q_sizes[b]);
                }
            }

            let mut stack_size = 0;
            // While the queue isn't empty...
            while q_sizes.iter().sum::<usize>() > 0 {
                while q_sizes[0] > 0 {
                    q_sizes[0] -= 1;
                    let ki = Q[0][q_sizes[0]];
                    if H[0][ki.index as usize].count == 0 {
                        continue;
                    }
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in [1, 2].iter() {
                        let idx = h(*j, ki.hash, block_length);
                        // Remove the element from set
                        H[*j][idx as usize].mask ^= ki.hash;
                        H[*j][idx as usize].count -= 1;
                        try_enqueue_set(&H[*j], &(idx as usize), &mut Q[*j], &mut q_sizes[*j]);
                    }
                }

                while q_sizes[1] > 0 {
                    q_sizes[1] -= 1;
                    let mut ki = Q[1][q_sizes[1]];
                    if H[1][ki.index as usize].count == 0 {
                        continue;
                    }
                    ki.index += block_length;
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in [0, 2].iter() {
                        let idx = h(*j, ki.hash, block_length);
                        // Remove the element from set
                        H[*j][idx as usize].mask ^= ki.hash;
                        H[*j][idx as usize].count -= 1;
                        try_enqueue_set(&H[*j], &(idx as usize), &mut Q[*j], &mut q_sizes[*j]);
                    }
                }

                while q_sizes[2] > 0 {
                    q_sizes[2] -= 1;
                    let mut ki = Q[2][q_sizes[2]];
                    if H[2][ki.index as usize].count == 0 {
                        continue;
                    }
                    ki.index += 2 * block_length;
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in [0, 1].iter() {
                        let idx = h(*j, ki.hash, block_length);
                        // Remove the element from set
                        H[*j][idx as usize].mask ^= ki.hash;
                        H[*j][idx as usize].count -= 1;
                        try_enqueue_set(&H[*j], &(idx as usize), &mut Q[*j], &mut q_sizes[*j]);
                    }
                }
            }

            if stack_size == num_keys {
                break;
            }

            for b in 0..3 {
                for set in H[b].iter_mut() {
                    *set = XorSet::default();
                }
            }

            seed = splitmix64(&mut rng)
        }

        let mut fingerprints = sets_block(capacity as usize);
        for i in (0..num_keys).rev() {
            let ki = stack[i];
            let mut fp = fingerprint(ki.hash) as u8;

            if ki.index < block_length {
                fp ^= fingerprints[(h(1, ki.hash, block_length) + block_length) as usize]
                    ^ fingerprints[(h(2, ki.hash, block_length) + 2 * block_length) as usize]
            } else if ki.index < 2 * block_length {
                fp ^= fingerprints[h(0, ki.hash, block_length) as usize]
                    ^ fingerprints[(h(2, ki.hash, block_length) + 2 * block_length) as usize]
            } else {
                fp ^= fingerprints[h(0, ki.hash, block_length) as usize]
                    ^ fingerprints[(h(1, ki.hash, block_length) + block_length) as usize]
            }

            fingerprints[ki.index as usize] = fp;
        }

        Self {
            seed,
            block_length,
            fingerprints,
        }
    }
}

impl From<&Vec<u64>> for Filter {
    fn from(v: &Vec<u64>) -> Self {
        Self::from(v.as_slice())
    }
}

#[cfg(test)]
mod test {
    use crate::Xor8Filter;

    use alloc::vec::Vec;
    use rand::Rng;

    #[test]
    fn test_initialization() {
        const SIZE: usize = 10_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8Filter::from(&keys);

        for key in keys {
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn test_bits_per_entry() {
        const SIZE: usize = 10_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8Filter::from(&keys);
        let bpe = (filter.fingerprints.len() as f64) * 8.0 / (SIZE as f64);

        assert!(bpe < 10.);
    }

    #[test]
    fn test_false_positives() {
        const SIZE: usize = 10_000;
        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8Filter::from(&keys);

        const NEGATIVES: usize = 1_000_000;
        let false_positives: usize = (0..NEGATIVES)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(*n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / NEGATIVES as f64;
        assert!(fp_rate < 0.4);
    }
}
