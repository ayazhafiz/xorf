use super::{murmur3::mix64, splitmix64::splitmix64};
use alloc::{boxed::Box, vec::Vec};

#[derive(Default)]
struct HashSet {
    hash: u64,
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

#[derive(Default, Copy, Clone)]
struct KeyIndex {
    hash: u64,
    index: usize,
}

#[derive(Default, Copy, Clone)]
struct XorSet {
    count: u32,
    mask: u64,
}

#[inline]
const fn mix(key: u64, seed: u64) -> u64 {
    mix64(key.overflowing_add(seed).0)
}

#[inline]
const fn rotl64(n: u64, c: isize) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}
///
/// [A fast alternative to the modulo reduction]
///
/// [A fast alternative to the modulo reduction]: http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
#[inline]
const fn reduce(hash: u32, n: usize) -> usize {
    ((hash as u64 * n as u64) >> 32) as usize
}

/// Computes a hash indexing the i'th filter block.
#[inline]
const fn h(i: usize, hash: u64, block_length: usize) -> usize {
    let r2 = rotl64(hash, (i as isize) * 21) as u32;
    reduce(r2, block_length)
}

#[inline]
const fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

///
pub struct Filter {
    seed: u64,
    block_length: usize,
    fingerprints: Box<[u8]>,
}

impl Filter {
    ///
    pub const fn contains(&self, key: u64) -> bool {
        let HashSet {
            hash,
            hset: [h0, h1, h2],
        } = HashSet::from(key, self.block_length, self.seed);
        let fp = fingerprint(hash) as u8;

        fp == self.fingerprints[h0]
            ^ self.fingerprints[(h1 + self.block_length)]
            ^ self.fingerprints[(h2 + 2 * self.block_length)]
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
    H_block: &[XorSet],
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

impl From<&[u64]> for Filter {
    fn from(keys: &[u64]) -> Self {
        let num_keys = keys.len();
        let capacity = (1.23 * num_keys as f64) as usize + 32;
        let capacity = capacity / 3 * 3;
        let block_length = capacity / 3;

        #[allow(non_snake_case)]
        let mut Q: [Box<[KeyIndex]>; 3] = [
            sets_block(capacity),
            sets_block(capacity),
            sets_block(capacity),
        ];
        #[allow(non_snake_case)]
        let mut H: [Box<[XorSet]>; 3] = [
            sets_block(capacity),
            sets_block(capacity),
            sets_block(capacity),
        ];
        let mut stack: Box<[KeyIndex]> = sets_block(num_keys);

        let mut rng = 1;
        let mut seed = splitmix64(&mut rng);
        loop {
            for key in keys.iter() {
                let HashSet { hash, hset } = HashSet::from(*key, block_length, seed);

                for b in 0..3 {
                    let h_b = hset[b];
                    H[b][h_b].mask ^= hash;
                    H[b][h_b].count += 1;
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
            // While the queue isn't empty...
            while q_sizes.iter().sum::<usize>() > 0 {
                while q_sizes[0] > 0 {
                    q_sizes[0] -= 1;
                    let ki = Q[0][q_sizes[0]];
                    if H[0][ki.index].count == 0 {
                        continue;
                    }
                    stack[stack_size] = ki;
                    stack_size += 1;

                    for j in &[1, 2] {
                        let idx = h(*j, ki.hash, block_length);
                        // Remove the element from set
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
                        // Remove the element from set
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
                        // Remove the element from set
                        H[*j][idx].mask ^= ki.hash;
                        H[*j][idx].count -= 1;
                        try_enqueue_set(&H[*j], idx, &mut Q[*j], &mut q_sizes[*j]);
                    }
                }
            }

            if stack_size == num_keys {
                break;
            }

            for block in H.iter_mut() {
                for set in block.iter_mut() {
                    *set = XorSet::default();
                }
            }

            seed = splitmix64(&mut rng)
        }

        let mut fingerprints = sets_block(capacity);
        for i in (0..num_keys).rev() {
            let ki = stack[i];
            let mut fp = fingerprint(ki.hash) as u8;

            if ki.index < block_length {
                fp ^= fingerprints[(h(1, ki.hash, block_length) + block_length)]
                    ^ fingerprints[(h(2, ki.hash, block_length) + 2 * block_length)]
            } else if ki.index < 2 * block_length {
                fp ^= fingerprints[h(0, ki.hash, block_length)]
                    ^ fingerprints[(h(2, ki.hash, block_length) + 2 * block_length)]
            } else {
                fp ^= fingerprints[h(0, ki.hash, block_length)]
                    ^ fingerprints[(h(1, ki.hash, block_length) + block_length)]
            }

            fingerprints[ki.index] = fp;
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
        const NEGATIVES: usize = 1_000_000;

        let mut rng = rand::thread_rng();
        let keys: Vec<u64> = (0..SIZE).map(|_| rng.gen()).collect();

        let filter = Xor8Filter::from(&keys);

        let false_positives: usize = (0..NEGATIVES)
            .map(|_| rng.gen())
            .filter(|n| filter.contains(*n))
            .count();
        let fp_rate: f64 = (false_positives * 100) as f64 / NEGATIVES as f64;
        assert!(fp_rate < 0.4);
    }
}
