/// Pseudo-RNG using Sebastiano Vigna's [`SplitMix64`] algorithm.
///
/// [`SplitMix64`]: http://xoroshiro.di.unimi.it/splitmix64.c
///
/// Written in 2015 by Sebastiano Vigna (vigna@acm.org)
///
/// To the extent possible under law, the author has dedicated all copyright and related and
/// neighboring rights to this software to the public domain worldwide. This software is
/// distributed without any warranty.
///
/// See <http://creativecommons.org/publicdomain/zero/1.0/>.
pub fn splitmix64(seed: &mut u64) -> u64 {
    *seed = (*seed).overflowing_add(0x9e37_79b9_7f4a_7c15).0;
    let mut z = *seed;
    z = (z ^ (z >> 30)).overflowing_mul(0xbf58_476d_1ce4_e5b9).0;
    z = (z ^ (z >> 27)).overflowing_mul(0x94d0_49bb_1331_11eb).0;
    z ^ (z >> 31)
}
