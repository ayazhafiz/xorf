//! Implements a hashing proxy for xor filters.

use crate::Filter;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Arbitrary key type proxy for xor filters.
///
/// A `HashProxy` exposes a [`Filter`] trait for arbitrary key types, using a `Filter<u64>` as
/// an underlying keystore. The performance and collision rate of the `HashProxy` filter depends
/// on the choice of [`Hasher`] and underlying [`Filter`]. A `HashProxy` is immutable once
/// constructed.
///
/// ```
/// # extern crate alloc;
/// # extern crate std;
/// use std::collections::hash_map::DefaultHasher;
/// use xorf::{Filter, HashProxy, Xor8};
/// # use alloc::vec::Vec;
/// # use rand::distributions::Alphanumeric;
/// # use rand::Rng;
///
/// const SAMPLE_SIZE: usize = 1_000_000;
/// let passwords: Vec<String> = (0..SAMPLE_SIZE)
///     .map(|_| rand::thread_rng().sample_iter(&Alphanumeric).take(30).map(char::from).collect())
///     .collect();
///
/// let pw_filter: HashProxy<String, DefaultHasher, Xor8> = HashProxy::from(&passwords);
///
/// for password in passwords {
///     assert!(pw_filter.contains(&password));
/// }
/// ```
///
/// While a `HashProxy` persists type information about the keys it is constructed with, in most
/// cases the key type parameter can be elided. For example, the `pw_filter` defined above can also
/// be defined as
///
/// ```
/// # extern crate alloc;
/// # extern crate std;
/// # use std::collections::hash_map::DefaultHasher;
/// # use xorf::{Filter, HashProxy, Xor8};
/// # use alloc::vec::Vec;
/// # use rand::distributions::Alphanumeric;
/// # use rand::Rng;
/// #
/// # const SAMPLE_SIZE: usize = 1_000_000;
/// # let passwords: Vec<String> = (0..SAMPLE_SIZE)
/// #     .map(|_| rand::thread_rng().sample_iter(&Alphanumeric).take(30).map(char::from).collect())
/// #     .collect();
/// #
/// let pw_filter: HashProxy<_, DefaultHasher, Xor8> = HashProxy::from(&passwords);
/// ```
///
/// Because of `HashProxy`s' key type parameter, the existence of a key can only be checked using
/// types a `HashProxy` is constructed with.
///
/// ```compile_fail
/// # extern crate alloc;
/// # extern crate std;
/// use std::collections::hash_map::DefaultHasher;
/// use std::hash::{Hash, Hasher};
/// use xorf::{Filter, HashProxy, Xor8};
/// # use alloc::vec::Vec;
///
/// let fruits = vec!["apple", "banana", "tangerine", "watermelon"];
/// let fruits: HashProxy<_, DefaultHasher, Xor8> = HashProxy::from(&fruits);
///
/// let mut hasher = DefaultHasher::default();
/// "tangerine".hash(&mut hasher);
/// let tangerine_hash = hasher.finish();
///
/// assert!(fruits.contains(&tangerine_hash)); // doesn't work!
/// ```
///
/// Serializing and deserializing `HashProxy`s can be enabled with the [`serde`] feature.
///
/// [`Filter`]: crate::Filter
/// [`Hasher`]: core::hash::Hasher
/// [`serde`]: http://serde.rs
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashProxy<T, H, F>
where
    T: Hash,
    H: Hasher + Default,
    F: Filter<u64>,
{
    filter: F,
    _hasher: core::marker::PhantomData<H>,
    _type: core::marker::PhantomData<T>,
}

#[inline]
fn hash<T: Hash, H: Hasher + Default>(key: &T) -> u64 {
    let mut hasher = H::default();
    key.hash(&mut hasher);
    hasher.finish()
}

impl<T, H, F> Filter<T> for HashProxy<T, H, F>
where
    T: Hash,
    H: Hasher + Default,
    F: Filter<u64>,
{
    /// Returns `true` if the underlying filter contains the specified key.
    fn contains(&self, key: &T) -> bool {
        self.filter.contains(&hash::<T, H>(key))
    }

    fn len(&self) -> usize {
        self.filter.len()
    }
}

impl<T, H, F> From<&[T]> for HashProxy<T, H, F>
where
    T: Hash,
    H: Hasher + Default,
    F: Filter<u64> + From<Vec<u64>>,
{
    fn from(keys: &[T]) -> Self {
        let keys: Vec<u64> = keys.iter().map(hash::<T, H>).collect();
        Self {
            filter: F::from(keys),
            _hasher: core::marker::PhantomData,
            _type: core::marker::PhantomData,
        }
    }
}

impl<T, H, F> From<&Vec<T>> for HashProxy<T, H, F>
where
    T: Hash,
    H: Hasher + Default,
    F: Filter<u64> + From<Vec<u64>>,
{
    fn from(v: &Vec<T>) -> Self {
        Self::from(v.as_slice())
    }
}

// TODO(ayazhafiz): We should support a `TryFrom` trait as well. Today this is impossible due to
// rustc's core blanket implementation of `Into`, which picks up a conflicting implementation when
// both `From<T>` and `TryFrom<T>` with unbound type parameters `T` are defined.
//
// See https://github.com/rust-lang/rust/issues/50133 for more details.

#[cfg(test)]
mod test {
    use crate::{xor16::Xor16, xor32::Xor32, xor8::Xor8};
    use crate::{Filter, HashProxy};

    use alloc::vec::Vec;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    extern crate std;
    use std::collections::hash_map::DefaultHasher;
    use std::string::String;

    #[test]
    fn test_initialization_from() {
        const SAMPLE_SIZE: usize = 1_000_000;
        // Key generation is expensive. Do it once and make copies during tests.
        let keys: Vec<String> = (0..SAMPLE_SIZE)
            .map(|_| {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(15)
                    .map(char::from)
                    .collect()
            })
            .collect();

        macro_rules! drive_test {
            ($xorf:ident) => {{
                let keys = keys.clone();
                let filter: HashProxy<_, DefaultHasher, $xorf> = HashProxy::from(&keys);
                for key in keys {
                    assert!(filter.contains(&key));
                }
            }};
        }

        drive_test!(Xor8);
        drive_test!(Xor16);
        drive_test!(Xor32);
    }
}
