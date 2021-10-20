//! This library implements Xor Filters and their derivatives. Xor filters are data structures for fast approximation of set
//! membership using little memory. Probabilistic filters like xor filters are useful for
//! quickly estimating of the existence of an entity to avoid using an expensive resource.
//! For example, they can be used to [reduce disk writes] in a cache or [identify malicious URLs].
//!
//! Xor filters are faster and smaller than Bloom and Cuckoo filters.
//! Xor filters incur a relative time penalty in construction, but are very fast in lookups; the
//! expectation is that construction of a filter is amortized after many queries.
//!
//! Xor filters operate only on sets of 64-bit (unsigned) integers. This library does not provide
//! methods for hashing arbitrary types to 64-bit integers. Xor filters are immutable,
//! serializable, and guarantee no false negatives. This library is `no_std` and [`needs_allocator`].
//!
//! Filters are implemented as described in the paper
//! "[Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters]", in the upcoming
//! "Binary Fuse Filters: Fast and Smaller Than Xor Filters", and in Daniel Lemire's [go] and
//! [c] implementations. All are useful references on the theory behind xor filters. For
//! performance statistics, refer to individual filters' documentation in this crate or the
//! mentioned papers.
//!
//! ## General considerations for all filters
//!
//! It is highly recommended to use the `BinaryFuse` family of xor-like filters. `BinaryFuse`
//! filters can fail to construct, but almost always only if they are constructed with duplicate
//! keys. If you need a filter that will unconditionally succeed in construction (up to duplicate
//! keys), use the `Xor` family of filters.
//!
//! For a given `N`, a `BinaryFuseN` and `FuseN` filter are roughly equivalent in size, uniformity
//! of key distribution, and false-positive rate.
//!
//! An `XorN` filter is larger, less uniform, and has a higher false-positive
//! rate than both a `BinaryFuseN` and `FuseN` filter.
//!
//! A `BinaryFuseN` filter's construction is faster, uses less memory, and is more likely to
//! succeed compared to a `FuseN` filter's construction.
//!
//! The false-positive rate of a filter with fingerprint size `N` is around `2^{-N}`; for more
//! numbers, see the documentation of each individual filter.
//!
//! ### Assumed pre-conditions
//!
//! - It is a pre-condition that all filters are constructed from a data structure containing no
//!   duplicate keys. You must perform any de-duplication needed yourself before constructing a
//!   filter.
//!
//! ## FAQ
//!
//! ### What's the difference between "Fuse" and "Binary Fuse" filters?
//!
//! Fuse filters use a [fuse graph] to reduce the space required to hold fingerprints. Binary Fuse
//! filters further exploit fuse graphs in a novel manner described in the upcoming
//! "Binary Fuse Filters: Fast and Smaller Than Xor Filters". In particular, Binary Fuse filters
//! use a binary-partitioned fuse graph, and are different enough from the "original" Fuse filters
//! to deserve a unique name.
//!
//! [fuse graph]: https://arxiv.org/abs/1907.04749
//! [reduce disk writes]: https://en.wikipedia.org/wiki/Bloom_filter#Cache_filtering
//! [identify malicious URLs]: https://en.wikipedia.org/wiki/Bloom_filter#Examples
//! [`needs_allocator`]: https://doc.rust-lang.org/1.9.0/book/custom-allocators.html
//! [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters]: https://arxiv.org/abs/1912.08258
//! [go]: https://github.com/FastFilter/xorfilter
//! [c]: https://github.com/FastFilter/xor_singleheader

#![no_std]
#![cfg_attr(feature = "nightly", feature(allocator_internals), needs_allocator)]
#![warn(missing_docs)]
#![forbid(clippy::all, clippy::cargo, clippy::nursery)]
#![allow(
    clippy::len_without_is_empty,
    clippy::useless_attribute,
    clippy::multiple_crate_versions,
    clippy::fallible_impl_from
)]

#[macro_use]
extern crate alloc;

mod murmur3;
mod prelude;
mod splitmix64;

#[cfg(feature = "binary-fuse")]
mod bfuse16;
#[cfg(feature = "binary-fuse")]
mod bfuse32;
#[cfg(feature = "binary-fuse")]
mod bfuse8;
mod fuse16;
mod fuse32;
mod fuse8;
mod hash_proxy;
mod xor16;
mod xor32;
mod xor8;

#[cfg(feature = "binary-fuse")]
pub use bfuse16::BinaryFuse16;
#[cfg(feature = "binary-fuse")]
pub use bfuse32::BinaryFuse32;
#[cfg(feature = "binary-fuse")]
pub use bfuse8::BinaryFuse8;
pub use fuse16::Fuse16;
pub use fuse32::Fuse32;
pub use fuse8::Fuse8;
pub use hash_proxy::HashProxy;
pub use xor16::Xor16;
pub use xor32::Xor32;
pub use xor8::Xor8;

/// Methods common to xor filters.
pub trait Filter<Type> {
    /// Returns `true` if the filter probably contains the specified key.
    ///
    /// There can never be a false negative, but there is a small possibility of false positives.
    /// Refer to individual filters' documentation for false positive rates.
    fn contains(&self, key: &Type) -> bool;

    /// Returns the number of fingerprints in the filter.
    fn len(&self) -> usize;
}
