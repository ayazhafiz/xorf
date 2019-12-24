//! This library implements Xor Filters -- data structures for fast approximation of set
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
//! serializable, and guarantee no false negatives.
//!
//! Filters provided by this library are implemented as described in the paper
//! [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters] and in Daniel Lemire's [go] and
//! [c] implementations. All are useful references on the theory behind xor filters. For
//! performance statistics, refer to individual filters' documentation or the mentioned
//! paper.
//!
//! [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters]: https://arxiv.org/abs/1912.08258
//! [reduce disk writes]: https://en.wikipedia.org/wiki/Bloom_filter#Cache_filtering
//! [identify malicious URLs]: https://en.wikipedia.org/wiki/Bloom_filter#Examples
//! [go]: https://github.com/FastFilter/xorfilter
//! [c]: https://github.com/FastFilter/xor_singleheader

#![no_std]
#![cfg_attr(feature = "nightly", feature(allocator_internals), needs_allocator)]
// Configuration attributes
#![warn(missing_docs)]
#![forbid(clippy::all, clippy::cargo, clippy::nursery)]

extern crate alloc;

mod murmur3;
mod splitmix64;
mod xor8;

pub use xor8::Filter as Xor8Filter;
