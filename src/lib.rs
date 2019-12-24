//!
//!

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
