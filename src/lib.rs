//!
//!

#![no_std]
#![warn(missing_docs)]
#![feature(allocator_internals)]
#![needs_allocator]

extern crate alloc;

mod murmur3;
mod splitmix64;
mod xor8;

pub use xor8::Filter as Xor8Filter;
