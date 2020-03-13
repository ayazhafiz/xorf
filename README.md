# xorf

[![Xorf docs](https://docs.rs/xorf/badge.svg)](https://docs.rs/xorf)
[![Crates.io](https://img.shields.io/crates/v/xorf)](https://crates.io/crates/xorf)
[![Build Status](https://travis-ci.com/ayazhafiz/xorf.svg?branch=master)](https://travis-ci.com/ayazhafiz/xorf)

- [Documentation](https://docs.rs/xorf)
- [Crates.io Registry](https://crates.io/crates/xorf)

This repository hosts a Rust library implementing
[xor filters](https://arxiv.org/abs/1912.08258) -- data structures for fast
approximation of set membership using little memory. Probabilistic filters like
xor filters are useful for quickly estimating of the existence of an entity to
avoid using an expensive resource. For example, they can be used to
[reduce disk writes](https://en.wikipedia.org/wiki/Bloom_filter#Cache_filtering)
in a cache or
[identify malicious URLs](https://en.wikipedia.org/wiki/Bloom_filter#Examples).

Xor filters are faster and smaller than Bloom and Cuckoo filters. Xor filters
incur a relative time penalty in construction, but are very fast in lookups; the
expectation is that construction of a filter is amortized after many queries.
Daniel Lemire's [go implementation](https://github.com/FastFilter/xorfilter)
provides a useful summary of xor filters' benefits and listing of other xor
filter libraries.

This library is `no_std` and
[`needs_allocator`](https://doc.rust-lang.org/1.9.0/book/custom-allocators.html).
Currently, the following xor filters are provided:

- [`Xor8`](./src/xor8.rs)
- [`Xor16`](./src/xor16.rs)
- [`Fuse8`](./src/fuse8.rs)
- [`Fuse16`](./src/fuse16.rs)

`xorf` also provides a [`HashProxy`](./src/hash_proxy.rs) for using Xor filters
with arbitrary key types.

## Installation

Add a dependency to `xorf` in `Cargo.toml`:

```toml
[dependencies]
xorf = "M.m.p" # use a desired version
```

To enable
[`needs_allocator`](https://doc.rust-lang.org/1.9.0/book/custom-allocators.html)
and serialization/deserialization, add the `nightly` and `serde` features,
respectively:

```toml
[dependencies]
xorf = { version = "M.m.p", features = ["nightly", "serde"] }
```

Finally, add `xorf` as an external crate in the depender crate's root file:

```rust
extern crate xorf;
```

## Usage

Please see the [library documentation](https://docs.rs/xorf) for usage
information.

## Development

Development of `xorf` targets the master branch of this repository.

Changes can be tested by running the [`check`](./scripts/check) script:

```bash
scripts/check lf     # validates lint and format
scripts/check test   # tests source code
```

## Contribution

Contributions are warmly welcomed. No contribution is too small, and all are
appreciated.

## License

[MIT](./LICENSE)
