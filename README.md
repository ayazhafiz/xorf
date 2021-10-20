# xorf

[![Xorf docs](https://docs.rs/xorf/badge.svg)](https://docs.rs/xorf)
[![Crates.io](https://img.shields.io/crates/v/xorf)](https://crates.io/crates/xorf)
[![Build Status](https://travis-ci.com/ayazhafiz/xorf.svg?branch=master)](https://travis-ci.com/ayazhafiz/xorf)

- [Documentation](https://docs.rs/xorf)
- [Crates.io Registry](https://crates.io/crates/xorf)

This repository hosts a Rust library implementing
[xor filters](https://arxiv.org/abs/1912.08258) and their derivates:

- Binary Fuse filters (most recommended)
  - [`BinaryFuse8`](./src/bfuse8.rs)
  - [`BinaryFuse16`](./src/bfuse16.rs)
  - [`BinaryFuse32`](./src/bfuse32.rs)
- Xor filters
  - [`Xor8`](./src/xor8.rs)
  - [`Xor16`](./src/xor16.rs)
  - [`Xor32`](./src/xor32.rs)
- Fuse filters (deprecated, use Binary Fuse filters instead)
  - [`Fuse8`](./src/fuse8.rs)
  - [`Fuse16`](./src/fuse16.rs)
  - [`Fuse32`](./src/fuse32.rs)

Xor filters are data structures for fast approximation of set membership using
little memory. Probabilistic filters like
xor filters are useful when it's okay to have false positives sometimes, but
it's important to be space and time efficient. In other words, they trade off
accuracy for efficiency as compared to general-purpose hashsets. Filters like
xor filter are often used in conjunction with larger hash-based data structures,
with the filter doing a "first pass" of the work to avoid using a more expensive
resource unnecessarily. For example, filters like xor filters can be used to
[reduce disk writes](https://en.wikipedia.org/wiki/Bloom_filter#Cache_filtering)
in a cache or
[identify malicious URLs](https://en.wikipedia.org/wiki/Bloom_filter#Examples)
in a browser.

Xor filters are faster and smaller than Bloom and Cuckoo filters. Xor filters
incur a relative time penalty in construction, but are very fast in lookups; the
expectation is that construction of a filter is amortized after many queries.
Daniel Lemire's [go implementation](https://github.com/FastFilter/xorfilter)
provides a useful summary of xor filters' benefits and listing of other xor
filter libraries.

This library is `no_std` and
[`needs_allocator`](https://doc.rust-lang.org/1.9.0/book/custom-allocators.html).

`xorf` also provides a [`HashProxy`](./src/hash_proxy.rs) for using Xor filters
with arbitrary key types.

## Installation

Add a dependency to `xorf` in `Cargo.toml`:

```toml
[dependencies]
xorf = "M.m.p" # use a desired version
```

Available versions are listed on [crates](https://crates.io/crates/xorf) and the in [repository's
releases](https://github.com/ayazhafiz/xorf/releases).

## Usage

Please see the [library documentation](https://docs.rs/xorf) for usage
information.

### Features

#### Custom allocator

To use a [custom global allocator](https://doc.rust-lang.org/1.9.0/book/custom-allocators.html),
you must be using a nightly release of rustc and have enabled the `nightly`
feature for `xorf`.

```toml
[dependencies]
xorf = { version = "M.m.p", features = ["nightly"] }
```

This will tag the crate as `needs_allocator`, which you will then have to
provide. At this time, a custom allocator is used globally.

#### Serialization/Deserialization

Serialization and deserialization with [serde](https://serde.rs/) cab be enabled
with the `serde` feature.

```toml
[dependencies]
xorf = { version = "M.m.p", features = ["serde"] }
```

#### Default features

##### Uniform Random

By default, `xorf` uses the `uniform-random` feature, which uses random values for unused
fingerprint entries rather than setting them to zero. This provides a slightly lower false-positive
rate, but incurs a higher initialization cost. The cost of lookups is not affected.

To disable the `uniform-random` feature, specify that default features should be disabled:

```toml
[dependencies]
xorf = { version = "M.m.p", default-features = false }
```

##### Binary Fuse

By default, `xorf` uses the `binary-fuse` feature, which adds support for and
exposes Binary Fuse filter implementations. This feature pulls in a dependency
of `libm`, but has no runtime cost. This feature is highly recommended, as
Binary Fuse filters are the most powerful in the Xor filter family.

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
