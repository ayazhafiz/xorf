# xorf

[![Build Status](https://travis-ci.com/ayazhafiz/xorf.svg?branch=master)](https://travis-ci.com/ayazhafiz/xorf)

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

Xor filters operate on sets ofs 64-bit unsigned integers. Information regarding
usage of the filters can be found in the
[library documentation](https://docs.rs/xorf). This library is `no_std` and
[`needs_allocator`](https://doc.rust-lang.org/1.9.0/book/custom-allocators.html).
