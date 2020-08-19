// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Fast, non-cryptographic hash used by rustc and Firefox.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # fn main() {
//! use rustc_hash::FxHashMap;
//! let mut map: FxHashMap<u32, u32> = FxHashMap::default();
//! map.insert(22, 44);
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```

#![no_std]

#[cfg(feature = "std")]
extern crate std;

use core::convert::TryInto;
use core::default::Default;
#[cfg(feature = "std")]
use core::hash::BuildHasherDefault;
use core::hash::Hasher;
use core::mem::size_of;
use core::ops::BitXor;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

/// Type alias for a hashmap using the `fx` hash algorithm.
#[cfg(feature = "std")]
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

/// Type alias for a hashmap using the `fx` hash algorithm.
#[cfg(feature = "std")]
pub type FxHashSet<V> = HashSet<V, BuildHasherDefault<FxHasher>>;

/// A speedy hash algorithm for use within rustc. The hashmap in liballoc
/// by default uses SipHash which isn't quite as speedy as we want. In the
/// compiler we're not really worried about DOS attempts, so we use a fast
/// non-cryptographic hash.
///
/// This is the same as the algorithm used by Firefox -- which is a homespun
/// one not based on any widely-known algorithm -- though modified to produce
/// 64-bit hash values instead of 32-bit hash values. It consistently
/// out-performs an FNV-based hash within rustc itself -- the collision rate is
/// similar or slightly worse than FNV, but the speed of the hash function
/// itself is much higher because it works on up to 8 bytes at a time.
#[derive(Copy, Clone)]
pub struct FxHasher {
    hash: usize,
}

#[cfg(target_pointer_width = "32")]
const K: usize = 0x9e3779b9;
#[cfg(target_pointer_width = "64")]
const K: usize = 0x517cc1b727220a95;

impl Default for FxHasher {
    #[inline]
    fn default() -> FxHasher {
        FxHasher { hash: 0 }
    }
}

impl FxHasher {
    #[inline]
    fn add_to_hash(&mut self, i: usize) {
        self.hash = self.hash.rotate_left(5).bitxor(i).wrapping_mul(K);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        let mut hash = *self;
        assert!(size_of::<usize>() <= size_of::<u64>());
        while bytes.len() >= size_of::<usize>() {
            let (usize_bytes, rest_bytes) = bytes.split_at(size_of::<usize>());
            hash.add_to_hash(usize::from_ne_bytes(usize_bytes.try_into().unwrap()));
            bytes = rest_bytes;
        }
        if bytes.len() >= size_of::<u32>() {
            let (u32_bytes, rest_bytes) = bytes.split_at(size_of::<u32>());
            hash.add_to_hash(u32::from_ne_bytes(u32_bytes.try_into().unwrap()) as usize);
            bytes = rest_bytes;
        }
        if bytes.len() >= size_of::<u16>() {
            let (u16_bytes, rest_bytes) = bytes.split_at(size_of::<u16>());
            hash.add_to_hash(u16::from_ne_bytes(u16_bytes.try_into().unwrap()) as usize);
            bytes = rest_bytes;
        }
        if bytes.len() >= size_of::<u8>() {
            hash.add_to_hash(bytes[0] as usize);
        }
        *self = hash;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash as u64
    }
}
