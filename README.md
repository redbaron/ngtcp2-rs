# ngtcp2 Rust bindings

This crate provides safe and idiomatic Rust bindings for [ngtcp2](https://github.com/ngtcp2/ngtcp2)

Made of 3 Rust crates:
- `ngtcp2-sys`: raw bindings to the ngtcp2 C library
- `ngtcp2-safe`: mostly safe interface over `ngtcp2-sys`. Minimal rustification for safety and basic ergonimics is performed:
     * nulltpr -> Option<T>
     * C enums into Rust `#[repr(u8)]` enums
     * Bitflags into `bitflags::Flags` types
     * pointers to lifetimes references
     * Trivial traits and helper methods are added
   Otherwise everything else is left how it is in ngtcp2.
   Some parts of it, mostly about callbacks, are inherently unsafe.
- `ngtcp2-rs`: faithful to ngtcp2, but idiomatic Rust interface. It is still a minimal abstraction, but
   looks and feels like if ngtcp2 was written in Rust.
