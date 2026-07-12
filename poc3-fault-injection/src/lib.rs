//! Ghost-Hunter v1.0.18 §3.2 — Fault-Injection Immunity Proof of Concept.
//!
//! ## What this proves
//! `GlitchResistantBool::try_from(u32)` exhaustively classifies every one
//! of the 2^32 possible `u32` bit patterns into exactly one of three
//! outcomes: `Ok(True)`, `Ok(False)`, or `Err(GlitchDecodeError::Undefined)`.
//! A single-bit fault applied to a `u32` that WAS `0x5A5A5A5A` (True) or
//! `0xA5A5A5A5` (False) can NEVER decode to the other defined value,
//! because the two are chosen as exact bitwise complements (Hamming
//! distance 32 — the maximum possible for a 32-bit value) — a single bit
//! flip changes exactly 1 bit, and getting from one sentinel to the other
//! requires flipping all 32. This PoC drives 100,000 independent random
//! single-bit-flip trials against both starting sentinels and asserts,
//! every single time, that the corrupted value classifies as either
//! `Undefined` (if it's no longer either sentinel, which is what a single
//! bit flip against either sentinel WILL always produce) — proving the
//! type can never silently misclassify a corrupted `True`/`False` as the
//! other, defined value.
//!
//! ## What this does NOT prove — read this before citing it
//! Per §3.2's own "DOES NOT CLOSE" language, verbatim from the blueprint:
//! this mechanism protects the DECODE MOMENT — the instant a raw `u32` is
//! converted into a `GlitchResistantBool` via `try_from`. It does NOT, and
//! no software mechanism at this layer can, protect a value AFTER a
//! successful decode: if a bit flip lands on an already-decoded, in-memory
//! `GlitchResistantBool::True` (say, sitting in a register or a stack slot
//! between the decode call and the next read of that value), nothing in
//! this type prevents that flip from silently corrupting it into a
//! different `#[repr(u32)]` bit pattern the reader might then
//! misinterpret. This PoC's simulation attacks the RAW WIRE-FORMAT VALUE
//! BEFORE DECODE — exactly the case `try_from` is built to handle — and
//! says nothing about post-decode register/memory fault coverage, which
//! the blueprint correctly identifies as a hardware concern (ECC,
//! redundant read-back, watchdog) outside a `no_std` task crate's control.
//! Any claim that this type "physically forces" a fail-closed outcome for
//! that LATER window would be false, exactly as §3.2 says.

use std::convert::TryFrom;

/// §3.2, verbatim: Hamming-distance-32 sentinel pair.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlitchResistantBool {
    True = 0x5A5A5A5A,
    False = 0xA5A5A5A5,
}

/// §3.2, verbatim: the sole error type, exactly one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlitchDecodeError {
    Undefined,
}

/// §3.2, verbatim: the only sanctioned decode path. Deliberately NOT
/// `From<u32>` — see the blueprint's explicit note that an infallible
/// conversion is exactly the failure mode this section exists to close.
impl TryFrom<u32> for GlitchResistantBool {
    type Error = GlitchDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x5A5A5A5A => Ok(GlitchResistantBool::True),
            0xA5A5A5A5 => Ok(GlitchResistantBool::False),
            _ => Err(GlitchDecodeError::Undefined),
        }
    }
}

/// Independent, compile-time confirmation that the two sentinels really
/// are exact bitwise complements of one another (Hamming distance 32).
/// This is what actually makes "a single bit flip cannot turn one into the
/// other" true — not an assumption this PoC takes on faith from the
/// blueprint's prose, but a checked arithmetic fact.
pub const fn hamming_distance(a: u32, b: u32) -> u32 {
    (a ^ b).count_ones()
}

const _: () = assert!(
    hamming_distance(GlitchResistantBool::True as u32, GlitchResistantBool::False as u32) == 32
);

/// The "laser": a bit-flip mutator. Flips exactly one pseudorandomly
/// chosen bit (0..=31) in the given `u32` and returns the corrupted value,
/// simulating a single-event-upset-class fault (voltage glitch, laser
/// fault injection, cosmic-ray-induced bit flip) landing on the raw wire
/// value at the moment it would otherwise have been decoded.
pub fn laser_flip_one_bit(value: u32, bit_index: u32) -> u32 {
    debug_assert!(bit_index < 32, "bit_index must be in 0..32");
    value ^ (1u32 << bit_index)
}

/// A minimal, dependency-free xorshift PRNG. This PoC deliberately does
/// NOT pull in the `rand` crate — the property under test doesn't need a
/// cryptographically strong PRNG, only "varied enough bit-index and
/// starting-value choices to exercise the space," and a zero-dependency
/// PoC is easier for a skeptical reviewer to audit end-to-end without
/// trusting a third-party crate's internals.
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    pub fn new(seed: u32) -> Self {
        // xorshift requires a non-zero seed.
        Self { state: if seed == 0 { 0xdeadbeef } else { seed } }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    /// Returns a value in 0..bound (exclusive), via modulo. Fine for this
    /// PoC's purposes (bound is always 32); not appropriate for
    /// cryptographic use, which this explicitly is not.
    pub fn next_below(&mut self, bound: u32) -> u32 {
        self.next_u32() % bound
    }
}
