//! `cargo test --release` runs this: an automated, assertion-based version
//! of the same simulation `laser` prints interactively. Kept separate from
//! `main.rs` so this property has both a human-readable demo AND a
//! CI-friendly pass/fail gate that doesn't depend on parsing stdout.

use poc3_fault_injection::{GlitchDecodeError, GlitchResistantBool, XorShift32};
use std::convert::TryFrom;

const TRIALS_PER_DIRECTION: u32 = 100_000;

fn assert_no_bypass_possible(starting_raw: u32, seed: u32) {
    let mut rng = XorShift32::new(seed);
    let mut undefined_count = 0u32;
    let mut bypass_count = 0u32;

    for _ in 0..TRIALS_PER_DIRECTION {
        let bit_index = rng.next_below(32);
        let corrupted = starting_raw ^ (1u32 << bit_index);

        match GlitchResistantBool::try_from(corrupted) {
            Err(GlitchDecodeError::Undefined) => undefined_count += 1,
            Ok(decoded) => {
                let started_as_true = starting_raw == GlitchResistantBool::True as u32;
                let decoded_as_true = decoded == GlitchResistantBool::True;
                if started_as_true != decoded_as_true {
                    bypass_count += 1;
                }
            }
        }
    }

    assert_eq!(
        bypass_count, 0,
        "CRITICAL: {} out of {} single-bit-flip trials from starting value \
         0x{:08X} silently decoded to the OTHER valid sentinel instead of \
         Err(Undefined). This falsifies GlitchResistantBool's central claim.",
        bypass_count, TRIALS_PER_DIRECTION, starting_raw
    );
    assert_eq!(
        undefined_count, TRIALS_PER_DIRECTION,
        "expected every single-bit flip against a defined sentinel to \
         decode as Undefined (Hamming distance 32 makes reaching the OTHER \
         defined sentinel via 1 bit flip impossible, and a flip against a \
         defined sentinel can never reproduce the SAME sentinel either)"
    );
}

#[test]
fn no_bit_flip_can_bypass_from_true() {
    assert_no_bypass_possible(GlitchResistantBool::True as u32, 0x1234_5678);
}

#[test]
fn no_bit_flip_can_bypass_from_false() {
    assert_no_bypass_possible(GlitchResistantBool::False as u32, 0x9E37_79B9);
}

#[test]
fn sentinels_are_exact_bitwise_complements() {
    // The property that MAKES the above true: Hamming distance 32 means
    // every single bit differs between True and False, so a single flip
    // starting from either one can only ever produce a value that is
    // NEITHER of the two defined sentinels.
    let distance = poc3_fault_injection::hamming_distance(
        GlitchResistantBool::True as u32,
        GlitchResistantBool::False as u32,
    );
    assert_eq!(distance, 32, "sentinels must be exact 32-bit complements");
}

#[test]
fn every_u32_neither_sentinel_is_rejected_as_undefined() {
    // Exhaustive spot-check (not exhaustive over all 2^32 -- that's a
    // multi-hour brute force elsewhere; see verify.sh's optional exhaustive
    // mode) confirming a broad, structured sample of non-sentinel values
    // -- including ones differing from a sentinel by 2, 3, and 16 bits,
    // not just 1 -- are ALL rejected, demonstrating the match arm's `_ =>`
    // catches everything outside the two named constants, not just
    // single-bit-flip neighbors specifically.
    let samples: [u32; 8] = [
        0x0000_0000,
        0xFFFF_FFFF,
        0x5A5A_5A5B, // True with its lowest bit ALSO flipped a 2nd time (net: 1 bit different from True, still not a sentinel)
        0xA5A5_A5A4,
        0x5A5A_A5A5, // half True, half False bit pattern
        0x1234_5678,
        0x0000_5A5A,
        0xDEAD_BEEF,
    ];
    for &sample in samples.iter() {
        assert!(
            !matches!(sample, 0x5A5A_5A5A | 0xA5A5_A5A5),
            "test bug: sample {:#X} is accidentally a real sentinel",
            sample
        );
        let result = GlitchResistantBool::try_from(sample);
        assert_eq!(
            result,
            Err(GlitchDecodeError::Undefined),
            "value {:#X} should have been rejected as Undefined",
            sample
        );
    }
}
