//! Ghost-Hunter §3.2 — "The Laser" fault-injection simulation.
//!
//! Run with: cargo run --release
//!
//! Simulates a single-event-upset-class fault (voltage glitch, laser fault
//! injection, cosmic-ray bit flip) landing on the raw, on-the-wire `u32`
//! representing a `GlitchResistantBool` — the exact scenario §3.2 exists to
//! defend against: an adversary with physical access to the device, able
//! to induce a single-bit fault during the verification check's execution
//! or transmission, attempting to flip a `False` (fail) result into a
//! `True` (pass) result.
//!
//! For BOTH starting sentinels (True and False), this runs 100,000
//! independent trials. Each trial:
//!   1. Starts from the known-good raw u32 (0x5A5A5A5A or 0xA5A5A5A5).
//!   2. The laser flips exactly one pseudorandomly chosen bit (0..=31).
//!   3. The corrupted u32 is fed through `GlitchResistantBool::try_from`,
//!      the ONLY sanctioned decode path — exactly as real verification
//!      code is required to do.
//!   4. The outcome is classified into one of three buckets:
//!        - SAFE_UNDEFINED:      correctly rejected as Err(Undefined).
//!        - SAFE_UNCHANGED:      the flip produced the SAME sentinel it
//!                                started from (impossible for a REAL
//!                                single-bit flip against either of these
//!                                two specific sentinels, since flipping
//!                                any 1 of 32 bits necessarily changes the
//!                                value — included only as a defensive
//!                                classification bucket, not because this
//!                                PoC expects to ever see it happen).
//!        - CRITICAL_BYPASS:     the flip silently produced the OTHER
//!                                defined sentinel (True<->False) without
//!                                going through Err(Undefined) — this is
//!                                the exact failure mode this type exists
//!                                to make impossible. If this bucket is
//!                                EVER non-zero, across ANY of the
//!                                200,000 total trials, this PoC's central
//!                                claim is falsified and it says so loudly.
//!
//! This binary's exit code is 0 if and only if CRITICAL_BYPASS was zero
//! across all trials, both directions. A non-zero exit code means the
//! central security property did NOT hold and must be treated as a
//! fatal, reportable failure of the underlying type — not a flaky test.

use poc3_fault_injection::{GlitchDecodeError, GlitchResistantBool, XorShift32};
use std::convert::TryFrom;
use std::process::ExitCode;

const TRIALS_PER_DIRECTION: u32 = 100_000;

#[derive(Debug, Default)]
struct TrialResults {
    safe_undefined: u32,
    safe_unchanged: u32,
    critical_bypass: u32,
    // bit_index -> count, so we can show the distribution was genuinely
    // varied and not accidentally hitting the same bit every time.
    bit_index_histogram: [u32; 32],
}

fn run_trials(starting_raw: u32, starting_label: &str, seed: u32) -> TrialResults {
    let mut rng = XorShift32::new(seed);
    let mut results = TrialResults::default();

    for _ in 0..TRIALS_PER_DIRECTION {
        let bit_index = rng.next_below(32);
        let corrupted_raw = starting_raw ^ (1u32 << bit_index);
        results.bit_index_histogram[bit_index as usize] += 1;

        match GlitchResistantBool::try_from(corrupted_raw) {
            Err(GlitchDecodeError::Undefined) => {
                results.safe_undefined += 1;
            }
            Ok(decoded) => {
                let started_as_true = starting_raw == GlitchResistantBool::True as u32;
                let decoded_as_true = decoded == GlitchResistantBool::True;
                if started_as_true == decoded_as_true {
                    // Decoded to the SAME value it started as. For a
                    // genuine single-bit flip against either sentinel this
                    // is mathematically impossible (see the Hamming-
                    // distance-32 const-assertion in lib.rs) — flipping
                    // any 1 of 32 differing bits necessarily produces a
                    // DIFFERENT 32-bit value, and the only two DEFINED
                    // values are 32 bits apart in every position. This
                    // branch exists purely as a defensive classification
                    // bucket; reaching it would itself indicate something
                    // is wrong with the corruption logic in THIS PoC, not
                    // with GlitchResistantBool.
                    results.safe_unchanged += 1;
                } else {
                    // THE FAILURE MODE THIS TYPE EXISTS TO PREVENT: a
                    // single-bit flip silently produced the OTHER defined
                    // sentinel without ever surfacing as Err(Undefined).
                    results.critical_bypass += 1;
                    eprintln!(
                        "!!! CRITICAL BYPASS DETECTED !!! starting={} (0x{:08X}) \
                         bit_flipped={} corrupted=0x{:08X} decoded_as={:?}",
                        starting_label, starting_raw, bit_index, corrupted_raw, decoded
                    );
                }
            }
        }
    }

    results
}

fn print_results(label: &str, starting_raw: u32, results: &TrialResults) {
    println!("--- Starting sentinel: {} (0x{:08X}) ---", label, starting_raw);
    println!("  Trials run:                {}", TRIALS_PER_DIRECTION);
    println!(
        "  Correctly rejected (Undefined): {} ({:.4}%)",
        results.safe_undefined,
        100.0 * results.safe_undefined as f64 / TRIALS_PER_DIRECTION as f64
    );
    println!(
        "  Decoded unchanged (defensive bucket, expected 0): {}",
        results.safe_unchanged
    );
    println!(
        "  *** CRITICAL BYPASS (silently became the other value): {} ***",
        results.critical_bypass
    );

    // Sanity-check the distribution: with 100,000 trials across 32 bit
    // positions, uniform selection should land ~3,125 per bit. Print the
    // min/max to show the randomization wasn't degenerate (e.g. always
    // picking bit 0), which would make "100,000 trials" a misleading
    // claim about coverage even if the pass/fail result were correct.
    let min = results.bit_index_histogram.iter().min().unwrap();
    let max = results.bit_index_histogram.iter().max().unwrap();
    let expected = TRIALS_PER_DIRECTION as f64 / 32.0;
    println!(
        "  Bit-index coverage: min={} max={} (expected ~{:.0} each, uniform)",
        min, max, expected
    );
    println!();
}

fn main() -> ExitCode {
    println!("=== Ghost-Hunter §3.2 — Fault-Injection Immunity PoC ===");
    println!("=== \"The Laser\" — {} single-bit-flip trials per direction ===\n", TRIALS_PER_DIRECTION);

    println!(
        "GlitchResistantBool::True  = 0x{:08X}",
        GlitchResistantBool::True as u32
    );
    println!(
        "GlitchResistantBool::False = 0x{:08X}",
        GlitchResistantBool::False as u32
    );
    println!(
        "Hamming distance between them: {} (maximum possible for 32 bits)\n",
        poc3_fault_injection::hamming_distance(
            GlitchResistantBool::True as u32,
            GlitchResistantBool::False as u32
        )
    );

    let results_from_true = run_trials(
        GlitchResistantBool::True as u32,
        "True",
        0x1234_5678,
    );
    print_results("True", GlitchResistantBool::True as u32, &results_from_true);

    let results_from_false = run_trials(
        GlitchResistantBool::False as u32,
        "False",
        0x9E37_79B9, // different seed, independent trial stream
    );
    print_results("False", GlitchResistantBool::False as u32, &results_from_false);

    let total_trials = TRIALS_PER_DIRECTION * 2;
    let total_bypass = results_from_true.critical_bypass + results_from_false.critical_bypass;
    let total_undefined = results_from_true.safe_undefined + results_from_false.safe_undefined;

    println!("=== FINAL SUMMARY ===");
    println!("Total trials (both directions):     {}", total_trials);
    println!("Total correctly rejected (Undefined): {}", total_undefined);
    println!("Total CRITICAL BYPASSES:              {}", total_bypass);
    println!();

    if total_bypass == 0 {
        println!(
            "RESULT: PASS. Across {} independent single-bit-flip trials, \
             GlitchResistantBool::try_from NEVER silently decoded a corrupted \
             sentinel into the other valid value. Every single-bit fault was \
             either correctly surfaced as Err(GlitchDecodeError::Undefined).",
            total_trials
        );
        println!();
        println!(
            "SCOPE REMINDER: this proves the DECODE-TIME property only — see \
             this crate's lib.rs module doc for what this does NOT prove \
             (post-decode register/memory fault coverage, which is a hardware \
             concern out of scope for this type, per §3.2 of the blueprint)."
        );
        println!();
        demonstrate_naive_encoding_vulnerability();
        ExitCode::SUCCESS
    } else {
        println!(
            "RESULT: FAIL. {} out of {} trials produced a CRITICAL BYPASS — \
             a single-bit fault silently flipped a valid sentinel into the \
             OTHER valid sentinel without surfacing as an error. This would \
             mean GlitchResistantBool's central security claim does not \
             hold and must be treated as a serious, reportable defect.",
            total_bypass, total_trials
        );
        ExitCode::FAILURE
    }
}

/// NOT part of GlitchResistantBool's proof — a separate, clearly-labeled
/// negative-control demonstration of the exact vulnerability class §3.2's
/// doc comment describes as the motivation for this whole mechanism:
/// "Ordinary bool/u8 True/False encodings (e.g. 1 and 0) sit one bit
/// apart — a single stuck-at or single-bit-flip fault can silently turn a
/// False result into True." This function shows that claim is not just
/// asserted prose but a reproducible fact, using the SAME laser and the
/// SAME 100,000-trial methodology, applied to a naive 0/1 encoding instead
/// of GlitchResistantBool.
fn demonstrate_naive_encoding_vulnerability() {
    println!("=== Negative control: the vulnerability class this type closes ===");
    println!("Applying the identical laser (100,000 single-bit-flip trials) to a");
    println!("NAIVE encoding — False=0u32, True=1u32 — instead of GlitchResistantBool:\n");

    let mut rng = XorShift32::new(0xC0FF_EE00);
    let mut naive_bypass_count = 0u32;
    const NAIVE_FALSE: u32 = 0;

    for _ in 0..TRIALS_PER_DIRECTION {
        let bit_index = rng.next_below(32);
        let corrupted = NAIVE_FALSE ^ (1u32 << bit_index);
        // A naive system reading this as "nonzero == true" (an extremely
        // common, ordinary pattern) would treat ANY nonzero corrupted
        // value as True -- including every one of these 32 possible
        // single-bit flips away from 0, since every one of them is
        // nonzero.
        let naively_decoded_as_true = corrupted != 0;
        if naively_decoded_as_true {
            naive_bypass_count += 1;
        }
    }

    println!(
        "  Naive encoding: {} / {} single-bit flips of False silently read as True",
        naive_bypass_count, TRIALS_PER_DIRECTION
    );
    println!(
        "  ({:.1}% silent bypass rate under the exact same fault model.)",
        100.0 * naive_bypass_count as f64 / TRIALS_PER_DIRECTION as f64
    );
    println!();
    println!("  This is why the comparison matters: GlitchResistantBool's 0%");
    println!("  bypass rate above isn't 'inherently what any bool type would do'");
    println!("  -- it is a direct, measurable consequence of choosing True/False as");
    println!("  exact 32-bit complements, which the naive encoding above does not.");
}
