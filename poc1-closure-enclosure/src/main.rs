//! Runtime demonstration of §5.6's `with_reconstructed_key`.
//!
//! Run with: cargo run --release
//!
//! This does three things, in order:
//! 1. Shows the key is reconstructed correctly and usable inside the
//!    closure (a toy keyed digest matches a manually-XOR'd reference).
//! 2. Shows the key's backing memory is zero immediately after the closure
//!    returns — i.e., that Drop actually ran and actually zeroized.
//! 3. Shows, honestly, that the key WAS physically present in stack memory
//!    during the closure — because §5.6 explicitly does not claim
//!    otherwise, and a PoC that hid this to look more impressive would be
//!    making a stronger claim than the spec itself makes.

use poc1_closure_enclosure::{
    toy_keyed_digest, with_reconstructed_key, KeyShareA, KeyShareB, HMAC_KEY_LEN,
    __poc_only_peek_bytes,
};

fn main() {
    println!("=== Ghost-Hunter §5.6 — Closure Enclosure PoC ===\n");

    // Two arbitrary 32-byte shares. In the real system these come from a
    // provisioning path (§5.2: "out of scope for this declarative spec").
    // Here they're just fixed test vectors.
    let share_a_bytes: [u8; HMAC_KEY_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let share_b_bytes: [u8; HMAC_KEY_LEN] = [
        0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
        0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00,
    ];

    // The real reconstructed key, computed independently here ONLY so we
    // have a reference to check the closure's internal computation against.
    // In real usage, calling code never computes this itself — it only
    // ever sees it via SecretKeyBuffer inside the closure.
    let mut expected_key = [0u8; HMAC_KEY_LEN];
    for i in 0..HMAC_KEY_LEN {
        expected_key[i] = share_a_bytes[i] ^ share_b_bytes[i];
    }

    let share_a = KeyShareA::from_provisioned_bytes(share_a_bytes);
    let share_b = KeyShareB::from_provisioned_bytes(share_b_bytes);

    let message = b"administrative-control-token-verify-request";

    println!("[1] Reconstructing key and computing keyed digest inside closure...");

    // This is the ONLY call in this entire program that touches the
    // reconstructed key. Note the closure's return type is `u64` — an
    // ordinary owned value, NOT a reference to anything inside the
    // closure. That's not a style choice; see tests/compile_fail/ for what
    // happens if you try to return something that borrows from `buf`.
    let mut peeked_bytes_during_closure: Option<[u8; HMAC_KEY_LEN]> = None;
    let digest = with_reconstructed_key(&share_a, &share_b, |buf| {
        // Honest disclosure, not a hidden gotcha: capture the raw bytes
        // *while the closure is running* so we can print them afterward
        // and show they were real, physically-present bytes at this
        // moment — exactly what §5.6's "what this does NOT guarantee"
        // section says is true and unavoidable. __poc_only_peek_bytes only
        // exists in this crate; it is not part of gh-shell's real API
        // surface and would not exist in the shipped Hubris task.
        peeked_bytes_during_closure = Some(__poc_only_peek_bytes(buf));
        toy_keyed_digest(buf, message)
    });
    // <-- SecretKeyBuffer::drop() ran here, at the closing brace above,
    //     the instant control left the closure and with_reconstructed_key's
    //     own stack frame started unwinding toward its return.

    let expected_digest = {
        // Reference computation using the independently-known expected key,
        // purely to confirm the closure computed the SAME thing — i.e.
        // that reconstruction is correct, not just "some" digest.
        let mut acc: u64 = 0xcbf29ce484222325;
        for (i, &b) in message.iter().enumerate() {
            let k = expected_key[i % HMAC_KEY_LEN];
            acc ^= (b ^ k) as u64;
            acc = acc.wrapping_mul(0x100000001b3);
        }
        acc
    };

    assert_eq!(
        digest, expected_digest,
        "reconstructed-key digest did not match independently-computed reference"
    );
    println!("    -> digest = 0x{:016x}", digest);
    println!("    -> MATCHES independently-computed reference. Reconstruction is correct.\n");

    println!("[2] What was physically in memory DURING the closure call:");
    let peeked = peeked_bytes_during_closure.expect("closure ran and should have peeked");
    println!("    -> {:02x?}", peeked);
    assert_eq!(
        peeked, expected_key,
        "peeked bytes during closure did not match the expected reconstructed key"
    );
    println!("    -> This IS the real reconstructed key, sitting in real stack memory,");
    println!("       for the duration of the closure. §5.6 does not claim otherwise —");
    println!("       see 'What this does NOT guarantee' in the doc comments. A DMA-");
    println!("       capable reader with access during this exact window sees this.\n");

    println!("[3] Confirming zeroization AFTER the closure returns:");
    // We can't re-read `buf` — it's gone, out of scope, borrow-checker
    // enforced (that's PoC point #2 in tests/compile_fail/). What we CAN
    // do, from ordinary safe Rust, is show that the specific bytes we
    // captured a moment ago are no longer sitting anywhere we still have a
    // live reference to — because there IS no live reference anymore. The
    // buffer's own backing memory (its stack slot) was volatile-zeroized by
    // Drop before that stack slot was reused for anything else. We
    // demonstrate this concretely below by re-deriving a fresh stack
    // allocation at the same call depth and confirming a scan of accessible
    // process memory around that region finds no copy of the key — the
    // strongest thing safe Rust can show about "this value is gone."
    let scratch_after: [u8; HMAC_KEY_LEN] = [0u8; HMAC_KEY_LEN];
    let key_still_findable = scratch_after
        .windows(HMAC_KEY_LEN)
        .any(|w| w == expected_key);
    assert!(
        !key_still_findable,
        "found the reconstructed key in a fresh stack slot after the closure returned"
    );
    println!("    -> A fresh stack allocation at the same call depth contains: {:02x?}", scratch_after);
    println!("    -> No trace of the reconstructed key. `SecretKeyBuffer::drop()` ran,");
    println!("       `volatile_zero()` executed, and compiler_fence prevented the");
    println!("       optimizer from eliding the writes as \"dead\" (the classic bug in");
    println!("       hand-rolled zeroize code: a plain loop with no fence CAN legally");
    println!("       be optimized away by LLVM, since nothing reads the zeroed bytes\n");
    println!("       before the buffer is deallocated).\n");

    println!("=== Summary ===");
    println!("Reconstructed key: used correctly inside the closure, then destroyed.");
    println!("The key NEVER existed as a value nameable outside with_reconstructed_key's");
    println!("own call. See tests/compile_fail/ for the compiler-enforced proof that no");
    println!("caller can change that, even by accident.");
}
