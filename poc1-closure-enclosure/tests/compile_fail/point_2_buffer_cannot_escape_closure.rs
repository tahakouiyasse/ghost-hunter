// §8.11 point 2: SecretKeyBuffer cannot be returned out of
// with_reconstructed_key's closure, because its lifetime is tied to the
// reference the closure receives (which is itself tied to
// with_reconstructed_key's own stack frame), not to an owned value the
// closure could hand back. This is THE central guarantee of §5.6 — if this
// compiled, the entire closure-enclosure design would be pointless, since
// any caller could just return the reference and hold it indefinitely.

use poc1_closure_enclosure::{with_reconstructed_key, KeyShareA, KeyShareB, SecretKeyBuffer};

fn main() {
    let a = KeyShareA::from_provisioned_bytes([0u8; 32]);
    let b = KeyShareB::from_provisioned_bytes([0u8; 32]);

    let _escaped: &SecretKeyBuffer = with_reconstructed_key(&a, &b, |buf| {
        buf // EXPECTED COMPILE ERROR: lifetime may not live long enough —
            // "returning this value requires that `'1` must outlive `'2`".
            // `buf`'s lifetime is scoped to with_reconstructed_key's own
            // stack frame; the borrow checker rejects this because
            // with_reconstructed_key's signature returns `R` by value with
            // no lifetime tying it back to `buf`'s scope.
            //
            // NOTE: this file deliberately does nothing with `_escaped`
            // after this point (no println!, no further use). The point
            // of this file is that the ASSIGNMENT above already fails to
            // compile on its own — adding a use of `_escaped` afterward
            // would risk masking that with an unrelated second error
            // (e.g. a missing Debug impl) and make it unclear which
            // failure is actually doing the enforcement. One error, one
            // cause: that's what verify_compile_fail.sh checks for.
    });
}
