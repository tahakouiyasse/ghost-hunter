// §8.11 point 3: SecretKeyBuffer has no accessor visible from this
// external-crate vantage point that would let even a legitimately-obtained
// `&SecretKeyBuffer` be converted into a `&[u8]` or `[u8; 32]` through a
// generic conversion trait. `as_bytes()` exists, but it is private to
// `poc1_closure_enclosure`'s own internals (not `pub`, not `pub(crate)`
// re-exported) — so external code has no NAMED path to it, and (this test)
// no GENERIC path to it either, since SecretKeyBuffer deliberately
// implements none of AsRef<[u8]>, Deref<Target = [u8]>, Borrow<[u8]>, or
// Into<[u8; 32]>.

use poc1_closure_enclosure::{with_reconstructed_key, KeyShareA, KeyShareB};

fn main() {
    let a = KeyShareA::from_provisioned_bytes([0u8; 32]);
    let b = KeyShareB::from_provisioned_bytes([0u8; 32]);

    let _sum: u8 = with_reconstructed_key(&a, &b, |buf| {
        // Attempt: reach the raw bytes through a generic conversion trait
        // instead of a named accessor, since SecretKeyBuffer has no pub
        // accessor reachable from this external-crate call site.
        let raw: &[u8] = buf.as_ref(); // EXPECTED COMPILE ERROR: the trait
                                       // bound `SecretKeyBuffer: AsRef<[u8]>`
                                       // is not satisfied — no such impl
                                       // exists.
        raw.iter().fold(0u8, |acc, b| acc ^ b)
    });
}
