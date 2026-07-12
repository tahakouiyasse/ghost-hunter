// §8.11 point 1: KeyShareA/KeyShareB have no expose() method at all.
// This is the v1.0.17 -> v1.0.18 change itself: expose() was deleted, not
// hidden. Calling it from ANY code, including this external-crate test,
// must be a compile error — "method not found," not a privacy error, since
// there is no such method anywhere in this revision to be private.

use poc1_closure_enclosure::{KeyShareA, KeyShareB};

fn main() {
    let a = KeyShareA::from_provisioned_bytes([0u8; 32]);
    let b = KeyShareB::from_provisioned_bytes([0u8; 32]);

    let _ = a.expose(); // EXPECTED COMPILE ERROR: no method named `expose`
                        // found for struct `KeyShareA` in the current scope
    let _ = b.expose(); // EXPECTED COMPILE ERROR: same, for KeyShareB
}
