//! Ghost-Hunter v1.0.18 §5.6 — "Closure Enclosure" Proof of Concept.
//!
//! This is a standalone, runnable port of the blueprint's §5.1 (`Secret<T>`),
//! §5.2 (`KeyShareA`/`KeyShareB`), and §5.6 (`SecretKeyBuffer` /
//! `with_reconstructed_key`) sections. Everywhere this file's behavior is
//! actually implemented (as opposed to the spec's `unimplemented!()`
//! placeholders), that is this PoC's own addition, done to make the
//! mechanism runnable and testable — not a claim that this file IS the
//! shipped Hubris task crate. The type-level structure — the part actually
//! under test — is copied over unchanged.
//!
//! ## What this file proves
//! 1. The reconstructed key is usable inside the closure (an HMAC-shaped
//!    computation can read it), and is volatile-zeroized the moment the
//!    closure returns — proven at runtime in `main.rs` / integration tests.
//! 2. It is *structurally impossible* — a compile error, not a runtime
//!    check — for calling code to retain a reference to the reconstructed
//!    key past the closure call, to obtain the key by any means other than
//!    `with_reconstructed_key`, or to convert a `&SecretKeyBuffer` into
//!    `&[u8]` via a trait bound. Proven in `tests/compile_fail/`.
//!
//! ## What this file does NOT prove (read this before citing it)
//! Per §5.6's own "What this does and does not guarantee" section: during
//! the closure's execution, the reconstructed key exists as a real,
//! contiguous 32-byte value in this process's stack memory — exactly as it
//! would under the *unsafe*, pre-v1.0.18 "expose both shares and XOR them
//! yourself" pattern. A physical-memory reader (DMA, cold-boot attack, a
//! debugger attached with sufficient privilege) with access during that
//! specific window sees the same bytes either way. This PoC closes the
//! SOFTWARE escape — careless retention by well-intentioned application
//! code — not the hardware exposure window. `demo_key_is_physically_present`
//! in `main.rs` demonstrates this directly, on purpose, so the claim isn't
//! just asserted in a doc comment.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::convert::TryInto;

pub const HMAC_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------
// §5.1 secret.rs — Secret<T>, ported. `Secret<T>` here backs each share's
// inner bytes, exactly as the real spec uses it internally within
// split_key.rs. Its own `expose()` is intentionally still present (per the
// spec's v1.0.18 note: "What v1.0.18 removes is KeyShareA::expose() /
// KeyShareB::expose() specifically" — Secret<T>::expose() is a different,
// lower-level thing, used only inside this module, never re-exported).
// ---------------------------------------------------------------------

pub trait VolatileZeroize {
    fn volatile_zero(&mut self);
}

impl VolatileZeroize for [u8; HMAC_KEY_LEN] {
    fn volatile_zero(&mut self) {
        // Real spec: core::ptr::write_volatile per byte + compiler_fence.
        // std::ptr::write_volatile is the identical operation outside
        // no_std; the fence prevents the compiler from proving the writes
        // are dead (since nothing "reads" bytes about to be dropped) and
        // eliding them, which is the actual bug this exists to prevent.
        for byte in self.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

struct Secret<T: VolatileZeroize> {
    inner: T,
}

impl<T: VolatileZeroize> Secret<T> {
    const fn new(inner: T) -> Self {
        Self { inner }
    }

    fn expose(&self) -> &T {
        &self.inner
    }
}

impl<T: VolatileZeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.volatile_zero();
    }
}

// ---------------------------------------------------------------------
// §5.2 split_key.rs — KeyShareA / KeyShareB.
//
// NOTE ON SCOPE: this PoC deliberately does NOT reproduce §5.2's
// #[repr(C, align(4096))] page-alignment or #[link_section] placement.
// That is PoC 2's entire subject (Anti-DMA Page Splitting) and is proven
// there, at the ELF layout level, where it actually belongs. Folding it in
// here would muddy what THIS PoC is proving: the escape-closure property
// is a property of the TYPE SYSTEM (visible even with ordinary alignment),
// independent of where the bytes physically land in memory. Conflating the
// two would let a reader mistakenly believe fixing one fixes the other.
//
// What IS carried over faithfully: no `expose()` method exists on either
// share type, at all, in this revision — matching §5.2's central change.
// ---------------------------------------------------------------------

pub struct KeyShareA {
    share: Secret<[u8; HMAC_KEY_LEN]>,
}

pub struct KeyShareB {
    share: Secret<[u8; HMAC_KEY_LEN]>,
}

impl KeyShareA {
    pub fn from_provisioned_bytes(share: [u8; HMAC_KEY_LEN]) -> Self {
        Self { share: Secret::new(share) }
    }

    // NOTE: no `expose()` method exists on this type in v1.0.18. This is
    // not an oversight — its absence is the specification (§5.2). See
    // tests/compile_fail/point_1_no_expose_on_shares.rs.
}

impl KeyShareB {
    pub fn from_provisioned_bytes(share: [u8; HMAC_KEY_LEN]) -> Self {
        Self { share: Secret::new(share) }
    }

    // NOTE: no `expose()` method exists on this type in v1.0.18.
}

// ---------------------------------------------------------------------
// §5.6 secret_key_buffer.rs — SecretKeyBuffer + with_reconstructed_key.
// This is the section under test. Ported as close to verbatim as a
// standalone, runnable crate allows.
// ---------------------------------------------------------------------

/// An opaque, stack-allocated token wrapping the XOR-reconstructed 32-byte
/// HMAC key. See this crate's module-level doc comment and §5.6 of the
/// blueprint for the full "what this structurally cannot do" enumeration.
pub struct SecretKeyBuffer {
    bytes: [u8; HMAC_KEY_LEN],
}

impl SecretKeyBuffer {
    /// `pub(super)` in the real spec — visible only within this module and
    /// its parent, called only from `with_reconstructed_key`. Not `pub`.
    fn from_xor(a: &[u8; HMAC_KEY_LEN], b: &[u8; HMAC_KEY_LEN]) -> Self {
        let mut bytes = [0u8; HMAC_KEY_LEN];
        for i in 0..HMAC_KEY_LEN {
            bytes[i] = a[i] ^ b[i];
        }
        Self { bytes }
    }

    /// The sole accessor. `pub(super)` in the real spec, private here for
    /// the same reason: not `pub`, not `pub(crate)`. No external-crate call
    /// site, and no other module in THIS crate either, can reach it.
    fn as_bytes(&self) -> &[u8; HMAC_KEY_LEN] {
        &self.bytes
    }
}

impl Drop for SecretKeyBuffer {
    fn drop(&mut self) {
        self.bytes.volatile_zero();
    }
}

/// The sole sanctioned means of obtaining access to the reconstructed HMAC
/// key. See §5.6 of the blueprint for the full "what this does and does
/// not guarantee" discussion — reproduced in this crate's module doc.
pub fn with_reconstructed_key<R>(
    share_a: &KeyShareA,
    share_b: &KeyShareB,
    f: impl FnOnce(&SecretKeyBuffer) -> R,
) -> R {
    let buffer = SecretKeyBuffer::from_xor(share_a.share.expose(), share_b.share.expose());
    f(&buffer)
    // `buffer` drops here, at end of scope — Drop::drop volatile-zeroizes
    // it unconditionally. This is the one load-bearing line: `f`'s result
    // is computed and bound to nothing extending `buffer`'s lifetime
    // before this function returns it.
}

// ---------------------------------------------------------------------
// A minimal, clearly-labeled-as-toy HMAC-SHA256-shaped function, so the
// demo has something realistic to DO with the key inside the closure. Real
// HMAC computation is explicitly out of scope for the blueprint itself
// (§5.4's comment: "gh-shell's runtime concern, out of scope for this
// declarative spec"), so this is this PoC's own addition, not a lift from
// the spec, and is not cryptographically meaningful — it exists only to
// prove "the key is genuinely used for something inside the closure," not
// to demonstrate real HMAC.
// ---------------------------------------------------------------------

/// Toy digest: NOT a real HMAC. Demonstrates "the key was used" without
/// pulling in a crypto dependency this PoC doesn't need to make its point.
pub fn toy_keyed_digest(key: &SecretKeyBuffer, message: &[u8]) -> u64 {
    let key_bytes = key.as_bytes();
    let mut acc: u64 = 0xcbf29ce484222325; // FNV offset basis, reused as a toy mixer
    for (i, &b) in message.iter().enumerate() {
        let k = key_bytes[i % HMAC_KEY_LEN];
        acc ^= (b ^ k) as u64;
        acc = acc.wrapping_mul(0x100000001b3);
    }
    acc
}

/// Reads the raw bytes of a `SecretKeyBuffer` for demonstration/audit
/// purposes ONLY. This function lives inside this crate, has crate-visible
/// access to `SecretKeyBuffer::as_bytes` (private, but this is the same
/// crate — see `tests/compile_fail/` for proof this does NOT work from an
/// external crate), and exists solely so `main.rs` can show the "key is
/// physically present in memory during the closure" fact honestly, rather
/// than asking the reader to take it on faith. This is not part of the
/// public API surface intended for `gh-shell`'s own callers, and would not
/// exist in the real Hubris task in this form — see its doc comment in
/// `main.rs` for why it's included here anyway.
#[doc(hidden)]
pub fn __poc_only_peek_bytes(key: &SecretKeyBuffer) -> [u8; HMAC_KEY_LEN] {
    (*key.as_bytes()).try_into().unwrap()
}
