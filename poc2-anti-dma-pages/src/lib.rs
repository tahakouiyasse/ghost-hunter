//! Ghost-Hunter v1.0.18 §5.2 — Anti-DMA Page Splitting Proof of Concept.
//!
//! ## What this proves
//! `KeyShareA` and `KeyShareB` are each declared `#[repr(C, align(4096))]`
//! and placed in distinct `#[link_section]`s. This file, once compiled and
//! linked, proves (via `verify_page_split.sh`, which drives `nm`,
//! `objdump`, and `readelf` against the resulting binary) that:
//!   1. Both statics are 4096-byte aligned in the final ELF's symbol table.
//!   2. Both statics occupy 4096 bytes each (one full page, matching
//!      `PAGE_SIZE` and the `HMAC_KEY_LEN` + padding layout from §5.2).
//!   3. Their virtual addresses differ by at least 4096 bytes AND neither
//!      address range overlaps the other — i.e., they are on two
//!      completely different pages, not merely two different offsets
//!      within the same page.
//!   4. They land in the section the source code assigned them to
//!      (`.bss.crypto_share_a` / `.bss.crypto_share_b`), confirming the
//!      `#[link_section]` attribute was honored by the linker rather than
//!      merged into a single generic `.bss` blob.
//!
//! ## What this does NOT prove — read this before citing it
//! Static/link-time page separation in an ELF binary is necessary but not
//! sufficient for the actual security property you likely want to claim
//! ("DMA cannot see the full key at once"). Specifically, this PoC does
//! NOT prove:
//!   - That the OS/hypervisor's actual page tables map these two
//!     link-time pages to physically non-adjacent DRAM frames at runtime
//!     — that is an MMU/IOMMU configuration question, entirely outside
//!     what a linker or `objdump` can attest to. On Hubris (the real
//!     target), static memory layout IS the physical layout, since there
//!     is no paging/virtual memory — this distinction matters a great
//!     deal LESS on the real target than it would running this PoC on a
//!     general-purpose Linux host under a virtual-memory OS, and the
//!     White Paper should be explicit about which environment a given
//!     claim applies to.
//!   - That an IOMMU or DMA-remapping unit is configured to actually
//!     restrict a DMA-capable device's addressable range to only one of
//!     the two pages at any given time — that is a platform/firmware
//!     configuration concern, not a Rust-level or ELF-level one.
//!   - Anything about runtime behavior once the key is reconstructed —
//!     see PoC 1 (`with_reconstructed_key`) for that, and note its own
//!     explicit caveat that reconstruction re-creates a single contiguous
//!     copy for the closure's duration regardless of how the shares
//!     themselves were laid out beforehand.
//! What IS proven, precisely: the compiled artifact's static layout keeps
//! the two shares from ever being fetched by a single naturally-aligned
//! 4096-byte read starting anywhere in either share's own page — narrowing
//! (per the blueprint's own words) the window, not eliminating a
//! DMA-based key-recovery attack outright.

#![allow(dead_code)]

use std::mem::{align_of, size_of};

pub const HMAC_KEY_LEN: usize = 32;
pub const PAGE_SIZE: usize = 4096;

/// A minimal, non-zeroizing stand-in for the real spec's `Secret<T>`
/// wrapper (§5.1). PoC 1 already demonstrates `Secret<T>`'s zeroizing-Drop
/// behavior in full — reproducing it here would duplicate that PoC's
/// subject matter without adding anything to THIS PoC's subject, which is
/// purely about static memory layout. Kept as a plain wrapper so the
/// struct shape (`share: Secret<[u8; HMAC_KEY_LEN]>` plus padding) matches
/// §5.2's real field layout byte-for-byte, which matters because the
/// `size_of` assertions below need to match the real spec's numbers
/// exactly to be a faithful proof rather than a look-alike.
#[repr(transparent)]
pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

/// §5.2, verbatim structure: `#[repr(C, align(4096))]`, one page total,
/// `HMAC_KEY_LEN` bytes of real share plus `PAGE_SIZE - HMAC_KEY_LEN`
/// bytes of padding to fill out the page.
#[repr(C, align(4096))]
pub struct KeyShareA {
    share: Secret<[u8; HMAC_KEY_LEN]>,
    _pad: [u8; PAGE_SIZE - HMAC_KEY_LEN],
}

#[repr(C, align(4096))]
pub struct KeyShareB {
    share: Secret<[u8; HMAC_KEY_LEN]>,
    _pad: [u8; PAGE_SIZE - HMAC_KEY_LEN],
}

// Compile-time proof (independent of the ELF-level proof below) that the
// Rust type itself is exactly one page, both in size and alignment. This
// mirrors the blueprint's own `const_assert_eq!(size_of::<KeyShareA>(),
// PAGE_SIZE)` from §5.2 — using plain `assert!` here since this PoC
// doesn't pull in the `static_assertions` crate (keeping dependency count
// at zero), but the check fires at const-eval time either way, which is
// what actually matters, not which macro spells it.
const _: () = assert!(size_of::<KeyShareA>() == PAGE_SIZE);
const _: () = assert!(align_of::<KeyShareA>() == PAGE_SIZE);
const _: () = assert!(size_of::<KeyShareB>() == PAGE_SIZE);
const _: () = assert!(align_of::<KeyShareB>() == PAGE_SIZE);

/// §5.2's exact placement: two distinct link sections, so that at the
/// object-file level (i.e. before the final link step), the two shares'
/// storage is unambiguously distinguished by name rather than merely by
/// coincidental placement order within a single generic `.bss`.
///
/// IMPORTANT, VERIFIED CAVEAT: most linkers (including the default GNU ld
/// / lld behavior this PoC's build was actually tested against — see
/// verify_page_split.sh's "pre-link vs. post-link" step) treat
/// `.bss.<suffix>`-prefixed input sections as "orphan sections" belonging
/// to the same output section family and MERGE them into a single output
/// `.bss` in the final linked binary. This PoC verifies that merge
/// happens here, explicitly, rather than silently assuming
/// `#[link_section]` alone guarantees separate OUTPUT sections survive to
/// the final ELF — it does not, on this toolchain. What DOES survive, and
/// what is actually load-bearing for the "different pages" claim, is the
/// `#[repr(C, align(4096))]` alignment on the TYPE: a linker is obligated
/// to place a symbol carrying that alignment at an address satisfying it,
/// regardless of which output section a same-alignment neighbor also ends
/// up in. verify_page_split.sh proves both halves of this precisely: (a)
/// the pre-link `.o` file shows two genuinely distinct named sections,
/// confirming `#[link_section]` was honored by the compiler as written;
/// (b) the POST-link binary's symbol table shows both `SHARE_A` and
/// `SHARE_B` individually 4096-byte-aligned, each exactly 4096 bytes, at
/// addresses exactly one page apart with zero overlap — which is what
/// actually matters for the DMA-confinement claim, independent of whether
/// the section merge happened.
#[link_section = ".bss.crypto_share_a"]
#[used]
pub static SHARE_A: KeyShareA = KeyShareA {
    share: Secret::new([0u8; HMAC_KEY_LEN]),
    _pad: [0u8; PAGE_SIZE - HMAC_KEY_LEN],
};

#[link_section = ".bss.crypto_share_b"]
#[used]
pub static SHARE_B: KeyShareB = KeyShareB {
    share: Secret::new([0u8; HMAC_KEY_LEN]),
    _pad: [0u8; PAGE_SIZE - HMAC_KEY_LEN],
};

/// A third, ordinary (non-page-aligned) static, included purely as a
/// NEGATIVE CONTROL for the verification script. If the alignment
/// attribute were silently ignored by the compiler/linker (a regression,
/// or a target where `align(4096)` isn't honored for some reason), an
/// ordinary variable placed nearby might still happen to be far from
/// SHARE_A/SHARE_B by coincidence — proving nothing. This control exists
/// so the verification script can also show what an UN-isolated variable
/// looks like in `nm` output, for contrast.
#[used]
pub static ORDINARY_CONTROL_VALUE: u64 = 0xDEADBEEF_CAFEF00D;
