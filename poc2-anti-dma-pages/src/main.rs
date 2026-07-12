//! Minimal binary whose only purpose is to force the linker to place
//! `SHARE_A`, `SHARE_B`, and `ORDINARY_CONTROL_VALUE` into a real, final
//! ELF executable with resolved virtual addresses — a bare `rlib`/
//! `staticlib` alone doesn't go through the final link step, and it's the
//! FINAL LINKED BINARY's layout that actually matters for a DMA-based
//! attack (a `.o` file's section layout is not what a physical memory
//! reader ever sees).
//!
//! `std::hint::black_box` prevents the optimizer from proving these
//! statics are provably-dead (unread) and eliding them from the binary
//! entirely — Fat-LTO at `opt-level = "s"` is aggressive enough to do
//! exactly that if given no reason not to, which would silently make this
//! whole PoC pass by testing a binary that doesn't contain what we claim
//! it contains.

use poc2_anti_dma_pages::{ORDINARY_CONTROL_VALUE, SHARE_A, SHARE_B};

fn main() {
    // Reading through black_box, not printing the actual key bytes — this
    // binary's job is to exist and be linked, not to leak anything. (These
    // are zero-initialized placeholder shares in this PoC in any case; see
    // lib.rs — no real key material is embedded here.)
    let a_addr = std::hint::black_box(&SHARE_A) as *const _ as usize;
    let b_addr = std::hint::black_box(&SHARE_B) as *const _ as usize;
    let c_addr = std::hint::black_box(&ORDINARY_CONTROL_VALUE) as *const _ as usize;

    println!("SHARE_A address:              0x{:x}", a_addr);
    println!("SHARE_B address:               0x{:x}", b_addr);
    println!("ORDINARY_CONTROL_VALUE address: 0x{:x}", c_addr);
    println!();
    println!("(Run ./verify_page_split.sh for the full ELF-level proof —");
    println!(" this program's own printed addresses are a runtime sanity");
    println!(" check, not the proof itself. The proof needs static ELF");
    println!(" inspection via nm/objdump/readelf, run against the compiled");
    println!(" binary independent of any particular execution's ASLR slide.)");
}
