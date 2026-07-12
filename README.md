# Ghost-Hunter — Standalone Proofs of Concept

These three crates are independent, standard-Rust demonstrations of three
specific mechanisms from `WORKSPACE_STRUCTURE_HUBRIS.md`. None of
them require the Hubris microkernel, the reference N4500 hardware, or a
cross-compilation toolchain — each runs on any Linux machine with a stable
Rust compiler (developed and verified against `rustc 1.75.0`).

**What these are:** faithful, runnable ports of the exact type definitions
and mechanisms specified in the sections below, extended only where needed
to make them independently compilable and runnable (e.g. swapping `no_std`
for `std` where the mechanism itself doesn't depend on that distinction).

**What these are not:** the shipped Hubris task crates. Building those is a
separate, larger undertaking the blueprint itself describes as not yet
done (see the blueprint's closing line: *"Every `unimplemented!()` in this
document marks a point where real, non-declarative engineering remains
before any claim depending on that function's behavior... is fully earned
rather than architecturally prepared for."*). These PoCs earn the specific,
narrow claims listed below — nothing more, and each README/doc-comment
says explicitly what is and is not proven.

## PoC 1 — `poc1-closure-enclosure/` (proves §5.6)

`SecretKeyBuffer` and `with_reconstructed_key`: proves the reconstructed
HMAC key can be used inside a closure and is volatile-zeroized the instant
the closure returns, AND that three independent escape attempts (no
`expose()` method, cannot return the buffer reference out of the closure,
no generic trait exposes the raw bytes) are compile errors, not runtime
checks.

```bash
cd poc1-closure-enclosure
cargo run --release          # runtime demo: reconstruct, use, zeroize
./verify_compile_fail.sh     # compile-fail proof: 3/3 escapes rejected
```

## PoC 2 — `poc2-anti-dma-pages/` (proves §5.2)

`KeyShareA` / `KeyShareB`: proves the two `#[repr(C, align(4096))]` key
shares occupy two separate, non-overlapping, individually 4096-byte-aligned
pages in the final linked ELF binary — verified with `nm`, `objdump`, and
`readelf` against the actual compiled artifact, not just the source code.

```bash
cd poc2-anti-dma-pages
./verify_page_split.sh       # builds, then proves page separation via ELF tools
```

## PoC 3 — `poc3-fault-injection/` (proves §3.2)

`GlitchResistantBool` / `GlitchDecodeError`: proves that 100,000 random
single-bit-flip trials against each of the two Hamming-distance-32
sentinels NEVER silently decode into the other valid value — every
corruption is caught as `Err(GlitchDecodeError::Undefined)`. Includes a
side-by-side negative control showing a naive 0/1 encoding suffers a 100%
silent bypass rate under the identical attack.

```bash
cd poc3-fault-injection
cargo run --release          # interactive: 200,000 trials, live results
cargo test --release         # automated: same property, as a CI-friendly gate
```

## Read the caveats

Every PoC's module-level doc comment (top of `src/lib.rs`) states plainly
what that PoC does NOT prove, in the same spirit as the blueprint's own
"what this closes and what it does not" sections (§3.2, §5.6). These are
not hedges added to lower expectations — they mark exactly where a
DMA-capable or hardware-level adversary's remaining attack surface sits,
which is precisely the information a serious technical reviewer (VC
technical diligence, an OS-dev engineer, a defense-agency evaluator) will
look for, and finding it already stated correctly is worth more than any
amount of confident marketing language.
