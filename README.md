# Ghost-Hunter v1.0.18: Compiler-Enforced Security Defenses

**Author:** Taha Kouiyasse — Systems Architect<br>
**White Paper:** [docs/WP_Critical_Infrastructures.pdf](docs/WP_Critical_Infrastructures.pdf)<br>
**Target:** Hubris microkernel (Oxide Computer Company)<br>
**License:** Apache License 2.0

A declarative architecture for an inline cryptographic boundary controller targeting Oxide Computer Company's Hubris microkernel, specifying Rust type-system and linker-level constraints intended to convert specific classes of implementer error and physical hardware fault into compile-time rejections or exhaustively-typed runtime error states. The architecture assumes the host CPU platform itself — not merely the operating system or application layer — may be adversarial.

> **TECHNOLOGY READINESS DISCLOSURE**
> Declarative specification stage. Zero runtime logic. Zero function bodies. 3 standalone PoCs verified. This is stated in the specification's own header, not qualified or walked back here: *"Declarative specification only. Zero runtime logic. Zero function bodies."* The blueprint's closing line reads, in part: *"Every `unimplemented!()` in this document marks a point where real, non-declarative engineering remains before any claim depending on that function's behavior... is fully earned rather than architecturally prepared for."*

---

## The Threat Model: Assume-Hostile-Silicon

Ghost-Hunter's threat model excludes the OS and application layers as trust boundaries and treats the host CPU platform itself as potentially adversarial, across three specific boundaries:

1. **Hostile or vendor-backdoored CPU management subsystems (Ring −3).** Intel's Management Engine and AMD's Platform Security Processor execute above Ring 0, on separate embedded cores, independent of and invisible to the host OS — with, in ME's case historically, independent network stack access coupled to specific integrated NIC silicon. Kernel-level mitigations (SELinux, seccomp-bpf, lockdown mode) constrain Ring 0 / Ring 3 code against each other; none of them constrain a subsystem that was never inside that boundary.
2. **DMA-capable physical RAM reading.** A Ring −3 or DMA-capable adversary with read access to physical memory does not need to defeat OS-level protections, because those protections were never positioned to apply to it.
3. **Physical single-event upset / fault injection (voltage glitching, laser fault injection).** Established hardware-security techniques for inducing a controlled bit-level fault at a chosen instant, typically timed against a security-critical comparison or branch.

Standard TEEs (Intel SGX, AMD SEV) construct their guarantees on an unstated axiom: that the silicon executing the enclave or handling encrypted memory is itself faithfully implementing its documented specification. If an adversary controls that silicon, the guarantee collapses at its root — the protection mechanism is administered by the same component it is meant to defend against.

## Core Architectural Mechanisms

### Anti-DMA Page Splitting
`KeyShareA` / `KeyShareB` split an HMAC key via a two-share XOR scheme into two independently-declared statics, each `#[repr(C, align(4096))]`, placing each share on its own 4096-byte-aligned page. The goal is explicitly narrowing, not eliminating, the window in which the complete key sits at a single DMA-readable location — a single naturally-aligned 4096-byte physical read captures at most one share.

Correction carried forward from PoC 2 below: the `#[link_section]` linker attribute is honored at the object-file level but does not guarantee a distinct output section survives final linking — standard linker behavior merges same-prefixed `.bss.*` input sections into one output `.bss`. The property that actually survives to the shipped, linked artifact and enforces the separation is the `align(4096)` constraint on the type itself, independent of section-name survival.

### The Closure Enclosure
`with_reconstructed_key` (§5.6) replaces a prior pattern that gave calling code direct references to both key shares with no compiler-enforced limit on retention. The combinator:
- Reconstructs the key internally into an opaque `SecretKeyBuffer`.
- Passes `&SecretKeyBuffer` into a caller-supplied `FnOnce(&SecretKeyBuffer) -> R`.
- Drops the buffer unconditionally at the end of its own stack frame, after the closure returns an owned `R` with no lifetime tied to the buffer's scope. `Drop` performs a volatile zero write guarded by `compiler_fence`, specifically to defeat dead-store elimination: a plain zeroing loop with no fence is a candidate for silent removal by LLVM's optimizer, since nothing subsequently reads the zeroed bytes before deallocation.

`SecretKeyBuffer` implements neither `Copy` nor `Clone`, exposes no field access, and implements no generic conversion trait (`AsRef<[u8]>`, `Deref<Target = [u8]>`, `Borrow<[u8]>`). `KeyShareA` / `KeyShareB` have no `expose()` method in this revision — deleted, not deprecated.

### Fault-Injection Immunity
`GlitchResistantBool` is a `#[repr(u32)]` enum whose two variants are exact 32-bit bitwise complements:

```rust
#[repr(u32)]
pub enum GlitchResistantBool {
    True = 0x5A5A5A5A,
    False = 0xA5A5A5A5,
}
```

Hamming distance between the two sentinels is 32 — the maximum for a 32-bit value — so a single-bit fault cannot produce the other sentinel; it produces one of 2³²−2 undefined patterns. Decoding is fallible by construction: the type implements `TryFrom<u32>` only. An infallible `From<u32>` is explicitly banned by the specification text. Any input that is not one of the two defined discriminants returns `Err(GlitchDecodeError::Undefined)`.

### The Hardware Honeypot
`BAIT_KEY`: a private static, 32-byte sentinel (`0xDEADBEEF` repeated), placed in `.bss.cleartext_bait`. Never read, used, or referenced by any verification logic — a passive tripwire whose value derives entirely from external memory-scanning tooling encountering it. Design invariant, stated explicitly in the specification: `BAIT_KEY` must not become, under any revision, a detector for or response to legitimate operator debugging (Humility probe attachment, task dump, IPC trace). No task in the workspace may implement anti-debug, anti-inspection, or monitoring-suppression logic under any name. Isolation is structural — a private static, unreachable from application code, verified via a compile-fail stub — not incidental.

## Proof of Concept (PoC) Verification

| PoC | Claim tested | Verified outcome | Explicit boundary |
|---|---|---|---|
| **1 — Closure Enclosure** | `SecretKeyBuffer` cannot escape `with_reconstructed_key`'s closure scope by any of 3 independent means | 3/3 escape attempts rejected at compile time; 0/3 incorrectly accepted; the legitimate usage pattern runs correctly, with its computed digest verified against an independent reference | Proves the type system, not programmer discipline, enforces scope. Does **not** prove the key is inaccessible to a physical/DMA observer during legitimate closure execution — the demo's own memory inspection confirms the reconstructed key sits in ordinary readable stack memory for that duration, and is verifiably zeroed only after the closure returns. |
| **2 — Anti-DMA Page Splitting** | `KeyShareA` / `KeyShareB` occupy separate, non-overlapping, 4096-byte-aligned pages in the final linked ELF | Confirmed via `nm` / `readelf` against a compiled and linked binary: addresses `0x4b000` / `0x4c000` in this verified run, exact 4096-byte delta, zero range overlap | Proves link-time static layout defeats a single naturally-aligned 4096-byte physical read. Does **not** prove OS page-table mapping to non-adjacent physical DRAM frames (inapplicable on Hubris's paging-free model, the actual target) or IOMMU / DMA-remapping configuration. Exact addresses are a property of a given build, not a fixed guarantee — see note below. |
| **3 — Fault-Injection Immunity** | A single bit flip on either `GlitchResistantBool` sentinel can never silently decode into the other | 200,000 trials (100,000 per sentinel), 0 critical bypasses (0.0%) vs. a 100.0% bypass rate for a naive 0/1 encoding under an identical fault model | Proves zero silent bypass across the tested fault model, at decode time. Does **not** prove protection against a fault landing on an already-decoded value sitting in a register or stack slot — a hardware fault-coverage question outside any software mechanism's reach. |

### PoC 1 detail — compiler diagnostics

| Escape attempt | Compiler outcome | Diagnostic |
|---|---|---|
| (a) Direct share accessor | Rejected | `` E0599: no method named `expose` found for struct `KeyShareA` `` |
| (b) Return buffer reference | Rejected | `lifetime may not live long enough` |
| (c) Generic trait conversion | Rejected | `` E0599: method `as_ref` exists for `&SecretKeyBuffer` but its trait bounds were not satisfied `` |

Correctly rejected: 3/3. Incorrectly accepted: 0/3. The runtime demo separately confirms the buffer is real, readable stack memory during the closure (digest `0x3aa97712a1853a9f` matches an independently computed reference) and is confirmed zeroed — all-zero at the same call depth — immediately after it returns.

### PoC 2 detail — ELF verification

| Property | SHARE_A | SHARE_B |
|---|---|---|
| Virtual address (this verified run) | `0x4b000` | `0x4c000` |
| Size | 4096 bytes | 4096 bytes |
| 4096-byte aligned | Yes | Yes |
| Page number | #75 | #76 |
| Address delta | 4096 bytes (exactly one page) | |
| Range overlap | None | |

Pre-link, `.bss.crypto_share_a` and `.bss.crypto_share_b` exist as two genuinely distinct sections, each exactly 4096 bytes, confirming the `#[link_section]` attribute is honored at the object-file stage. A negative control (`ORDINARY_CONTROL_VALUE`, an 8-byte static with no alignment attribute, at `0x7010` in this run) was confirmed non-page-aligned at the identical `nm` / `readelf` inspection stage, isolating SHARE_A / SHARE_B's alignment as a consequence of the `align(4096)` type attribute, not general toolchain placement behavior.

Exact addresses are a property of a given compiled artifact — link order and other symbols present will shift them on a different build. What is reproducible, and what this PoC actually verifies, is the relationship: two distinct 4096-byte, individually page-aligned regions, exactly one page apart, with zero overlap.

### PoC 3 detail — fault-injection simulation

| Starting sentinel | Trials | Correctly rejected | Critical bypasses | Bit-index coverage (min–max, expected ~3125) |
|---|---|---|---|---|
| True (`0x5A5A5A5A`) | 100,000 | 100,000 (100.0000%) | 0 | 3031–3230 |
| False (`0xA5A5A5A5`) | 100,000 | 100,000 (100.0000%) | 0 | 3016–3258 |
| **Total** | **200,000** | **200,000** | **0** | |

Contrast measurement, identical fault model:

| Encoding | Trials | Silent bypass rate |
|---|---|---|
| `GlitchResistantBool` (Hamming distance 32) | 100,000 | 0.0% |
| Naive 0/1 encoding | 100,000 | 100.0% |

`cargo test --release` runs this as four named, automated properties (`sentinels_are_exact_bitwise_complements`, `no_bit_flip_can_bypass_from_true`, `no_bit_flip_can_bypass_from_false`, `every_u32_neither_sentinel_is_rejected_as_undefined`) — all passing, independent of the trial run above.

## Getting Started & PoC Execution

Developed and verified against `rustc 1.75.0`. None of the three PoCs require the Hubris microkernel, the reference N4500 hardware, or a cross-compilation toolchain — each runs on any Linux machine with a stable Rust compiler. Commands assume the working directory is the repository root.

```bash
# PoC 1 — Closure Enclosure
cd poc1-closure-enclosure
cargo run --release          # reconstruct → use → zeroize, verified at runtime
./verify_compile_fail.sh     # 3/3 escape attempts rejected by rustc, not by convention
```

```bash
# PoC 2 — Anti-DMA Page Splitting
cd poc2-anti-dma-pages
./verify_page_split.sh       # builds, then proves page separation via ELF tools (nm, objdump, readelf)
```

```bash
# PoC 3 — Fault-Injection Immunity
cd poc3-fault-injection
cargo run --release          # 200,000 trials, live
cargo test --release         # same property, as an automated gate
```

Each PoC's module-level doc comment (top of its `src/lib.rs`) states explicitly what it does and does not prove, consistent with the boundaries listed above.

## Technical Specification & White Paper

The full architectural analysis — threat-model derivation, complete specification text, and the structural-proof methodology behind every figure in this document — is at [`docs/WP_Critical_Infrastructures.pdf`](docs/WP_Critical_Infrastructures.pdf) (*Compiler-Enforced Typestate Boundaries for Hostile-Silicon and Physical Fault-Injection Threat Models*, document version 1.0, July 2026). Diagnostics and trial counts throughout this README match the white paper's own verification runs. The one exception: exact memory addresses in the PoC 2 detail above are from a later, independent verification run and differ numerically from the addresses printed in the PDF — expected for ELF linking (see the note under PoC 2), and it does not change the underlying claim.

Document structure:

| Section | Contents |
|---|---|
| Abstract | Full claim summary, stated with explicit scope and boundary conditions |
| §1 The Failure of Current Technologies | Why SGX/SEV, standard OS ring isolation, and standard cryptographic practice do not hold under an assume-hostile-silicon model |
| §2 The Ghost-Hunter Protocol | Full architecture: microkernel isolation, anti-DMA page splitting, the closure enclosure, fault-injection immunity, `BAIT_KEY` |
| §3 Target Applications and Buyer Categories | Threat-model fit by sector (military-grade HSMs, space-grade uplink crypto, zero-trust critical infrastructure, intelligence gateways) — explicitly not a deployment or certification claim |
| §4 Structural Proofs Over Runtime Promises | Full PoC methodology, raw results, and stated boundaries for all three PoCs (§4.1–§4.3), plus summary position (§4.4) |
| §5 Author's Note and Open Call for Collaboration | Process disclosure and the collaboration call |

This README summarizes the white paper; it is not a substitute for it. Anything requiring primary-source citation should reference the PDF directly.

## Future Roadmap & Call for Collaboration

What exists is three independently verified structural boundaries: compiler-enforced key-destruction scope, linked-binary page separation, and decode-time fault immunity. What does not yet exist, and is not implied to exist by any claim above:

- HMAC runtime computation logic.
- Hubris IPC server implementation and task bring-up.
- Hardware integration against the reference N4500 platform.
- The integration work connecting the three proven boundaries into a single operating cryptographic boundary controller.

This is an open call, not a pitch. Looking to hear from:

- **Deep-tech VCs** evaluating pre-implementation, specification-stage security architecture as an investment category, with the explicit understanding that this requires committed technical execution to reach a deployable state.
- **Rust systems / OS-development engineers** — particularly `no_std`, embedded, or microkernel background — capable of taking a technical leadership or CTO-track role building the runtime this specification currently lacks.
- **Defense-technology firms** for whom the threat model in this document (hostile silicon, physical fault injection, Ring −3 adversaries) is an existing, unmet procurement requirement rather than a hypothetical.
- **Intelligence-community research labs** with the technical depth to evaluate these claims directly against their own threat models and red-team methodology.

Contact: tahakouiyasse@protonmail.com

## License

Licensed under the Apache License 2.0.
