#!/usr/bin/env bash
# Ghost-Hunter §5.6 / §8.11 — Compile-Fail Verification Harness
#
# Proves the three properties §8.11 of the blueprint requires:
#   1. KeyShareA/KeyShareB have no expose() method.
#   2. SecretKeyBuffer cannot escape with_reconstructed_key's closure.
#   3. No generic conversion trait exposes SecretKeyBuffer's raw bytes.
#
# This does NOT use an external test-harness crate (trybuild, etc.) —
# deliberately. It builds the library once as an rlib, then invokes `rustc`
# directly against each file in tests/compile_fail/, exactly the way a
# reviewer auditing this repo would want to see it done: no dependency-tree
# indirection between "the compiler was asked to build this" and "the
# compiler refused." Every step below is a command you could type by hand.
#
# Usage: ./verify_compile_fail.sh
# Exit code 0 = all three files correctly failed to compile (PASS).
# Exit code 1 = at least one file compiled when it should not have, or
#               failed to build the library rlib in the first place (FAIL).

set -u
cd "$(dirname "$0")"

LIB_SRC="src/lib.rs"
RLIB_DIR="$(mktemp -d)"
trap 'rm -rf "$RLIB_DIR"' EXIT

echo "=== Building library as rlib (release profile) ==="
rustc --edition 2021 --crate-type rlib --crate-name poc1_closure_enclosure \
    -O -C lto=fat -C codegen-units=1 \
    --out-dir "$RLIB_DIR" "$LIB_SRC"
if [ $? -ne 0 ]; then
    echo "FATAL: library itself failed to build. Cannot run compile-fail suite."
    exit 1
fi
echo "OK: $RLIB_DIR/libpoc1_closure_enclosure.rlib built.
"

FAIL_COUNT=0
PASS_COUNT=0

check_fails_to_compile() {
    local file="$1"
    local label="$2"
    echo "=== $label ==="
    echo "    file: $file"

    OUT=$(rustc --edition 2021 --crate-type bin \
        -L "$RLIB_DIR" --extern poc1_closure_enclosure="$RLIB_DIR/libpoc1_closure_enclosure.rlib" \
        -o /dev/null "$file" 2>&1)
    STATUS=$?

    if [ $STATUS -ne 0 ]; then
        echo "    PASS: rustc rejected this file (exit code $STATUS), as required."
        echo "    --- compiler diagnostic (truncated) ---"
        echo "$OUT" | head -8 | sed 's/^/    | /'
        echo "    ----------------------------------------
"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "    *** FAIL: rustc ACCEPTED this file. This should be IMPOSSIBLE. ***"
        echo "    This means the property this file is supposed to prove is NOT"
        echo "    actually enforced by the type system. Treat this as a critical bug.
"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

check_fails_to_compile "tests/compile_fail/point_1_no_expose_on_shares.rs" \
    "Point 1: KeyShareA/KeyShareB have no expose() method"

check_fails_to_compile "tests/compile_fail/point_2_buffer_cannot_escape_closure.rs" \
    "Point 2: SecretKeyBuffer cannot escape the closure"

check_fails_to_compile "tests/compile_fail/point_3_no_conversion_from_buffer_reference.rs" \
    "Point 3: no generic conversion trait exposes the raw bytes"

echo "=== Summary ==="
echo "Correctly rejected: $PASS_COUNT / 3"
echo "Incorrectly accepted: $FAIL_COUNT / 3"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "RESULT: PASS — all three escape attempts are structurally impossible."
    exit 0
else
    echo "RESULT: FAIL — at least one escape attempt compiled successfully."
    exit 1
fi
