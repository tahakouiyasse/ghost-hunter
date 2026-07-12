#!/usr/bin/env bash
# Ghost-Hunter §5.2 — Anti-DMA Page Splitting Verification Harness
#
# Proves, using ONLY standard Linux binutils (nm, objdump, readelf) against
# the actual compiled and linked binary, that KeyShareA and KeyShareB:
#   1. At the PRE-LINK object-file level: occupy two distinct, named
#      sections (.bss.crypto_share_a / .bss.crypto_share_b), each 4096
#      bytes — confirming #[link_section] was honored by the compiler.
#   2. At the POST-LINK, FINAL BINARY level: are each individually
#      4096-byte aligned, each occupy exactly 4096 bytes, and sit at
#      addresses with ZERO overlap and a full page of separation —
#      confirming #[repr(align(4096))] was honored by the linker in the
#      artifact that actually ships / actually sits in physical memory.
#   3. A negative control (an ordinary, non-page-aligned static) is shown
#      for contrast, so the reader can see what "not isolated" looks like
#      in the same tool output.
#
# Usage: ./verify_page_split.sh
# Exit code 0 = all checks pass. Exit code 1 = any check fails.
#
# HONEST LIMITS OF THIS SCRIPT (read before citing results):
# This proves STATIC LINK-TIME LAYOUT ONLY. It does not and cannot prove
# anything about runtime page-table mappings, IOMMU configuration, or
# physical DRAM frame placement on a general-purpose OS with virtual
# memory — see the caveats in src/lib.rs's module doc comment. On the
# real Hubris target (no paging), static layout IS physical layout, which
# is a materially different and STRONGER claim than what this script
# proves when run on an ordinary Linux host, and the difference should be
# stated plainly in anything built on top of this PoC.

set -u
cd "$(dirname "$0")"

FAIL=0
BIN="target/release/demo"
RLIB=""

echo "############################################################"
echo "# STEP 0: Build (release, matching profile settings from   #"
echo "#         Cargo.toml — LTO, codegen-units=1, opt-level=s)  #"
echo "############################################################"
cargo build --release 2>&1 | tail -5
if [ ! -f "$BIN" ]; then
    echo "FATAL: $BIN not found after build."
    exit 1
fi
RLIB=$(find target/release/deps -name "libpoc2_anti_dma_pages-*.rlib" | head -1)
echo "Binary:    $BIN"
echo "Test rlib: $RLIB"
echo ""

echo "############################################################"
echo "# STEP 1: PRE-LINK object file — confirm #[link_section]   #"
echo "#         produced two genuinely distinct named sections   #"
echo "############################################################"
OBJ_DIR=$(mktemp -d)
trap 'rm -rf "$OBJ_DIR"' EXIT
( cd "$OBJ_DIR" && ar x "$OLDPWD/$RLIB" )
OBJ_FILE=$(find "$OBJ_DIR" -name "*.rcgu.o" | head -1)
echo "Extracted object file: $OBJ_FILE"
echo ""
echo "--- readelf -SW (section headers) filtered to our sections ---"
SECTION_OUT=$(readelf -SW "$OBJ_FILE" | grep -E "crypto_share_a|crypto_share_b")
echo "$SECTION_OUT"
echo ""

SEC_A_COUNT=$(echo "$SECTION_OUT" | grep -c "crypto_share_a")
SEC_B_COUNT=$(echo "$SECTION_OUT" | grep -c "crypto_share_b")
SEC_A_SIZE=$(echo "$SECTION_OUT" | grep "crypto_share_a" | awk '{print $6}')
SEC_B_SIZE=$(echo "$SECTION_OUT" | grep "crypto_share_b" | awk '{print $6}')

if [ "$SEC_A_COUNT" -ge 1 ] && [ "$SEC_B_COUNT" -ge 1 ]; then
    echo "PASS: both .bss.crypto_share_a and .bss.crypto_share_b exist as"
    echo "      distinct sections in the pre-link object file."
else
    echo "*** FAIL: expected sections not found in pre-link object file. ***"
    FAIL=1
fi

if [ "0x$SEC_A_SIZE" = "0x001000" ] && [ "0x$SEC_B_SIZE" = "0x001000" ]; then
    echo "PASS: both sections are exactly 0x1000 (4096) bytes."
else
    echo "*** FAIL: section sizes are not 4096 bytes each (got A=$SEC_A_SIZE, B=$SEC_B_SIZE). ***"
    FAIL=1
fi
echo ""

echo "############################################################"
echo "# STEP 2: POST-LINK final binary — confirm the two shares  #"
echo "#         sit on two separate, non-overlapping 4096-byte-  #"
echo "#         aligned pages in the SHIPPED artifact             #"
echo "############################################################"
echo "--- nm output (demangled) ---"
nm -C --print-size "$BIN" | grep -E "SHARE_A|SHARE_B|ORDINARY_CONTROL"
echo ""
echo "--- readelf symbol table (address, size, name) ---"
SYM_OUT=$(readelf -sW "$BIN" | grep -E "SHARE_A|SHARE_B|ORDINARY_CONTROL_VALUE")
echo "$SYM_OUT"
echo ""

ADDR_A=$(echo "$SYM_OUT" | grep "7SHARE_A" | awk '{print $2}')
ADDR_B=$(echo "$SYM_OUT" | grep "7SHARE_B" | awk '{print $2}')
SIZE_A=$(echo "$SYM_OUT" | grep "7SHARE_A" | awk '{print $3}')
SIZE_B=$(echo "$SYM_OUT" | grep "7SHARE_B" | awk '{print $3}')
ADDR_C=$(echo "$SYM_OUT" | grep "ORDINARY_CONTROL_VALUE" | awk '{print $2}')
SIZE_C=$(echo "$SYM_OUT" | grep "ORDINARY_CONTROL_VALUE" | awk '{print $3}')

if [ -z "$ADDR_A" ] || [ -z "$ADDR_B" ]; then
    echo "*** FAIL: could not locate SHARE_A / SHARE_B symbols in the binary. ***"
    FAIL=1
else
    python3 - "$ADDR_A" "$ADDR_B" "$SIZE_A" "$SIZE_B" "$ADDR_C" "$SIZE_C" << 'PYEOF'
import sys

addr_a = int(sys.argv[1], 16)
addr_b = int(sys.argv[2], 16)
size_a = int(sys.argv[3])
size_b = int(sys.argv[4])
addr_c = int(sys.argv[5], 16)
size_c = int(sys.argv[6])

PAGE = 4096
ok = True

print(f"SHARE_A: addr=0x{addr_a:x} size={size_a}")
print(f"SHARE_B: addr=0x{addr_b:x} size={size_b}")
print(f"ORDINARY_CONTROL_VALUE (negative control): addr=0x{addr_c:x} size={size_c}")
print()

# Check 1: both individually page-aligned
a_aligned = (addr_a % PAGE == 0)
b_aligned = (addr_b % PAGE == 0)
print(f"CHECK: SHARE_A address is 4096-byte aligned -> {a_aligned}")
print(f"CHECK: SHARE_B address is 4096-byte aligned -> {b_aligned}")
ok = ok and a_aligned and b_aligned

# Check 2: both exactly one page in size
print(f"CHECK: SHARE_A size == 4096 -> {size_a == PAGE}")
print(f"CHECK: SHARE_B size == 4096 -> {size_b == PAGE}")
ok = ok and (size_a == PAGE) and (size_b == PAGE)

# Check 3: zero overlap between [addr_a, addr_a+size_a) and [addr_b, addr_b+size_b)
range_a = (addr_a, addr_a + size_a)
range_b = (addr_b, addr_b + size_b)
overlap = not (range_a[1] <= range_b[0] or range_b[1] <= range_a[0])
print(f"CHECK: SHARE_A range {hex(range_a[0])}-{hex(range_a[1])} and "
      f"SHARE_B range {hex(range_b[0])}-{hex(range_b[1])} overlap -> {overlap} (want False)")
ok = ok and (not overlap)

# Check 4: they are on genuinely DIFFERENT pages (not just non-overlapping
# within a shared page — since both are exactly one page in size and
# page-aligned, this is implied by checks 1-3, but stated explicitly here
# since it's the actual claim being made to a reader.)
page_a = addr_a // PAGE
page_b = addr_b // PAGE
different_pages = (page_a != page_b)
print(f"CHECK: SHARE_A occupies page #{page_a}, SHARE_B occupies page #{page_b} "
      f"-> different pages: {different_pages}")
ok = ok and different_pages

print()
print("--- Negative control, for contrast ---")
c_aligned = (addr_c % PAGE == 0)
print(f"ORDINARY_CONTROL_VALUE address 4096-aligned? -> {c_aligned} "
      f"(expected False -- this value has no alignment attribute, so it is "
      f"NOT page-isolated, which is exactly the point: SHARE_A/SHARE_B look "
      f"different from an ordinary variable in this exact same tool output.)")

print()
if ok:
    print("RESULT: PASS -- SHARE_A and SHARE_B are confirmed, via the actual")
    print("        linked binary's own symbol table, to occupy two separate,")
    print("        non-overlapping, individually 4096-byte-aligned pages.")
    sys.exit(0)
else:
    print("RESULT: FAIL -- one or more required properties did not hold.")
    sys.exit(1)
PYEOF
    PYSTATUS=$?
    if [ $PYSTATUS -ne 0 ]; then
        FAIL=1
    fi
fi

echo ""
echo "############################################################"
echo "# FINAL RESULT                                              #"
echo "############################################################"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED."
    exit 0
else
    echo "ONE OR MORE CHECKS FAILED. See output above."
    exit 1
fi
