#!/usr/bin/env bash
# verify-static.sh - assert that a catos-system binary is fully static.
#
# This is the canonical static-linking acceptance check. It does NOT rely on
# the human-readable `file` output, which can describe binaries as "static-pie
# linked" while still carrying a PT_INTERP or NEEDED entry. We parse the ELF
# directly via readelf.
#
# Real risks:
#   * A dependency quietly turns into a dynamic link (e.g. an inadvertent
#     feature flag pulling in openssl-sys with `vendored = false`).
#   * The musl target gets switched to glibc by accident.
#   * A future Rust toolchain regresses static-pie on musl.
#
# Usage: verify-static.sh <path-to-binary>
# Exit codes: 0 = fully static, 1 = dynamic linking detected or check failed.

set -u

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-binary>" >&2
    exit 2
fi

BIN="$1"

if [ ! -f "$BIN" ]; then
    echo "error: not a file: $BIN" >&2
    exit 2
fi

if ! command -v readelf >/dev/null 2>&1; then
    echo "error: readelf not found on PATH; cannot verify ELF static linking" >&2
    echo "       install binutils (Arch: pacman -S binutils)" >&2
    exit 2
fi

fail=0
TMPDIR=$(mktemp -d -t catos-static-check-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

# 1. PT_INTERP must be absent. A static binary has no interpreter.
# readelf exits non-zero on a malformed ELF; capture that explicitly so a
# corrupt or truncated binary does not get a false pass via empty output.
interp=$(readelf -l "$BIN" 2>"$TMPDIR/readelf-program.err" | awk '/^[[:space:]]*INTERP /{print; exit}')
readelf_rc=${PIPESTATUS[0]}
if [ "$readelf_rc" -ne 0 ]; then
    echo "FAIL: readelf -l exited $readelf_rc; cannot trust empty INTERP output"
    cat "$TMPDIR/readelf-program.err" >&2
    exit 1
fi
if [ -n "$interp" ]; then
    echo "FAIL: PT_INTERP present (binary has a dynamic linker):"
    echo "  $interp"
    fail=1
else
    echo "ok: no PT_INTERP segment"
fi

# 2. No NEEDED entries in the dynamic section. A static binary does not need
# any shared object at runtime. As above, capture readelf's exit code so a
# malformed ELF does not silently slip through.
needed_raw=$(readelf -d "$BIN" 2>"$TMPDIR/readelf-dynamic.err")
readelf_rc=$?
if [ "$readelf_rc" -ne 0 ]; then
    echo "FAIL: readelf -d exited $readelf_rc; cannot trust empty NEEDED output"
    cat "$TMPDIR/readelf-dynamic.err" >&2
    exit 1
fi
needed=$(echo "$needed_raw" | awk '/\(NEEDED\)/{print}')
if [ -n "$needed" ]; then
    echo "FAIL: dynamic NEEDED entries present:"
    echo "$needed"
    fail=1
else
    echo "ok: no NEEDED entries"
fi

# 3. Optional sanity: the binary should be ELF.
elf_magic=$(head -c 4 "$BIN" 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$elf_magic" != "7f454c46" ]; then
    echo "FAIL: not an ELF file (magic bytes: $elf_magic)"
    fail=1
else
    echo "ok: ELF magic bytes present"
fi

# 4. Optional sanity: report size so regressions in bloat are visible.
size=$(stat -c %s "$BIN" 2>/dev/null || stat -f %z "$BIN" 2>/dev/null)
if [ -n "$size" ]; then
    kib=$((size / 1024))
    echo "info: binary size ${size} bytes (${kib} KiB)"
    if [ "$size" -gt $((4 * 1024 * 1024)) ]; then
        echo "warn: binary exceeds 4 MiB soft limit; investigate size budget"
        # Not a hard failure - investigate first.
    fi
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL (binary is NOT fully static)"
    exit 1
fi
echo "RESULT: OK (binary is fully static)"
exit 0
