#!/usr/bin/env bash
# initramfs-smoke.sh - minimal initramfs + QEMU smoke test for catos-system.
#
# Real risks this guards against:
#   * The static binary refuses to start in an environment without the
#     dynamic linker, systemd, dbus, network, or /usr.
#   * A future dependency quietly reintroduces a dynamic link (caught at the
#     static-link check, but this is the runtime counterpart).
#   * Probe code panics when /proc, /sys, /dev are missing or unusual.
#   * JSON output gets polluted by something that only triggers in initramfs.
#   * The runtime detector fails to identify a real initramfs as such.
#
# Two modes:
#   bare         No initramfs markers (no /etc/initrd-release, no /run/initramfs).
#                Verifies the binary starts and produces valid JSON. Does NOT
#                assert anything about is_initramfs.status. Use this to prove
#                the binary does not depend on systemd/dbus/network.
#   with-marker  Includes /etc/initrd-release (matching mkinitcpio output).
#                Additionally asserts is_initramfs.status == "detected".
#                This is the contract the doctor/recovery tools will rely on.
#
# This test is OPT-IN. It is not part of the default `cargo test` or
# `cmake --build . --target check` runs because it requires QEMU + a usable
# kernel image + busybox, which not every dev machine has.
#
# Exit codes:
#   0  test ran and passed
#   1  test ran and FAILED
#   77 skipped (prerequisites missing) - CTest SKIP code
#   2  usage error

set -u

usage() {
    cat >&2 <<EOF
usage: $0 [options]

options:
  --mode MODE     Test mode: bare (no markers) or with-marker (asserts
                  is_initramfs.status == "detected"). Default: with-marker.
  --kernel PATH   Kernel image (bzImage). Default: auto-detect from
                  /usr/lib/modules/\$(uname -r)/vmlinuz and /boot/vmlinuz*.
  --busybox PATH  Static busybox binary. Default: search PATH.
  --bin PATH      catos-system binary to test. Default: auto-detect from
                  the cargo musl release target dir relative to this script.
  --workdir DIR   Working directory for cpio build. Default: tempdir.
  --qemu PATH     qemu-system-x86_64 binary. Default: search PATH.
  --keep          Keep workdir on exit for inspection.
EOF
}

MODE="with-marker"
KERNEL=""
BUSYBOX=""
BIN=""
WORKDIR=""
QEMU_BIN=""
KEEP=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)    MODE="$2"; shift 2 ;;
        --kernel)  KERNEL="$2"; shift 2 ;;
        --busybox) BUSYBOX="$2"; shift 2 ;;
        --bin)     BIN="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        --qemu)    QEMU_BIN="$2"; shift 2 ;;
        --keep)    KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

case "$MODE" in
    bare|with-marker) ;;
    *) echo "error: --mode must be 'bare' or 'with-marker', got: $MODE" >&2; exit 2 ;;
esac

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Locate the catos-system musl release binary if not explicitly given.
if [ -z "$BIN" ]; then
    candidates=(
        "$SCRIPT_DIR/../../build/apps/system/cargo-target/x86_64-unknown-linux-musl/release/catos-system"
        "$SCRIPT_DIR/../../target/x86_64-unknown-linux-musl/release/catos-system"
    )
    for c in "${candidates[@]}"; do
        if [ -x "$c" ]; then BIN="$c"; break; fi
    done
fi

# Locate QEMU.
if [ -z "$QEMU_BIN" ]; then
    if command -v qemu-system-x86_64 >/dev/null 2>&1; then
        QEMU_BIN=$(command -v qemu-system-x86_64)
    fi
fi

# Locate kernel.
if [ -z "$KERNEL" ]; then
    for c in \
        "/usr/lib/modules/$(uname -r)/vmlinuz" \
        /usr/lib/modules/*/vmlinuz \
        /boot/vmlinuz-linux \
        /boot/vmlinuz-linux-lts \
        /boot/vmlinuz-* ; do
        if [ -e "$c" ]; then KERNEL="$c"; break; fi
    done
fi

# Locate busybox (must be executable as PID 1 init).
if [ -z "$BUSYBOX" ]; then
    if command -v busybox >/dev/null 2>&1; then
        BUSYBOX=$(command -v busybox)
    fi
fi

# Report any missing prerequisite. Skip with code 77 (CTest SKIP).
missing=()
[ -z "$BIN" ]        && missing+=("catos-system binary (build it first or pass --bin)")
[ -z "$QEMU_BIN" ]   && missing+=("qemu-system-x86_64 (Arch: pacman -S qemu-system-x86)")
[ -z "$KERNEL" ]     && missing+=("kernel image (install linux/linux-lts, or pass --kernel)")
[ -z "$BUSYBOX" ]    && missing+=("busybox (Arch: pacman -S busybox)")

if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: initramfs smoke test missing prerequisites:" >&2
    for m in "${missing[@]}"; do
        echo "  - $m" >&2
    done
    echo >&2
    echo "This test is opt-in. The catos-system build itself does not require it." >&2
    exit 77
fi

echo "info: using"
echo "  binary : $BIN"
echo "  qemu   : $QEMU_BIN"
echo "  kernel : $KERNEL"
echo "  busybox: $BUSYBOX"

for tool in cpio gzip timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "skip: required tool '$tool' not found" >&2
        exit 77
    fi
done

# Verify the binary is actually static before spending QEMU time on it.
if [ -x "$SCRIPT_DIR/verify-static.sh" ]; then
    if ! "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null; then
        echo "fail: $BIN is not fully static; initramfs smoke is meaningless." >&2
        exit 1
    fi
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-initramfs-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
SERIAL_LOG="$WORKDIR/serial.log"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "info: keeping workdir ($WORKDIR) due to --keep"
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

# Build initramfs tree.
rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,proc,sys,dev,etc,run,usr/bin,usr/sbin,sbin}

cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
chmod +x "$INITRAMFS/bin/busybox"

cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/catos-system"

# busybox applet symlinks - only the ones /init uses.
for applet in sh mount echo poweroff cat; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

# In with-marker mode, populate /etc/initrd-release to mirror what mkinitcpio
# places in real initramfs images. This is the canonical initramfs marker
# that the runtime detector keys on; without it, the detector correctly
# reports "not_detected", which is the right answer for the bare mode.
if [ "$MODE" = "with-marker" ]; then
    echo "NAME=CatOS" > "$INITRAMFS/etc/initrd-release"
    echo "VERSION_ID=initramfs" >> "$INITRAMFS/etc/initrd-release"
fi

# /init script: PID 1.
cat >"$INITRAMFS/init" <<'INIT_EOF'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

/bin/busybox mount -t proc     none /proc 2>/dev/null
/bin/busybox mount -t sysfs    none /sys  2>/dev/null
/bin/busybox mount -t devtmpfs none /dev  2>/dev/null

echo "===INITRAMFS_SMOKE_BEGIN==="
/bin/catos-system inspect --json
rc=$?
echo
echo "===INITRAMFS_SMOKE_END=== rc=$rc"

# Hard poweroff via reboot syscall. -f skips initctl.
/bin/busybox poweroff -f
INIT_EOF
chmod +x "$INITRAMFS/init"

# Pack.
( cd "$INITRAMFS" && find . -print0 | cpio --null --create --format=newc 2>/dev/null ) \
    | gzip -9 > "$INITRAMFS_IMG"

if [ ! -s "$INITRAMFS_IMG" ]; then
    echo "fail: initramfs image is empty" >&2
    exit 1
fi

echo "info: initramfs image: $(stat -c %s "$INITRAMFS_IMG") bytes"

# Boot QEMU. -no-reboot ensures that if init panics or exits, QEMU exits
# instead of looping. console=ttyS0 routes kernel+init stdout to the serial
# port, which -nographic wires to our stdin/stdout.
#
# KVM acceleration: modern kernels (especially distribution kernels tuned for
# recent CPUs like CachyOS's) may fail to boot under pure TCG emulation
# because the kernel probes for CPU features TCG doesn't expose. We prefer
# KVM when /dev/kvm is accessible, and transparently fall back to TCG
# otherwise (slow but correct on machines without KVM).
accel_args=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel_args=(-enable-kvm -cpu host)
    echo "info: using KVM acceleration"
else
    echo "info: KVM unavailable; falling back to TCG emulation (slower)"
fi

timeout 60 "$QEMU_BIN" \
    -M pc \
    -m 512M \
    -no-reboot \
    -nographic \
    "${accel_args[@]}" \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS_IMG" \
    -append "console=ttyS0 panic=1 rdinit=/init" \
    < /dev/null > "$SERIAL_LOG" 2>&1
qemu_rc=$?

if [ "$qemu_rc" -eq 124 ]; then
    echo "fail: QEMU timed out after 60s (init did not power off)" >&2
    echo "serial log: $SERIAL_LOG" >&2
    KEEP=1
    exit 1
fi

# QEMU may exit with non-zero from the poweroff ACPI sequence; that's fine.
# We look for our sentinel markers in the serial log.
if [ ! -s "$SERIAL_LOG" ]; then
    echo "fail: empty serial log" >&2
    exit 1
fi

if ! grep -q "===INITRAMFS_SMOKE_BEGIN===" "$SERIAL_LOG"; then
    echo "fail: BEGIN sentinel not found in serial log" >&2
    echo "----- serial log -----" >&2
    cat "$SERIAL_LOG" >&2
    echo "----------------------" >&2
    KEEP=1
    exit 1
fi

if ! grep -q "===INITRAMFS_SMOKE_END===" "$SERIAL_LOG"; then
    echo "fail: END sentinel not found (catos-system crashed or hung)" >&2
    echo "----- serial log -----" >&2
    cat "$SERIAL_LOG" >&2
    echo "----------------------" >&2
    KEEP=1
    exit 1
fi

# Extract the JSON block. The init script prints BEGIN then the JSON then a
# newline then END. We slice between the markers.
json_block=$(awk '
    /===INITRAMFS_SMOKE_BEGIN===/{flag=1; next}
    /===INITRAMFS_SMOKE_END===/{flag=0}
    flag
' "$SERIAL_LOG")

# Validate JSON via python (qemu env may not have jq).
# In with-marker mode, additionally assert that the runtime detector
# identified the environment as initramfs. Without this assertion the test
# would pass even if the detector returned "not_detected", which is the
# exact false-green the original review caught.
if [ "$MODE" = "with-marker" ]; then
    if ! python3 -c "
import sys, json
text = sys.stdin.read()
data = json.loads(text)
assert data['schemaVersion'] == 2, 'schemaVersion is not 2'
assert 'runtime' in data, 'missing runtime'
assert 'capabilities' in data, 'missing capabilities'
assert 'target' in data, 'missing target'
status = data['runtime']['is_initramfs']['status']
assert status == 'detected', \
    f'is_initramfs.status should be detected (initrd-release marker present), got {status!r}'
print('json ok: schemaVersion=%d, caps=%d, invocation=%s, is_initramfs=%s' % (
    data['schemaVersion'], len(data['capabilities']), data['invocation'], status))
" <<<"$json_block"; then
        echo "fail: JSON or is_initramfs assertion failed (mode=$MODE)" >&2
        echo "----- extracted JSON -----" >&2
        echo "$json_block" >&2
        echo "--------------------------" >&2
        KEEP=1
        exit 1
    fi
else
    if ! python3 -c "
import sys, json
text = sys.stdin.read()
data = json.loads(text)
assert data['schemaVersion'] == 2, 'schemaVersion is not 2'
assert 'runtime' in data, 'missing runtime'
assert 'capabilities' in data, 'missing capabilities'
assert 'target' in data, 'missing target'
print('json ok (bare mode, no is_initramfs assertion): schemaVersion=%d, caps=%d' % (
    data['schemaVersion'], len(data['capabilities'])))
" <<<"$json_block"; then
        echo "fail: JSON validation failed (mode=$MODE)" >&2
        echo "----- extracted JSON -----" >&2
        echo "$json_block" >&2
        echo "--------------------------" >&2
        KEEP=1
        exit 1
    fi
fi

echo "pass: catos-system ran in initramfs (mode=$MODE) and produced valid JSON"
exit 0
