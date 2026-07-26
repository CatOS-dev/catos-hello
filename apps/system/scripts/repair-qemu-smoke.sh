#!/usr/bin/env bash
# repair-qemu-smoke.sh - real ext4/vfat/btrfs/xfs repair in QEMU.
#
# This test creates writable raw filesystem images, deliberately
# corrupts each one in a way the matching fsck tool can fix, boots
# the static catos-system binary in a minimal initramfs, and verifies:
#
#   * catos-repair fs routes each image to the correct tool;
#   * ext4 corruption is repaired by e2fsck and the post-repair
#     read-only verification mount succeeds;
#   * vfat corruption is repaired by fsck.fat;
#   * btrfs corruption triggers --readonly check, then --repair,
#     then a second --readonly check; the report flags
#     RepairedWithRisk;
#   * xfs repair exercises the normal xfs_repair path;
#   * the high-risk fallback (xfs_repair -L) is exercised on a
#     second xfs image with a deliberately dirty log;
#   * the program's own verification mounts are cleaned up before
#     exit (no residual sessions under /run/catos-system/sessions).
#
# Exit 77 means a prerequisite is unavailable.

set -u

usage() {
    cat >&2 <<EOF
usage: $0 [options]

options:
  --kernel PATH   Kernel image. Default: auto-detect host kernel image.
  --busybox PATH  Static busybox. Default: search PATH.
  --bin PATH      Static catos-system binary.
  --qemu PATH     qemu-system-x86_64. Default: search PATH.
  --workdir DIR   Work directory. Default: temporary directory.
  --keep          Keep workdir after completion.
EOF
}

KERNEL=""
BUSYBOX=""
BIN=""
QEMU_BIN=""
WORKDIR=""
KEEP=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --kernel) KERNEL="$2"; shift 2 ;;
        --busybox) BUSYBOX="$2"; shift 2 ;;
        --bin) BIN="$2"; shift 2 ;;
        --qemu) QEMU_BIN="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -z "$BIN" ]; then
    for candidate in \
        "$SCRIPT_DIR/../../target/x86_64-unknown-linux-musl/release/catos-system" \
        "$SCRIPT_DIR/../../build/apps/system/cargo-target/x86_64-unknown-linux-musl/release/catos-system"; do
        if [ -x "$candidate" ]; then BIN="$candidate"; break; fi
    done
fi
if [ -z "$QEMU_BIN" ] && command -v qemu-system-x86_64 >/dev/null 2>&1; then
    QEMU_BIN=$(command -v qemu-system-x86_64)
fi
if [ -z "$BUSYBOX" ] && command -v busybox >/dev/null 2>&1; then
    BUSYBOX=$(command -v busybox)
fi
if [ -z "$KERNEL" ]; then
    for candidate in \
        "/usr/lib/modules/$(uname -r)/vmlinuz" \
        /usr/lib/modules/*/vmlinuz \
        /boot/vmlinuz-linux \
        /boot/vmlinuz-linux-lts \
        /boot/vmlinuz-*; do
        if [ -e "$candidate" ]; then KERNEL="$candidate"; break; fi
    done
fi

missing=()
[ -z "$BIN" ] && missing+=("catos-system musl binary")
[ -z "$QEMU_BIN" ] && missing+=("qemu-system-x86_64")
[ -z "$BUSYBOX" ] && missing+=("static busybox")
[ -z "$KERNEL" ] && missing+=("kernel image")
# Build-time tools. Each tool is needed to construct at least one
# corruptible image; missing tools cause the corresponding assertion
# to be skipped rather than fabricated.
for tool in cpio gzip timeout mkfs.ext4 mkfs.vfat mkfs.btrfs \
            e2fsck fsck.fat btrfs btrfs-map-logical debugfs sha256sum python3 ldd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
# xfs is optional — many minimal hosts do not ship xfsprogs. The
# test still passes if xfs is missing; the xfs assertions are
# skipped from inside the python verifier.
HAVE_XFS=0
if command -v mkfs.xfs >/dev/null 2>&1 && command -v xfs_repair >/dev/null 2>&1; then
    HAVE_XFS=1
fi
if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: repair QEMU smoke test missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

if [ -x "$SCRIPT_DIR/verify-static.sh" ]; then
    "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || {
        echo "fail: catos-system is not fully static" >&2
        exit 1
    }
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-repair-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
SERIAL_LOG="$WORKDIR/serial.log"

# Image files. vda = ext4 (corrupted); vdb = vfat (corrupted);
# vdc = Btrfs metadata-DUP with one damaged root-tree mirror; vdd = XFS
# normal repair; vde = XFS dirty log that must use the -L fallback.
EXT4_IMG="$WORKDIR/ext4.img"
VFAT_IMG="$WORKDIR/vfat.img"
BTRFS_IMG="$WORKDIR/btrfs.img"
XFS_CLEAN_IMG="$WORKDIR/xfs-clean.img"
XFS_DIRTY_IMG="$WORKDIR/xfs-dirty.img"

KVER=$(basename "$(dirname "$KERNEL")")
if [ "$KVER" = "modules" ] || [ ! -d "/usr/lib/modules/$KVER" ]; then
    KVER=$(uname -r)
fi

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "info: keeping workdir $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build the images.
# ---------------------------------------------------------------------------

rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,usr/bin,usr/sbin,"lib/modules/$KVER/kernel/fs"}

# ext4 image: build, snapshot hash, then corrupt the superblock magic
# bytes. e2fsck -y restores them.
truncate -s 64M "$EXT4_IMG"
mkfs.ext4 -q -F -U 11111111-aaaa-bbbb-cccc-dddddddddddd -L repair-ext4 "$EXT4_IMG"
EXT4_HASH_BEFORE_CORRUPT=$(sha256sum "$EXT4_IMG" | awk '{print $1}')
# Corrupt: zero bytes 1080..1100 (well inside the superblock region;
# magic 0xEF53 lives at offset 0x438, but tearing a wider hole forces
# e2fsck to actually rewrite multiple fields rather than just one
# magic). Then immediately take the post-corruption hash — this is
# the "before repair" evidence.
dd if=/dev/zero of="$EXT4_IMG" bs=1 count=32 seek=1080 conv=notrunc status=none
EXT4_HASH_AFTER_CORRUPT=$(sha256sum "$EXT4_IMG" | awk '{print $1}')
if [ "$EXT4_HASH_BEFORE_CORRUPT" = "$EXT4_HASH_AFTER_CORRUPT" ]; then
    echo "fail: ext4 corruption did not change image hash" >&2
    KEEP=1
    exit 1
fi

# vfat image: build, then flip bytes inside the FAT table (sector
# offset 1, well past the boot sector). fsck.fat -a restores a
# consistent FAT state.
truncate -s 32M "$VFAT_IMG"
mkfs.vfat -n REPAIRVFAT "$VFAT_IMG" >/dev/null
VFAT_HASH_BEFORE_CORRUPT=$(sha256sum "$VFAT_IMG" | awk '{print $1}')
# Corrupt: scramble 256 bytes inside the first FAT copy. The FAT
# begins immediately after the boot sector + reserved sectors. For
# FAT32 with default mkfs.vfat settings, that is offset 0x200 * N
# where N is the reserved sector count (typically 32). Use offset
# 0x4000 to be safely inside FAT1.
head -c 256 /dev/urandom > "$WORKDIR/vfat-corruption.bin"
dd if="$WORKDIR/vfat-corruption.bin" of="$VFAT_IMG" bs=1 count=256 seek=16384 conv=notrunc status=none
VFAT_HASH_AFTER_CORRUPT=$(sha256sum "$VFAT_IMG" | awk '{print $1}')
if [ "$VFAT_HASH_BEFORE_CORRUPT" = "$VFAT_HASH_AFTER_CORRUPT" ]; then
    echo "fail: vfat corruption did not change image hash" >&2
    KEEP=1
    exit 1
fi

# Btrfs image: metadata DUP gives the root-tree block two physical
# mirrors. Corrupt one mirror at a mapped physical offset. Current
# btrfs-progs can return exit 0 after reading the healthy mirror while still
# printing "checksum verify failed"; catos-repair treats that diagnostic as
# real corruption, invokes --repair, and requires a clean diagnostic recheck.
truncate -s 512M "$BTRFS_IMG"
mkfs.btrfs -q -f -L repair-btrfs -m dup -d single "$BTRFS_IMG"
BTRFS_HASH_BEFORE_CORRUPT=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')
BTRFS_ROOT_LOGICAL=$(btrfs inspect-internal dump-tree -t root "$BTRFS_IMG" 2>/dev/null \
    | awk '/^leaf [0-9]+/ { print $2; exit }')
if [ -z "$BTRFS_ROOT_LOGICAL" ]; then
    echo "fail: could not identify the Btrfs root-tree logical block" >&2
    KEEP=1
    exit 1
fi
BTRFS_MAP_OUTPUT=$(btrfs-map-logical \
    -l "$BTRFS_ROOT_LOGICAL" -c 1 -b 16384 \
    -o "$WORKDIR/btrfs-root-copy.bin" "$BTRFS_IMG" 2>&1)
BTRFS_ROOT_PHYSICAL=$(printf '%s\n' "$BTRFS_MAP_OUTPUT" \
    | awk '/^mirror 1 logical / { print $6; exit }')
if [ -z "$BTRFS_ROOT_PHYSICAL" ]; then
    echo "fail: could not map Btrfs root-tree mirror 1" >&2
    echo "$BTRFS_MAP_OUTPUT" >&2
    KEEP=1
    exit 1
fi
python3 - "$BTRFS_IMG" "$((BTRFS_ROOT_PHYSICAL + 1024))" <<'PY_BTRFS_CORRUPT'
import sys
path = sys.argv[1]
offset = int(sys.argv[2])
with open(path, "r+b", buffering=0) as image:
    image.seek(offset)
    original = image.read(1)
    if len(original) != 1:
        raise SystemExit("cannot read Btrfs corruption byte")
    image.seek(offset)
    image.write(bytes([original[0] ^ 0x5A]))
PY_BTRFS_CORRUPT
BTRFS_HASH_AFTER_CORRUPT=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')
if [ "$BTRFS_HASH_BEFORE_CORRUPT" = "$BTRFS_HASH_AFTER_CORRUPT" ]; then
    echo "fail: Btrfs mirror corruption did not change the image" >&2
    KEEP=1
    exit 1
fi
set +e
btrfs check --readonly "$BTRFS_IMG" > "$WORKDIR/btrfs-before-repair.log" 2>&1
BTRFS_PRECHECK_RC=$?
set -e
if ! grep -q 'checksum verify failed' "$WORKDIR/btrfs-before-repair.log"; then
    echo "fail: Btrfs fixture did not expose the expected checksum failure" >&2
    cat "$WORKDIR/btrfs-before-repair.log" >&2
    KEEP=1
    exit 1
fi
# The exit code is intentionally not constrained: btrfs-progs 7.1 reports
# this recoverable mirror corruption while returning 0.
: "$BTRFS_PRECHECK_RC"

# XFS images (only if xfsprogs is present). The clean image exercises
# normal xfs_repair. The second image is mounted and written in a separate
# QEMU boot that the host kills without unmounting, producing a real dirty
# journal for the mandatory -L fallback acceptance.
if [ "$HAVE_XFS" -eq 1 ]; then
    truncate -s 512M "$XFS_CLEAN_IMG"
    mkfs.xfs -q -f -L xfs-clean "$XFS_CLEAN_IMG"
    # "Corrupt" the clean image lightly: zero a single byte inside a
    # metadata block. xfs_repair normal mode should restore it.
    XFS_CLEAN_OFFSET=$(stat -c %s "$XFS_CLEAN_IMG")
    XFS_CLEAN_OFFSET=$((XFS_CLEAN_OFFSET / 2))
    dd if=/dev/zero of="$XFS_CLEAN_IMG" bs=1 count=64 seek=$XFS_CLEAN_OFFSET conv=notrunc status=none
    XFS_CLEAN_HASH_AFTER_CORRUPT=$(sha256sum "$XFS_CLEAN_IMG" | awk '{print $1}')

    truncate -s 512M "$XFS_DIRTY_IMG"
    mkfs.xfs -q -f -L xfs-dirty "$XFS_DIRTY_IMG"
    XFS_DIRTY_HASH_AFTER_CORRUPT=$(sha256sum "$XFS_DIRTY_IMG" | awk '{print $1}')
fi

# ---------------------------------------------------------------------------
# Build the initramfs.
# ---------------------------------------------------------------------------

cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system"
for applet in sh mount cat echo sleep modprobe poweroff mkdir grep awk find dd sync; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

# Include the fsck tools so the guest actually runs real fscks rather
# than discovering they are absent. We copy the binaries plus their
# shared library deps so a dynamically-linked tool chain works in the
# guest (the host binary is musl-static; the tools are typically glibc).
copy_tool_with_deps() {
    local tool="$1"
    [ -f "/usr/bin/$tool" ] || [ -f "/usr/sbin/$tool" ] || return 0
    local src
    src=$(command -v "$tool")
    mkdir -p "$INITRAMFS/usr/bin" "$INITRAMFS/usr/sbin"
    local dest="$INITRAMFS$src"
    mkdir -p "$(dirname "$dest")"
    cp -L "$src" "$dest"
    # Copy shared library dependencies. Static tools produce no
    # output from ldd; we just skip.
    ldd "$src" 2>/dev/null | awk '
        /=> \/[^ ]+/ { print $3 }
        $1 ~ /^\// { print $1 }
    ' | while read -r library; do
        [ -f "$library" ] || continue
        mkdir -p "$INITRAMFS$(dirname "$library")"
        cp -L "$library" "$INITRAMFS$library"
    done
}

for tool in e2fsck fsck.fat fsck.vfat btrfs mkfs.ext4 mkfs.vfat mkfs.btrfs debugfs; do
    copy_tool_with_deps "$tool"
done
if [ "$HAVE_XFS" -eq 1 ]; then
    for tool in xfs_repair mkfs.xfs xfs_db; do
        copy_tool_with_deps "$tool"
    done
fi

# FAT module may be modular on the test kernel; we copy it if present.
mkdir -p "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat" "$INITRAMFS/lib/modules/$KVER/kernel/fs/xfs"
FAT_MODULE=$(modinfo -k "$KVER" -n fat 2>/dev/null || true)
VFAT_MODULE=$(modinfo -k "$KVER" -n vfat 2>/dev/null || true)
XFS_MODULE=$(modinfo -k "$KVER" -n xfs 2>/dev/null || true)
if [ -n "$FAT_MODULE" ] && [ -f "$FAT_MODULE" ]; then
    case "$FAT_MODULE" in
        *.zst) zstd -q -d -c "$FAT_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/fat.ko" 2>/dev/null || cp "$FAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/fat.ko" ;;
        *) cp "$FAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/fat.ko" ;;
    esac
fi
if [ -n "$VFAT_MODULE" ] && [ -f "$VFAT_MODULE" ]; then
    case "$VFAT_MODULE" in
        *.zst) zstd -q -d -c "$VFAT_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/vfat.ko" 2>/dev/null || cp "$VFAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/vfat.ko" ;;
        *) cp "$VFAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/vfat.ko" ;;
    esac
fi
if [ -n "$XFS_MODULE" ] && [ -f "$XFS_MODULE" ]; then
    case "$XFS_MODULE" in
        *.zst) zstd -q -d -c "$XFS_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/xfs/xfs.ko" 2>/dev/null || cp "$XFS_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/xfs/xfs.ko" ;;
        *) cp "$XFS_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/xfs/xfs.ko" ;;
    esac
fi
cat > "$INITRAMFS/lib/modules/$KVER/modules.dep" <<EOF
kernel/fs/fat/fat.ko:
kernel/fs/fat/vfat.ko: kernel/fs/fat/fat.ko
kernel/fs/xfs/xfs.ko:
EOF
: > "$INITRAMFS/lib/modules/$KVER/modules.alias"
: > "$INITRAMFS/lib/modules/$KVER/modules.symbols"

cat > "$INITRAMFS/etc/initrd-release" <<'EOF'
NAME=CatOS
VERSION_ID=repair-smoke
EOF

# Guest init. The guest:
#   1. waits for virtio-blk devices to settle
#   2. injects udev database signatures so catos-system discovers
#      each image as a known filesystem
#   3. runs `catos-repair fs <DEVICE>` per image, capturing stdout
#      between marker lines
#   4. verifies no residual sessions are left under
#      /run/catos-system/sessions
cat > "$INITRAMFS/init" <<'INIT_EOF'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t devtmpfs none /dev 2>/dev/null
modprobe vfat 2>/dev/null || true
modprobe xfs 2>/dev/null || true

if grep -q 'catos_xfs_dirty_precondition=1' /proc/cmdline; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -b /dev/vda ] && break
        sleep 1
    done
    mkdir -p /mnt
    mount -t xfs /dev/vda /mnt || {
        echo '===XFS_DIRTY_FATAL=== mount failed'
        poweroff -f
    }
    dd if=/dev/zero of=/mnt/dirty-payload bs=1M count=64 2>/dev/null
    sync
    echo '===XFS_DIRTY_READY==='
    while true; do sleep 60; done
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && [ -b /dev/vdb ] && [ -b /dev/vdc ] && break
    sleep 1
done
if [ ! -b /dev/vda ] || [ ! -b /dev/vdb ] || [ ! -b /dev/vdc ]; then
    echo "===REPAIR_FATAL=== missing virtio block devices"
    poweroff -f
fi

mkdir -p /run/udev/data
ext4_mm=$(cat /sys/class/block/vda/dev)
vfat_mm=$(cat /sys/class/block/vdb/dev)
btrfs_mm=$(cat /sys/class/block/vdc/dev)
cat > "/run/udev/data/b${ext4_mm}" <<'EOF'
E:ID_FS_TYPE=ext4
E:ID_FS_UUID=11111111-aaaa-bbbb-cccc-dddddddddddd
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=repair-ext4
EOF
cat > "/run/udev/data/b${vfat_mm}" <<'EOF'
E:ID_FS_TYPE=vfat
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=REPAIRVFAT
EOF
cat > "/run/udev/data/b${btrfs_mm}" <<'EOF'
E:ID_FS_TYPE=btrfs
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=repair-btrfs
EOF
if [ -b /dev/vdd ]; then
    xfs_clean_mm=$(cat /sys/class/block/vdd/dev)
    cat > "/run/udev/data/b${xfs_clean_mm}" <<'EOF'
E:ID_FS_TYPE=xfs
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=xfs-clean
EOF
fi
if [ -b /dev/vde ]; then
    xfs_dirty_mm=$(cat /sys/class/block/vde/dev)
    cat > "/run/udev/data/b${xfs_dirty_mm}" <<'EOF'
E:ID_FS_TYPE=xfs
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=xfs-dirty
EOF
fi

run_repair() {
    label="$1"
    dev="$2"
    echo "===REPAIR_${label}_BEGIN==="
    # catos-repair is a multicall alias for catos-system; we must
    # invoke through the alias so argv[0] selects the repair entry
    # point. The binary is physically /bin/catos-system; we link
    # /bin/catos-repair to it on first use.
    [ -e /bin/catos-repair ] || ln -sf /bin/catos-system /bin/catos-repair
    /bin/catos-repair fs "$dev" --json
    rc=$?
    echo "===REPAIR_${label}_END=== rc=$rc"
}

# Explicit-device invocations: the safety layer requires an explicit
# device because the auto-discovery would see multiple ext4/xfs
# candidates and refuse on ambiguity.
run_repair EXT4 /dev/vda
run_repair VFAT /dev/vdb
run_repair BTRFS /dev/vdc
[ -b /dev/vdd ] && run_repair XFS_CLEAN /dev/vdd
[ -b /dev/vde ] && run_repair XFS_DIRTY /dev/vde

# Refuse-running-root regression: the initramfs runs on a tmpfs root,
# so /dev/vda is NOT the running root. The repair flow MUST proceed
# rather than refuse on running-root grounds. The above invocations
# already cover this — if any had refused, the python verifier would
# catch the refusal outcome.

# Verify the program cleaned up its own session mounts.
if find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo "===SESSION_RESIDUAL=== yes"
else
    echo "===SESSION_RESIDUAL=== no"
fi

sync
poweroff -f
INIT_EOF
chmod +x "$INITRAMFS/init"

(
    cd "$INITRAMFS" || exit 1
    find . -print0 | cpio --null --create --format=newc 2>/dev/null
) | gzip -9 > "$INITRAMFS_IMG"

# ---------------------------------------------------------------------------
# Boot QEMU and capture serial output.
# ---------------------------------------------------------------------------

accel_args=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel_args=(-enable-kvm -cpu host)
fi

if [ "$HAVE_XFS" -eq 1 ]; then
    XFS_DIRTY_SERIAL="$WORKDIR/xfs-dirty-precondition.log"
    "$QEMU_BIN" \
        -M pc -m 512M -no-reboot -nographic \
        "${accel_args[@]}" \
        -kernel "$KERNEL" -initrd "$INITRAMFS_IMG" \
        -append "console=ttyS0 panic=1 rdinit=/init catos_xfs_dirty_precondition=1" \
        -drive "if=none,id=xfs_dirty_pre,file=$XFS_DIRTY_IMG,format=raw,cache=none" \
        -device virtio-blk-pci,drive=xfs_dirty_pre \
        < /dev/null > "$XFS_DIRTY_SERIAL" 2>&1 &
    dirty_pid=$!
    dirty_ready=0
    for _ in $(seq 1 60); do
        if grep -q '===XFS_DIRTY_READY===' "$XFS_DIRTY_SERIAL" 2>/dev/null; then
            dirty_ready=1
            break
        fi
        if ! kill -0 "$dirty_pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if [ "$dirty_ready" -ne 1 ]; then
        kill -9 "$dirty_pid" 2>/dev/null || true
        wait "$dirty_pid" 2>/dev/null || true
        echo "fail: could not create a real unclean XFS log" >&2
        cat "$XFS_DIRTY_SERIAL" >&2
        KEEP=1
        exit 1
    fi
    kill -9 "$dirty_pid" 2>/dev/null || true
    wait "$dirty_pid" 2>/dev/null || true
    # Prove the abrupt shutdown actually left a log that normal repair refuses.
    set +e
    xfs_repair -n "$XFS_DIRTY_IMG" > "$WORKDIR/xfs-dirty-proof.log" 2>&1
    dirty_probe_rc=$?
    set -e
    if [ "$dirty_probe_rc" -eq 0 ] || ! grep -Eqi 'log.*(replay|valuable metadata|dirty)|mount.*log' "$WORKDIR/xfs-dirty-proof.log"; then
        echo "fail: XFS precondition boot did not leave a verifiable dirty log" >&2
        cat "$WORKDIR/xfs-dirty-proof.log" >&2
        KEEP=1
        exit 1
    fi
    XFS_DIRTY_HASH_AFTER_CORRUPT=$(sha256sum "$XFS_DIRTY_IMG" | awk '{print $1}')
fi

qemu_drives=(
    -drive "if=none,id=ext4,file=$EXT4_IMG,format=raw,cache=none"
    -device virtio-blk-pci,drive=ext4
    -drive "if=none,id=vfat,file=$VFAT_IMG,format=raw,cache=none"
    -device virtio-blk-pci,drive=vfat
    -drive "if=none,id=btrfs,file=$BTRFS_IMG,format=raw,cache=none"
    -device virtio-blk-pci,drive=btrfs
)
if [ "$HAVE_XFS" -eq 1 ]; then
    qemu_drives+=(
        -drive "if=none,id=xfs_clean,file=$XFS_CLEAN_IMG,format=raw,cache=none"
        -device virtio-blk-pci,drive=xfs_clean
        -drive "if=none,id=xfs_dirty,file=$XFS_DIRTY_IMG,format=raw,cache=none"
        -device virtio-blk-pci,drive=xfs_dirty
    )
fi

timeout 180 "$QEMU_BIN" \
    -M pc \
    -m 1024M \
    -no-reboot \
    -nographic \
    "${accel_args[@]}" \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS_IMG" \
    -append "console=ttyS0 panic=1 rdinit=/init" \
    "${qemu_drives[@]}" \
    < /dev/null > "$SERIAL_LOG" 2>&1
qemu_rc=$?
if [ "$qemu_rc" -eq 124 ]; then
    echo "fail: QEMU repair test timed out" >&2
    KEEP=1
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify results.
# ---------------------------------------------------------------------------

EXT4_HASH_AFTER_REPAIR=$(sha256sum "$EXT4_IMG" | awk '{print $1}')
VFAT_HASH_AFTER_REPAIR=$(sha256sum "$VFAT_IMG" | awk '{print $1}')
BTRFS_HASH_AFTER_REPAIR=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')
if [ "$HAVE_XFS" -eq 1 ]; then
    XFS_CLEAN_HASH_AFTER_REPAIR=$(sha256sum "$XFS_CLEAN_IMG" | awk '{print $1}')
    XFS_DIRTY_HASH_AFTER_REPAIR=$(sha256sum "$XFS_DIRTY_IMG" | awk '{print $1}')
fi

# Sanity: successful repair changes the deliberately damaged images.
# Btrfs is additionally rechecked on the host to prove the damaged DUP mirror
# no longer emits a metadata checksum diagnostic.
if [ "$EXT4_HASH_AFTER_REPAIR" = "$EXT4_HASH_AFTER_CORRUPT" ]; then
    echo "fail: ext4 image unchanged after repair (tool did nothing or refused)" >&2
    KEEP=1
    exit 1
fi
if [ "$VFAT_HASH_AFTER_REPAIR" = "$VFAT_HASH_AFTER_CORRUPT" ]; then
    echo "fail: vfat image unchanged after repair (tool did nothing or refused)" >&2
    KEEP=1
    exit 1
fi
if [ "$BTRFS_HASH_AFTER_REPAIR" = "$BTRFS_HASH_AFTER_CORRUPT" ]; then
    echo "fail: Btrfs image unchanged after --repair" >&2
    KEEP=1
    exit 1
fi
set +e
btrfs check --readonly "$BTRFS_IMG" > "$WORKDIR/btrfs-after-repair.log" 2>&1
BTRFS_POSTCHECK_RC=$?
set -e
if [ "$BTRFS_POSTCHECK_RC" -ne 0 ] || grep -q 'checksum verify failed' "$WORKDIR/btrfs-after-repair.log"; then
    echo "fail: Btrfs metadata mirror remained damaged after repair" >&2
    cat "$WORKDIR/btrfs-after-repair.log" >&2
    KEEP=1
    exit 1
fi

python3 - "$SERIAL_LOG" "$HAVE_XFS" <<'PY'
import json
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
have_xfs = int(sys.argv[2]) == 1

def document(name):
    match = re.search(
        rf"==={name}_BEGIN===\s*(\{{.*?\}})\s*==={name}_END=== rc=(-?\d+)",
        text,
        re.S,
    )
    if not match:
        raise SystemExit(f"fail: missing or malformed {name} document")
    return int(match.group(2)), json.loads(match.group(1))

# ext4
rc, report = document("REPAIR_EXT4")
if rc != 0:
    raise SystemExit(f"fail: ext4 repair exited {rc}: {report}")
assert report["kind"] == "repair_fs", report
payload = report["payload"]
assert payload["final_outcome"] in ("clean", "repaired", "repaired_with_risk"), payload["final_outcome"]
assert payload["selected_tool"] == "e2fsck", payload["selected_tool"]
# ext4 corruption SHOULD have triggered errors_corrected -> "repaired".
assert payload["final_outcome"] == "repaired", f"ext4 expected repaired, got {payload['final_outcome']}"
assert any(a["tool"] == "e2fsck" for a in payload["attempts"]), payload["attempts"]
assert payload["verification_mount"]["mounted"] is True, payload["verification_mount"]
assert payload["cleanup"]["all_clean"] is True, payload["cleanup"]
print("pass: ext4 repair routed to e2fsck, errors corrected, verification mount succeeded, cleanup clean")

# vfat
rc, report = document("REPAIR_VFAT")
if rc != 0:
    raise SystemExit(f"fail: vfat repair exited {rc}: {report}")
payload = report["payload"]
assert payload["selected_tool"] == "fsck_fat", payload["selected_tool"]
assert payload["final_outcome"] in ("clean", "repaired"), payload["final_outcome"]
assert payload["verification_mount"]["mounted"] is True, payload["verification_mount"]
print("pass: vfat repair routed to fsck.fat, repaired, verification mount succeeded")

# btrfs
rc, report = document("REPAIR_BTRFS")
payload = report["payload"]
assert payload["selected_tool"] == "btrfs_check", payload["selected_tool"]
attempt_kinds = [(a["kind"], a["high_risk"]) for a in payload["attempts"]]
assert attempt_kinds == [
    ("readonly_check", False),
    ("high_risk_fallback", True),
    ("verification_check", False),
], attempt_kinds
assert payload["final_outcome"] == "repaired_with_risk", payload["final_outcome"]
assert rc == 0, f"btrfs metadata-DUP repair exited {rc}"
first_output = payload["attempts"][0]["stdout"] + payload["attempts"][0]["stderr"]
recheck_output = payload["attempts"][2]["stdout"] + payload["attempts"][2]["stderr"]
assert "checksum verify failed" in first_output, payload["attempts"][0]
assert "checksum verify failed" not in recheck_output, payload["attempts"][2]
print("pass: real Btrfs DUP mirror corruption forced --repair and rechecked clean")

# xfs (optional)
if have_xfs:
    rc, report = document("REPAIR_XFS_CLEAN")
    if rc != 0:
        raise SystemExit(f"fail: xfs clean repair exited {rc}: {report}")
    payload = report["payload"]
    assert payload["selected_tool"] == "xfs_repair", payload["selected_tool"]
    # Normal repair (no -L) is the expected path for the clean image.
    assert not any(a["high_risk"] for a in payload["attempts"]), payload["attempts"]
    assert payload["final_outcome"] in ("clean", "repaired"), payload["final_outcome"]
    print("pass: xfs normal repair path used (no -L fallback)")

    rc, report = document("REPAIR_XFS_DIRTY")
    payload = report["payload"]
    # This image was mounted and written in a first QEMU process that the
    # host killed without unmounting. Normal xfs_repair must refuse the dirty
    # journal, after which the authorised -L fallback must be visible.
    high_risk = [a for a in payload["attempts"] if a["high_risk"]]
    assert high_risk, payload["attempts"]
    assert high_risk[0]["kind"] == "high_risk_fallback", high_risk[0]
    assert payload["final_outcome"] == "repaired_with_risk", payload["final_outcome"]
    assert rc == 0, f"xfs dirty-log fallback exited {rc}"
    print("pass: real unclean XFS log forced -L and was flagged repaired_with_risk")
else:
    print("skip: xfs tools unavailable on host; xfs repair assertions skipped")

# Cleanup: no residual session mounts.
if "===SESSION_RESIDUAL=== no" not in text:
    raise SystemExit("fail: residual session mounts left under /run/catos-system/sessions")
print("pass: no residual session mounts after repair flow")

print("pass: QEMU repair smoke test succeeded for all available filesystems")
PY
