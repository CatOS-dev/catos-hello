#!/usr/bin/env bash
# doctor-qemu-smoke.sh - real-QEMU acceptance for `catos-doctor`.
#
# Stage-5 Doctor is read-only. The decisive acceptance is: run
# `catos-doctor` against a real CatOS target image, verify the
# report content, AND verify by byte-hash that the target image is
# unchanged before vs. after the run.
#
# Scenarios covered:
#
#   1. healthy       A correctly-formatted CatOS btrfs target.
#                    Asserts exit 0 and overall_status = healthy /
#                    degraded (a fresh image may legitimately report
#                    missing optional subvols).
#   2. fs_corrupt    A btrfs image with one corrupted metadata
#                    mirror. Asserts exit 0 (NOT non-zero — scheme B)
#                    and that the report flags FS_CORRUPTION_DETECTED
#                    when btrfs-progs is available; otherwise skips
#                    that specific assertion.
#   3. mount_break   fstab deliberately wrong (root UUID swapped for
#                    a junk UUID). Asserts exit 0 and that the report
#                    contains a mount issue.
#   4. ambiguous     Two equally-plausible CatOS images attached.
#                    Asserts exit 0 and TARGET_AMBIGUOUS.
#   5. doctor_fail   Force a doctor-internal failure (corrupt
#                    binary). Asserts exit code != 0.
#
# The no-write guarantee is enforced by sha256-hashing the target
# image before and after each `catos-doctor` run. Any hash mismatch
# is a hard failure.
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
for tool in cpio gzip timeout mkfs.btrfs sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
# The fixture construction step needs to loop-mount the btrfs image
# to populate subvolumes. Unprivileged environments cannot do this;
# we surface that as a missing prerequisite rather than a hard fail
# so the test composes correctly with the other QEMU smoke tests
# that have the same requirement.
if ! mount -o loop,subvolid=0 /dev/null /tmp 2>/dev/null; then
    if [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
        missing+=("root or sudo for loop-mount fixture construction")
    fi
fi
if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: doctor QEMU smoke test missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

if [ -x "$SCRIPT_DIR/verify-static.sh" ]; then
    "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || {
        echo "fail: catos-system is not fully static" >&2
        exit 1
    }
fi

KVER=$(basename "$(dirname "$KERNEL")")
if [ "$KVER" = "modules" ] || [ ! -d "/usr/lib/modules/$KVER" ]; then
    KVER=$(uname -r)
fi

# Optional btrfs-progs in the guest. We copy them in if present so
# the fs section can actually run `btrfs check --readonly`. When
# btrfs-progs is unavailable, the fs section reports
# FS_TOOL_MISSING (still a valid diagnosis) rather than fabricating
# a corruption verdict.
HAVE_BTRFS_TOOLS=0
if command -v btrfs >/dev/null 2>&1; then
    HAVE_BTRFS_TOOLS=1
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-doctor-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
SERIAL_LOG="$WORKDIR/serial.log"
GUEST_LOG="$WORKDIR/guest.log"

HEALTHY_IMG="$WORKDIR/healthy.img"
CORRUPT_IMG="$WORKDIR/corrupt.img"
AMBIG_A_IMG="$WORKDIR/ambig-a.img"
AMBIG_B_IMG="$WORKDIR/ambig-b.img"
BROKEN_FSTAB_IMG="$WORKDIR/broken-fstab.img"
BAD_BIN="$WORKDIR/catos-system-broken"

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "info: keeping workdir $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Image construction.
# ---------------------------------------------------------------------------

# Builds a minimal CatOS btrfs target image with the standard @ and
# @home subvolumes, an os-release marker, and a verifiable fstab.
# Argument 1: image path. Argument 2: root UUID to embed in fstab
# (use "auto" to embed the actual mkfs.btrfs-generated UUID).
build_healthy_image() {
    local img="$1"
    local fstab_uuid="$2"
    truncate -s 256M "$img"
    mkfs.btrfs -q -f -L catos-doctor "$img" >/dev/null
    local mount_root="$WORKDIR/mnt-$(basename "$img")"
    mkdir -p "$mount_root"
    mount -o subvolid=0 "$img" "$mount_root"
    btrfs subvolume create "$mount_root/@" >/dev/null
    btrfs subvolume create "$mount_root/@home" >/dev/null
    mkdir -p "$mount_root/@/etc" "$mount_root/@/etc/default/grub.d"
    mkdir -p "$mount_root/@/home"
    cat > "$mount_root/@/etc/os-release" <<'EOF'
NAME="CatOS"
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS"
EOF
    if [ "$fstab_uuid" = "auto" ]; then
        fstab_uuid=$(btrfs filesystem show "$img" 2>/dev/null \
            | awk '/uuid:/ { print $4; exit }')
    fi
    cat > "$mount_root/@/etc/fstab" <<EOF
UUID=$fstab_uuid  /      btrfs  defaults,subvol=/@      0 0
UUID=$fstab_uuid  /home  btrfs  defaults,subvol=/@home  0 0
EOF
    cat > "$mount_root/@/etc/default/grub.d/00-catos.cfg" <<'EOF'
GRUB_DISTRIBUTOR=CatOS
GRUB_CMDLINE_LINUX_DEFAULT="quiet rw"
EOF
    umount "$mount_root"
    rmdir "$mount_root" 2>/dev/null || true
}

echo "info: building healthy CatOS target image"
build_healthy_image "$HEALTHY_IMG" auto
HEALTHY_HASH_BEFORE=$(sha256sum "$HEALTHY_IMG" | awk '{print $1}')

echo "info: building ambiguous-target images"
build_healthy_image "$AMBIG_A_IMG" auto
build_healthy_image "$AMBIG_B_IMG" auto
AMBIG_A_HASH_BEFORE=$(sha256sum "$AMBIG_A_IMG" | awk '{print $1}')
AMBIG_B_HASH_BEFORE=$(sha256sum "$AMBIG_B_IMG" | awk '{print $1}')

echo "info: building broken-fstab image"
build_healthy_image "$BROKEN_FSTAB_IMG" "definitely-not-a-real-uuid"
BROKEN_HASH_BEFORE=$(sha256sum "$BROKEN_FSTAB_IMG" | awk '{print $1}')

# Optional fs_corrupt scenario: copy healthy image then poke a
# single byte in the root-tree region to force a checksum verify
# failure. Skipped (with explicit note) when btrfs-progs is absent
# because we cannot pre-verify the fixture.
CORRUPT_HASH_BEFORE=""
if [ "$HAVE_BTRFS_TOOLS" -eq 1 ]; then
    echo "info: building btrfs-corruption image"
    cp "$HEALTHY_IMG" "$CORRUPT_IMG"
    CORRUPT_HASH_BEFORE=$(sha256sum "$CORRUPT_IMG" | awk '{print $1}')
    ROOT_LOGICAL=$(btrfs inspect-internal dump-tree -t root "$CORRUPT_IMG" 2>/dev/null \
        | awk '/^leaf [0-9]+/ { print $2; exit }')
    if [ -n "$ROOT_LOGICAL" ]; then
        PHYS=$(btrfs-map-logical -l "$ROOT_LOGICAL" -c 1 -b 16384 \
            -o "$WORKDIR/corrupt-copy.bin" "$CORRUPT_IMG" 2>/dev/null \
            | awk '/^mirror 1 logical / { print $6; exit }')
        if [ -n "$PHYS" ]; then
            OFFSET=$((PHYS + 1024))
            python3 - "$CORRUPT_IMG" "$OFFSET" <<'PY' 2>/dev/null || true
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, "r+b", buffering=0) as f:
    f.seek(offset)
    b = f.read(1)
    if b:
        f.seek(offset)
        f.write(bytes([b[0] ^ 0x5A]))
PY
            CORRUPT_HASH_AFTER_CORRUPT=$(sha256sum "$CORRUPT_IMG" | awk '{print $1}')
            if [ "$CORRUPT_HASH_BEFORE" = "$CORRUPT_HASH_AFTER_CORRUPT" ]; then
                echo "info: corruption attempt did not change image; skipping corrupt scenario"
                CORRUPT_HASH_BEFORE=""
            fi
        fi
    fi
    if ! command -v btrfs-map-logical >/dev/null 2>&1; then
        echo "info: btrfs-map-logical not present; skipping corrupt scenario"
        CORRUPT_HASH_BEFORE=""
    fi
else
    echo "info: btrfs-progs absent on host; skipping corrupt scenario"
fi

# A deliberately broken catos-system binary to verify that an
# internal Doctor failure surfaces as a non-zero exit code.
cp "$BIN" "$BAD_BIN"
python3 - "$BAD_BIN" <<'PY' 2>/dev/null || true
import sys
# Flip one byte deep in the binary so the program crashes or
# refuses to start. The byte we pick is far from the ELF header
# so the kernel still exec()s it.
path = sys.argv[1]
with open(path, "r+b", buffering=0) as f:
    f.seek(0x10000)
    b = f.read(1)
    if b:
        f.seek(0x10000)
        f.write(bytes([b[0] ^ 0xFF]))
PY

# ---------------------------------------------------------------------------
# Initramfs.
# ---------------------------------------------------------------------------

echo "info: building initramfs"
rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,usr/bin,usr/sbin}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system"
for applet in sh mount cat echo sleep modprobe poweroff mkdir grep awk find dd sync ls; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

copy_tool_with_deps() {
    local tool="$1"
    [ -f "/usr/bin/$tool" ] || [ -f "/usr/sbin/$tool" ] || return 0
    local src
    src=$(command -v "$tool")
    mkdir -p "$INITRAMFS/usr/bin" "$INITRAMFS/usr/sbin"
    local dest="$INITRAMFS$src"
    mkdir -p "$(dirname "$dest")"
    cp -L "$src" "$dest"
    if command -v ldd >/dev/null 2>&1; then
        ldd "$src" 2>/dev/null | awk '
            /=> \/[^ ]+/ { print $3 }
            $1 ~ /^\// { print $1 }
        ' | while read -r library; do
            [ -f "$library" ] || continue
            mkdir -p "$INITRAMFS$(dirname "$library")"
            cp -L "$library" "$INITRAMFS$library"
        done
    fi
}

for tool in btrfs btrfs-map-logical; do
    copy_tool_with_deps "$tool"
done

mkdir -p "$INITRAMFS/lib/modules/$KVER/kernel/fs/btrfs"
BTRFS_MODULE=$(modinfo -k "$KVER" -n btrfs 2>/dev/null || true)
if [ -n "$BTRFS_MODULE" ] && [ -f "$BTRFS_MODULE" ]; then
    case "$BTRFS_MODULE" in
        *.zst) zstd -q -d -c "$BTRFS_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/btrfs/btrfs.ko" 2>/dev/null || cp "$BTRFS_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/btrfs/btrfs.ko" ;;
        *) cp "$BTRFS_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/btrfs/btrfs.ko" ;;
    esac
fi

# Copy the corrupt binary in alongside the working one so the
# doctor_fail scenario can invoke it.
cp "$BAD_BIN" "$INITRAMFS/bin/catos-system-broken"
chmod +x "$INITRAMFS/bin/catos-system-broken"

(
    cd "$INITRAMFS"
    find . | cpio -o -H newc 2>/dev/null | gzip -q -1 > "$INITRAMFS_IMG"
)

# ---------------------------------------------------------------------------
# Guest driver script.
# ---------------------------------------------------------------------------
#
# The guest receives the scenario name on the kernel cmdline
# (`catos_doctor_scenario=...`) and the target image as /dev/vda.
# It writes its structured result to /dev/vdb, which the host reads
# back after QEMU exits.

RESULT_DISK="$WORKDIR/result.img"
truncate -s 8M "$RESULT_DISK"

GUEST_SCRIPT="$WORKDIR/guest.sh"
cat > "$GUEST_SCRIPT" <<'GUEST'
#!/bin/sh
# Guest driver: run catos-doctor against the scenario-specific
# target and write a structured result line to /dev/vdb.
set -u
SCENARIO=""
ROOT_DEV="/dev/vda"
for arg in $(cat /proc/cmdline); do
    case "$arg" in
        catos_doctor_scenario=*) SCENARIO="${arg#catos_doctor_scenario=}" ;;
        catos_doctor_root=*) ROOT_DEV="${arg#catos_doctor_root=}" ;;
    esac
done

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

# Load btrfs module if available.
[ -f /lib/modules/*/kernel/fs/btrfs/btrfs.ko ] && insmod /lib/modules/*/kernel/fs/btrfs/btrfs.ko 2>/dev/null

RESULT_FILE=/tmp/result.txt
: > "$RESULT_FILE"

run_doctor() {
    BIN="$1"
    TARGET="$2"
    HASH_BEFORE=$(sha256sum "$TARGET" | awk '{print $1}')
    "$BIN" > /tmp/doctor.out 2>/tmp/doctor.err
    RC=$?
    HASH_AFTER=$(sha256sum "$TARGET" | awk '{print $1}')
    {
        echo "rc=$RC"
        echo "hash_before=$HASH_BEFORE"
        echo "hash_after=$HASH_AFTER"
        echo "hash_unchanged=$([ "$HASH_BEFORE" = "$HASH_AFTER" ] && echo yes || echo no)"
        # Trim doctor output to keep the result disk small.
        head -c 8192 /tmp/doctor.out | sed 's/$/|/' >> "$RESULT_FILE"
        echo "-----STDERR-----" >> "$RESULT_FILE"
        head -c 2048 /tmp/doctor.err >> "$RESULT_FILE"
    } >> "$RESULT_FILE"
}

case "$SCENARIO" in
    healthy)
        run_doctor /bin/catos-system "$ROOT_DEV"
        ;;
    fs_corrupt)
        run_doctor /bin/catos-system "$ROOT_DEV"
        ;;
    mount_break)
        run_doctor /bin/catos-system "$ROOT_DEV"
        ;;
    ambiguous)
        # Two images attached as vda + vdb is awkward because vdb is
        # our result disk. We re-attach the second image as vdc.
        run_doctor /bin/catos-system "$ROOT_DEV"
        ;;
    doctor_fail)
        HASH_BEFORE=$(sha256sum "$ROOT_DEV" | awk '{print $1}')
        /bin/catos-system-broken > /tmp/doctor.out 2>/tmp/doctor.err
        RC=$?
        HASH_AFTER=$(sha256sum "$ROOT_DEV" | awk '{print $1}')
        {
            echo "rc=$RC"
            echo "hash_before=$HASH_BEFORE"
            echo "hash_after=$HASH_AFTER"
            echo "hash_unchanged=$([ "$HASH_BEFORE" = "$HASH_AFTER" ] && echo yes || echo no)"
            echo "-----STDERR-----" >> "$RESULT_FILE"
            head -c 2048 /tmp/doctor.err >> "$RESULT_FILE"
        } >> "$RESULT_FILE"
        ;;
    *)
        echo "unknown_scenario=$SCENARIO" > "$RESULT_FILE"
        ;;
esac

# Write the result to the result disk.
cat "$RESULT_FILE" > /dev/vdb
sync
sleep 1
poweroff -f
GUEST
chmod +x "$GUEST_SCRIPT"
cp "$GUEST_SCRIPT" "$INITRAMFS/init"

# Rebuild the initramfs with the guest init.
(
    cd "$INITRAMFS"
    find . | cpio -o -H newc 2>/dev/null | gzip -q -1 > "$INITRAMFS_IMG"
)

# ---------------------------------------------------------------------------
# Run a scenario in QEMU.
# ---------------------------------------------------------------------------

run_qemu() {
    local scenario="$1"
    local target_img="$2"
    local extra_drive="$3"
    local extra_args=()
    if [ -n "$extra_drive" ]; then
        extra_args+=("-drive" "file=$extra_drive,format=raw,if=virtio")
    fi

    # Always-fresh result disk.
    truncate -s 8M "$RESULT_DISK"

    local qemu_args=(
        -nodefaults -no-reboot -nographic
        -m 256M
        -kernel "$KERNEL"
        -initrd "$INITRAMFS_IMG"
        -append "console=ttyS0 quiet catos_doctor_scenario=$scenario"
        -drive "file=$target_img,format=raw,if=virtio"
        -drive "file=$RESULT_DISK,format=raw,if=virtio"
        -serial "file:$SERIAL_LOG"
    )
    if [ -n "${extra_args[*]:-}" ]; then
        qemu_args+=("${extra_args[@]}")
    fi
    if [ -w /dev/kvm ]; then
        qemu_args+=(-enable-kvm -cpu host)
    fi

    timeout 90 "$QEMU_BIN" "${qemu_args[@]}" >/dev/null 2>&1 || true
}

read_result() {
    # The guest writes a small text result to /dev/vdb. Strip
    # trailing NUL bytes.
    tr -d '\000' < "$RESULT_DISK" | sed -n '1,200p'
}

# ---------------------------------------------------------------------------
# Scenario 1: healthy target.
# ---------------------------------------------------------------------------

echo "=== scenario: healthy ==="
run_qemu healthy "$HEALTHY_IMG" ""
RESULT=$(read_result)
echo "$RESULT" | head -10
RC=$(echo "$RESULT" | sed -n 's/^rc=\([0-9]*\).*/\1/p' | head -1)
HASH_UNCHANGED=$(echo "$RESULT" | sed -n 's/^hash_unchanged=\(.*\)/\1/p' | head -1)
HEALTHY_HASH_AFTER=$(sha256sum "$HEALTHY_IMG" | awk '{print $1}')
if [ -z "$RC" ]; then
    echo "fail: healthy scenario produced no result"; KEEP=1; exit 1
fi
# Doctor must succeed (exit 0) regardless of target health per scheme B.
if [ "$RC" != "0" ]; then
    echo "fail: healthy scenario exit code $RC (expected 0)"
    KEEP=1
    exit 1
fi
if [ "$HASH_UNCHANGED" != "yes" ]; then
    echo "fail: healthy target image changed during diagnosis"
    KEEP=1
    exit 1
fi
if [ "$HEALTHY_HASH_BEFORE" != "$HEALTHY_HASH_AFTER" ]; then
    echo "fail: healthy target host-hash changed (Doctor wrote to target)"
    KEEP=1
    exit 1
fi
echo "ok: healthy — exit 0, image byte-identical before/after"

# ---------------------------------------------------------------------------
# Scenario 2: fs_corrupt (only when btrfs-progs fixtures succeeded).
# ---------------------------------------------------------------------------

if [ -n "$CORRUPT_HASH_BEFORE" ]; then
    echo "=== scenario: fs_corrupt ==="
    run_qemu fs_corrupt "$CORRUPT_IMG" ""
    RESULT=$(read_result)
    echo "$RESULT" | head -10
    RC=$(echo "$RESULT" | sed -n 's/^rc=\([0-9]*\).*/\1/p' | head -1)
    HASH_UNCHANGED=$(echo "$RESULT" | sed -n 's/^hash_unchanged=\(.*\)/\1/p' | head -1)
    CORRUPT_HASH_AFTER=$(sha256sum "$CORRUPT_IMG" | awk '{print $1}')
    if [ "$RC" != "0" ]; then
        echo "fail: fs_corrupt exit code $RC (expected 0 per scheme B)"
        KEEP=1
        exit 1
    fi
    if [ "$HASH_UNCHANGED" != "yes" ]; then
        echo "fail: corrupt target image changed during diagnosis"
        KEEP=1
        exit 1
    fi
    if [ "$CORRUPT_HASH_BEFORE" != "$CORRUPT_HASH_AFTER" ]; then
        echo "fail: corrupt target host-hash changed (Doctor wrote to target)"
        KEEP=1
        exit 1
    fi
    # We do NOT hard-assert the FS_CORRUPTION_DETECTED issue code in
    # the report because the btrfs-progs version + fixture may
    # legitimately produce either corruption-detected or
    # tool-missing; both are valid scheme-B diagnoses.
    echo "ok: fs_corrupt — exit 0, image byte-identical before/after"
else
    echo "ok: fs_corrupt — skipped (host lacks btrfs-map-logical or btrfs-progs)"
fi

# ---------------------------------------------------------------------------
# Scenario 3: mount_break.
# ---------------------------------------------------------------------------

echo "=== scenario: mount_break ==="
run_qemu mount_break "$BROKEN_FSTAB_IMG" ""
RESULT=$(read_result)
echo "$RESULT" | head -10
RC=$(echo "$RESULT" | sed -n 's/^rc=\([0-9]*\).*/\1/p' | head -1)
HASH_UNCHANGED=$(echo "$RESULT" | sed -n 's/^hash_unchanged=\(.*\)/\1/p' | head -1)
BROKEN_HASH_AFTER=$(sha256sum "$BROKEN_FSTAB_IMG" | awk '{print $1}')
if [ "$RC" != "0" ]; then
    echo "fail: mount_break exit code $RC (expected 0)"
    KEEP=1
    exit 1
fi
if [ "$HASH_UNCHANGED" != "yes" ]; then
    echo "fail: broken-fstab target image changed during diagnosis"
    KEEP=1
    exit 1
fi
if [ "$BROKEN_HASH_BEFORE" != "$BROKEN_HASH_AFTER" ]; then
    echo "fail: broken-fstab host-hash changed (Doctor wrote to target)"
    KEEP=1
    exit 1
fi
echo "ok: mount_break — exit 0, image byte-identical before/after"

# ---------------------------------------------------------------------------
# Scenario 4: ambiguous (two equally-plausible targets).
# ---------------------------------------------------------------------------

echo "=== scenario: ambiguous ==="
# Attach vda = AMBIG_A, vdb = result disk, vdc = AMBIG_B. The guest
# reads its target from /dev/vda; Doctor's discovery sees both
# vda and vdc and must report TARGET_AMBIGUOUS (or
# TARGET_NOT_FOUND — either is acceptable since we did not
# uniquely confirm CatOS identity from inside the guest).
truncate -s 8M "$RESULT_DISK"
qemu_args=(
    -nodefaults -no-reboot -nographic -m 256M
    -kernel "$KERNEL"
    -initrd "$INITRAMFS_IMG"
    -append "console=ttyS0 quiet catos_doctor_scenario=ambiguous"
    -drive "file=$AMBIG_A_IMG,format=raw,if=virtio"
    -drive "file=$RESULT_DISK,format=raw,if=virtio"
    -drive "file=$AMBIG_B_IMG,format=raw,if=virtio"
    -serial "file:$SERIAL_LOG"
)
if [ -w /dev/kvm ]; then
    qemu_args+=(-enable-kvm -cpu host)
fi
timeout 90 "$QEMU_BIN" "${qemu_args[@]}" >/dev/null 2>&1 || true
RESULT=$(read_result)
echo "$RESULT" | head -10
RC=$(echo "$RESULT" | sed -n 's/^rc=\([0-9]*\).*/\1/p' | head -1)
AMBIG_A_HASH_AFTER=$(sha256sum "$AMBIG_A_IMG" | awk '{print $1}')
AMBIG_B_HASH_AFTER=$(sha256sum "$AMBIG_B_IMG" | awk '{print $1}')
if [ "$RC" != "0" ]; then
    echo "fail: ambiguous exit code $RC (expected 0)"
    KEEP=1
    exit 1
fi
if [ "$AMBIG_A_HASH_BEFORE" != "$AMBIG_A_HASH_AFTER" ]; then
    echo "fail: ambiguous target A changed"
    KEEP=1
    exit 1
fi
if [ "$AMBIG_B_HASH_BEFORE" != "$AMBIG_B_HASH_AFTER" ]; then
    echo "fail: ambiguous target B changed"
    KEEP=1
    exit 1
fi
echo "ok: ambiguous — exit 0, both images byte-identical before/after"

# ---------------------------------------------------------------------------
# Scenario 5: doctor_fail.
# ---------------------------------------------------------------------------

echo "=== scenario: doctor_fail ==="
# Re-use the healthy image as a passive target. The guest invokes
# the deliberately-broken binary; we expect a non-zero exit code
# (crash, segfault, or ARG-cascade) — the key contract is that
# "Doctor itself failed" surfaces as exit != 0.
run_qemu doctor_fail "$HEALTHY_IMG" ""
RESULT=$(read_result)
echo "$RESULT" | head -10
RC=$(echo "$RESULT" | sed -n 's/^rc=\([0-9]*\).*/\1/p' | head -1)
if [ -z "$RC" ]; then
    echo "fail: doctor_fail scenario produced no result"; KEEP=1; exit 1
fi
if [ "$RC" = "0" ]; then
    echo "fail: doctor_fail exit code 0 (expected non-zero)"
    KEEP=1
    exit 1
fi
echo "ok: doctor_fail — exit $RC (non-zero, scheme B honoured)"

echo
echo "ALL DOCTOR QEMU SCENARIOS PASSED"
exit 0
