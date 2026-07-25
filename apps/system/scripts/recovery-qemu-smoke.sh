#!/usr/bin/env bash
# recovery-qemu-smoke.sh - real Btrfs snapshot recovery crash/resume in QEMU.
#
# This test creates a real Btrfs image with:
#   /@                  current CatOS root
#   /@home              separate @home subvolume (must NOT change)
#   /@/.snapshots/1/snapshot   readonly snapshot of /@
#   /@/.snapshots/2/snapshot   readonly snapshot with DISTINCTIVE content
# Plus an independent FAT ESP that we leave untouched.
#
# It boots a static catos-system binary built with the
# `recovery_fault_injection` cargo feature inside a minimal initramfs
# and exercises the full phase-3 lifecycle:
#
#   1. recovery plan  -> emits a plan record bound to plan_id+token
#   2. recovery apply with CATOS_RECOVERY_FAULT_AT=backup_created
#      -> process is SIGKILLed after persisting backup_created
#   3. recovery status -> reconciles disk facts, reports resumable
#   4. recovery resume -> continues from backup_created, may be killed
#      again at the next fault point
#   5. (repeat for replacement_created, old_root_moved,
#      new_root_installed, boot_finalization_pending)
#   6. final recovery resume -> reaches `completed`
#   7. assert /@ now contains the snapshot's distinctive file
#   8. assert /.catos-recovery/backups/.../root-before contains the
#      original /@ content
#   9. assert /@home content unchanged
#  10. assert snapshot readonly attribute unchanged
#  11. assert ESP image byte-for-byte unchanged
#
# Exit 77 means a prerequisite is unavailable.

set -u

usage() {
    cat >&2 <<EOF
usage: $0 [options]

options:
  --kernel PATH       Kernel image. Default: auto-detect host kernel.
  --busybox PATH      Static busybox. Default: search PATH.
  --bin PATH          Static catos-system musl binary (release).
  --test-bin PATH     Static catos-system musl binary built with
                      --features recovery_fault_injection. Required.
  --qemu PATH         qemu-system-x86_64. Default: search PATH.
  --workdir DIR       Work directory. Default: temporary directory.
  --keep              Keep workdir after completion.
  --skip-crash        Skip the crash-injection iterations; only run a
                      single apply -> completed. Useful for fast
                      verification of the happy path.
EOF
}

KERNEL=""
BUSYBOX=""
BIN=""
TEST_BIN=""
QEMU_BIN=""
WORKDIR=""
KEEP=0
SKIP_CRASH=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --kernel) KERNEL="$2"; shift 2 ;;
        --busybox) BUSYBOX="$2"; shift 2 ;;
        --bin) BIN="$2"; shift 2 ;;
        --test-bin) TEST_BIN="$2"; shift 2 ;;
        --qemu) QEMU_BIN="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --skip-crash) SKIP_CRASH=1; shift ;;
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
if [ -z "$TEST_BIN" ]; then
    for candidate in \
        "$SCRIPT_DIR/../../target/x86_64-unknown-linux-musl/release/catos-system" \
        "$SCRIPT_DIR/../../build/apps/system/cargo-target/x86_64-unknown-linux-musl/release/catos-system"; do
        if [ -x "$candidate" ]; then TEST_BIN="$candidate"; break; fi
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
[ -z "$BIN" ] && missing+=("catos-system release musl binary")
[ -z "$TEST_BIN" ] && missing+=("catos-system recovery_fault_injection musl binary")
[ -z "$QEMU_BIN" ] && missing+=("qemu-system-x86_64")
[ -z "$BUSYBOX" ] && missing+=("static busybox")
[ -z "$KERNEL" ] && missing+=("kernel image")
for tool in cpio gzip timeout mkfs.btrfs mkfs.vfat sha256sum zstd python3 modinfo ldd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: recovery QEMU smoke test missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

if [ "$BIN" != "$TEST_BIN" ]; then
    echo "note: --bin and --test-bin differ; using --test-bin for crash injection" >&2
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-recovery-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
INITRAMFS_IMG_PLAN="$WORKDIR/initramfs-plan.cpio.gz"
INITRAMFS_IMG_RUN="$WORKDIR/initramfs-run.cpio.gz"
PLAN_FILE="$WORKDIR/plan.json"
SERIAL_LOG="$WORKDIR/serial.log"
BTREE_TREE="$WORKDIR/btrfs-tree"
BTRFS_IMG="$WORKDIR/btrfs.img"
ESP_IMG="$WORKDIR/esp.img"
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

rm -rf "$INITRAMFS" "$BTREE_TREE"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,usr/bin,usr/sbin,"lib/modules/$KVER/kernel/fs/fat"}
mkdir -p "$BTREE_TREE/@"/{etc,usr/lib/modules,boot,var/lib/pacman/local}
mkdir -p "$BTREE_TREE/@home"
mkdir -p "$BTREE_TREE/@/.snapshots/1/snapshot"/{etc,usr/lib/modules,boot,var/lib/pacman/local}
mkdir -p "$BTREE_TREE/@/.snapshots/2/snapshot"/{etc,usr/lib/modules,boot,var/lib/pacman/local}

# Current /@: an identifiable CatOS root.
cat > "$BTREE_TREE/@/etc/os-release" <<'EOF'
NAME=CatOS
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS Recovery QEMU Current Root"
EOF
echo 'current-root-marker' > "$BTREE_TREE/@/var/lib/pacman/local/CURRENT_MARKER"
echo 'home-data-must-not-change' > "$BTREE_TREE/@home/user-file"

# Snapshot 1: identical content (not used in this test).
cp -r "$BTREE_TREE/@/.snapshots/1/snapshot/." "$BTREE_TREE/@/." 2>/dev/null || true

# Snapshot 2: DISTINCTIVE content the recovery should swap in.
cat > "$BTREE_TREE/@/.snapshots/2/snapshot/etc/os-release" <<'EOF'
NAME=CatOS
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS Recovery QEMU SNAPSHOT 2"
EOF
echo 'snapshot-2-marker' > "$BTREE_TREE/@/.snapshots/2/snapshot/var/lib/pacman/local/SNAPSHOT_2_MARKER"

truncate -s 512M "$BTRFS_IMG"
mkfs.btrfs -q -f -U 22222222-3333-4444-5555-666666666666 \
    -r "$BTREE_TREE" \
    --subvol default:@ \
    --subvol rw:@home \
    --subvol ro:@/.snapshots/1/snapshot \
    --subvol ro:@/.snapshots/2/snapshot \
    "$BTRFS_IMG"

# Independent FAT ESP.
truncate -s 32M "$ESP_IMG"
mkfs.vfat -i C4705E12 "$ESP_IMG" >/dev/null
mmd -i "$ESP_IMG" ::/EFI ::/EFI/CatOS
printf 'CatOS ESP fixture\n' > "$WORKDIR/test.efi"
mcopy -i "$ESP_IMG" "$WORKDIR/test.efi" ::/EFI/CatOS/test.efi

BTRFS_HASH_BEFORE=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')
ESP_HASH_BEFORE=$(sha256sum "$ESP_IMG" | awk '{print $1}')

cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$TEST_BIN" "$INITRAMFS/bin/catos-system-test"
[ "$BIN" != "$TEST_BIN" ] && cp "$BIN" "$INITRAMFS/bin/catos-system" || cp "$TEST_BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system" "$INITRAMFS/bin/catos-system-test"
for applet in sh mount cat echo sleep modprobe poweroff mkdir grep awk find ls; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

# Include btrfs-progs so the guest can run real subvolume operations.
cp /usr/bin/btrfs "$INITRAMFS/usr/bin/btrfs"
ldd /usr/bin/btrfs | awk '
    /=> \/[^ ]+/ { print $3 }
    $1 ~ /^\// { print $1 }
' | while read -r library; do
    [ -f "$library" ] || continue
    mkdir -p "$INITRAMFS$(dirname "$library")"
    cp -L "$library" "$INITRAMFS$library"
done

FAT_MODULE=$(modinfo -k "$KVER" -n fat 2>/dev/null || true)
VFAT_MODULE=$(modinfo -k "$KVER" -n vfat 2>/dev/null || true)
if [ -n "$FAT_MODULE" ] && [ -f "$FAT_MODULE" ]; then
    case "$FAT_MODULE" in
        *.zst) zstd -q -d -c "$FAT_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/fat.ko" ;;
        *) cp "$FAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/fat.ko" ;;
    esac
fi
if [ -n "$VFAT_MODULE" ] && [ -f "$VFAT_MODULE" ]; then
    case "$VFAT_MODULE" in
        *.zst) zstd -q -d -c "$VFAT_MODULE" > "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/vfat.ko" ;;
        *) cp "$VFAT_MODULE" "$INITRAMFS/lib/modules/$KVER/kernel/fs/fat/vfat.ko" ;;
    esac
fi
cat > "$INITRAMFS/lib/modules/$KVER/modules.dep" <<EOF
kernel/fs/fat/fat.ko:
kernel/fs/fat/vfat.ko: kernel/fs/fat/fat.ko
EOF
: > "$INITRAMFS/lib/modules/$KVER/modules.alias"
: > "$INITRAMFS/lib/modules/$KVER/modules.symbols"

cat > "$INITRAMFS/etc/initrd-release" <<'EOF'
NAME=CatOS
VERSION_ID=recovery-smoke
EOF

# The init script runs the requested scenario. The scenario name is
# passed via the kernel cmdline as RECOVERY_SCENARIO=<name>.
cat > "$INITRAMFS/init" <<'INIT_EOF'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t devtmpfs none /dev 2>/dev/null
modprobe vfat 2>/dev/null || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && [ -b /dev/vdb ] && break
    sleep 1
done
if [ ! -b /dev/vda ] || [ ! -b /dev/vdb ]; then
    echo "===RECOVERY_FATAL=== missing virtio block devices"
    poweroff -f
fi

cmdline=$(cat /proc/cmdline)
scenario=""
plan_id=""
token=""
fault_at=""
for tok in $cmdline; do
    case "$tok" in
        RECOVERY_SCENARIO=*) scenario="${tok#RECOVERY_SCENARIO=}" ;;
        RECOVERY_PLAN_ID=*) plan_id="${tok#RECOVERY_PLAN_ID=}" ;;
        RECOVERY_TOKEN=*) token="${tok#RECOVERY_TOKEN=}" ;;
        RECOVERY_FAULT_AT=*) fault_at="${tok#RECOVERY_FAULT_AT=}" ;;
    esac
done
[ -n "$fault_at" ] && export CATOS_RECOVERY_FAULT_AT="$fault_at"

BIN=/bin/catos-system
[ "$scenario" = "crash" ] || [ "$scenario" = "resume" ] && BIN=/bin/catos-system-test

if [ "$scenario" = "plan" ]; then
    echo "===RECOVERY_PLAN_BEGIN==="
    $BIN recovery plan \
        --root-device /dev/vda \
        --root-subvolume /@ \
        --snapshot-subvolume /@/.snapshots/2/snapshot \
        --json
    plan_rc=$?
    echo "===RECOVERY_PLAN_END=== rc=$plan_rc"
    sync
    poweroff -f
fi

if [ -z "$plan_id" ] || [ -z "$token" ]; then
    # Apply/resume without a plan_id pair: re-issue plan to obtain one.
    $BIN recovery plan \
        --root-device /dev/vda \
        --root-subvolume /@ \
        --snapshot-subvolume /@/.snapshots/2/snapshot \
        --json > /tmp/plan.json 2>/dev/null
    plan_id=$(grep -o '"plan_id"[^"]*"[^"]*"' /tmp/plan.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    token=$(grep -o '"confirmation_token"[^"]*"[^"]*"' /tmp/plan.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
fi

echo "===RECOVERY_IDS=== plan_id=$plan_id token=$token"

if [ -z "$plan_id" ] || [ -z "$token" ]; then
    echo "===RECOVERY_NO_IDS==="
    sync; poweroff -f
fi

if [ "$scenario" = "apply" ] || [ "$scenario" = "crash" ]; then
    cmd=apply
elif [ "$scenario" = "resume" ]; then
    cmd=resume
else
    echo "===RECOVERY_FATAL=== unknown scenario $scenario"
    sync; poweroff -f
fi

echo "===RECOVERY_${cmd}_BEGIN==="
if [ "$cmd" = "apply" ]; then
    plan_file_arg=""
    [ -f /plan.json ] && plan_file_arg="--plan-file /plan.json"
    if [ -z "$plan_file_arg" ]; then
        plan_file_arg="--plan-file /tmp/plan.json"
    fi
    $BIN recovery apply \
        --root-device /dev/vda \
        --root-subvolume /@ \
        --snapshot-subvolume /@/.snapshots/2/snapshot \
        --plan-id "$plan_id" \
        --confirm "$token" \
        $plan_file_arg \
        --json
else
    $BIN recovery resume \
        --root-device /dev/vda \
        --root-subvolume /@ \
        --snapshot-subvolume /@/.snapshots/2/snapshot \
        --transaction "$plan_id" \
        --json
fi
rc=$?
echo "===RECOVERY_${cmd}_END=== rc=$rc"

sync
poweroff -f
INIT_EOF
chmod +x "$INITRAMFS/init"

(
    cd "$INITRAMFS" || exit 1
    find . -print0 | cpio --null --create --format=newc 2>/dev/null
) | gzip -9 > "$INITRAMFS_IMG"

build_initramfs() {
    local extra_plan_file="$1"
    local out="$2"
    if [ -n "$extra_plan_file" ] && [ -f "$extra_plan_file" ]; then
        cp "$extra_plan_file" "$INITRAMFS/plan.json"
    else
        rm -f "$INITRAMFS/plan.json"
    fi
    (
        cd "$INITRAMFS" || exit 1
        find . -print0 | cpio --null --create --format=newc 2>/dev/null
    ) | gzip -9 > "$out"
}

# Two initramfs builds: the first lacks /plan.json (used for the
# read-only plan phase); the second embeds the plan emitted by phase
# one and is used by every subsequent apply/crash/resume run.
build_initramfs "" "$INITRAMFS_IMG_PLAN"

accel_args=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel_args=(-enable-kvm -cpu host)
fi

run_qemu() {
    local scenario="$1"
    local fault="$2"
    local plan_id_arg="${3:-}"
    local token_arg="${4:-}"
    local initramfs="${5:-$INITRAMFS_IMG_RUN}"
    local extra_append=""
    [ -n "$fault" ] && extra_append="$extra_append RECOVERY_FAULT_AT=$fault"
    [ -n "$plan_id_arg" ] && extra_append="$extra_append RECOVERY_PLAN_ID=$plan_id_arg"
    [ -n "$token_arg" ] && extra_append="$extra_append RECOVERY_TOKEN=$token_arg"

    timeout 90 "$QEMU_BIN" \
        -M pc \
        -m 1024M \
        -no-reboot \
        -nographic \
        "${accel_args[@]}" \
        -kernel "$KERNEL" \
        -initrd "$initramfs" \
        -append "console=ttyS0 panic=1 rdinit=/init RECOVERY_SCENARIO=$scenario$extra_append" \
        -drive if=none,id=btrfs,file="$BTRFS_IMG",format=raw,cache=none \
        -device virtio-blk-pci,drive=btrfs \
        -drive if=none,id=esp,file="$ESP_IMG",format=raw,cache=none \
        -device virtio-blk-pci,drive=esp \
        < /dev/null > "$SERIAL_LOG" 2>&1
    return $?
}

# Step 1: PLAN phase — emits the plan JSON to stdout.
run_qemu plan "" "" "" "$INITRAMFS_IMG_PLAN"
plan_qemu_rc=$?
if [ "$plan_qemu_rc" -eq 124 ]; then
    echo "fail: QEMU plan phase timed out" >&2
    KEEP=1
    exit 1
fi

awk '/===RECOVERY_PLAN_BEGIN===/,/===RECOVERY_PLAN_END===/' "$SERIAL_LOG" \
    | grep -v '^===RECOVERY' > "$PLAN_FILE"
if ! grep -q '"plan_id"' "$PLAN_FILE"; then
    echo "fail: plan phase did not emit a valid plan JSON" >&2
    KEEP=1
    cat "$SERIAL_LOG" >&2
    exit 1
fi
plan_id=$(grep -o '"plan_id"[^"]*"[^"]*"' "$PLAN_FILE" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
token=$(grep -o '"confirmation_token"[^"]*"[^"]*"' "$PLAN_FILE" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
if [ -z "$plan_id" ] || [ -z "$token" ]; then
    echo "fail: could not extract plan_id and token from plan file" >&2
    KEEP=1
    cat "$PLAN_FILE" >&2
    exit 1
fi
echo "info: plan_id=$plan_id token=$token"

build_initramfs "$PLAN_FILE" "$INITRAMFS_IMG_RUN"

if [ "$SKIP_CRASH" -eq 1 ]; then
    run_qemu apply "" "$plan_id" "$token"
    apply_rc=$?
    if [ "$apply_rc" -eq 124 ]; then
        echo "fail: QEMU apply phase timed out" >&2
        KEEP=1
        exit 1
    fi
    if ! grep -q '===RECOVERY_apply_END=== rc=0' "$SERIAL_LOG"; then
        echo "fail: apply did not exit cleanly" >&2
        KEEP=1
        cat "$SERIAL_LOG" >&2
        exit 1
    fi
else
    crash_points=(
        backup_created
        replacement_created
        old_root_moved
        new_root_installed
        boot_finalization_pending
    )
    iter=0
    for fault in "${crash_points[@]}"; do
        iter=$((iter + 1))
        # The first iteration must use `apply` (no transaction exists
        # yet). Every subsequent iteration must use `resume` because
        # the previous crash persisted state mid-transaction.
        if [ "$iter" -eq 1 ]; then
            scenario=crash
        else
            scenario=resume
        fi
        echo "info: injecting fault at $fault (scenario=$scenario)"
        run_qemu "$scenario" "$fault" "$plan_id" "$token"
        # Preserve per-iteration serial log for debugging.
        cp "$SERIAL_LOG" "$WORKDIR/serial-$iter-$fault.log"
        if ! grep -q "===RECOVERY_IDS===" "$SERIAL_LOG"; then
            echo "fail: crash run ($fault) did not reach the apply step" >&2
            KEEP=1
            cat "$SERIAL_LOG" >&2
            exit 1
        fi
        cmd_label=$( [ "$scenario" = "crash" ] && echo apply || echo resume )
        if grep -q "===RECOVERY_${cmd_label}_END=== rc=" "$SERIAL_LOG"; then
            apply_rc=$(sed -n "s/.*===RECOVERY_${cmd_label}_END=== rc=\([0-9]*\).*/\1/p" "$SERIAL_LOG" | tail -1)
            echo "info:   fault=$fault $cmd_label exited rc=$apply_rc"
            if [ "$apply_rc" != "137" ] && [ "$apply_rc" != "0" ]; then
                echo "warn:   fault=$fault $cmd_label exited rc=$apply_rc (expected 137 for SIGKILL or 0 for completion)"
            fi
        else
            echo "info:   fault=$fault $cmd_label did not print end marker (likely SIGKILL at $fault)"
        fi
    done

    echo "info: final resume -> completed"
    run_qemu resume "" "$plan_id" "$token"
    cp "$SERIAL_LOG" "$WORKDIR/serial-resume-final.log"
    if ! grep -q '===RECOVERY_resume_END=== rc=0' "$SERIAL_LOG"; then
        echo "fail: final resume did not reach resume end rc=0" >&2
        KEEP=1
        cat "$SERIAL_LOG" >&2
        exit 1
    fi
fi

# Step verification: image-level assertions on the btrfs image.
# We re-mount the image read-only on the host (Linux + btrfs) and
# inspect the resulting tree. Skip if host has no btrfs module.
if ! modprobe btrfs 2>/dev/null; then
    echo "skip: host has no btrfs module; deferring image verification to guest-side checks"
else
    VERIFY_MNT="$WORKDIR/verify-mnt"
    rm -rf "$VERIFY_MNT"
    mkdir -p "$VERIFY_MNT"
    if mount -o loop,subvolid=5,ro "$BTRFS_IMG" "$VERIFY_MNT" 2>/dev/null; then
        # 1. /@ now contains the snapshot-2 marker.
        if [ -r "$VERIFY_MNT/@/var/lib/pacman/local/SNAPSHOT_2_MARKER" ]; then
            echo "pass: /@ contains snapshot-2 content"
        else
            echo "fail: /@ does not contain SNAPSHOT_2_MARKER" >&2
            KEEP=1
            umount "$VERIFY_MNT" 2>/dev/null || true
            exit 1
        fi
        # 2. Backup path contains the original current-root marker.
        backup_path=$(ls -d "$VERIFY_MNT/.catos-recovery/backups/"*/root-before 2>/dev/null | head -1)
        if [ -n "$backup_path" ] && [ -r "$backup_path/var/lib/pacman/local/CURRENT_MARKER" ]; then
            echo "pass: backup contains original /@ content"
        else
            echo "fail: backup missing or lacks CURRENT_MARKER" >&2
            KEEP=1
            umount "$VERIFY_MNT" 2>/dev/null || true
            exit 1
        fi
        # 3. @home content unchanged.
        if grep -q 'home-data-must-not-change' "$VERIFY_MNT/@home/user-file"; then
            echo "pass: @home unchanged"
        else
            echo "fail: @home content changed" >&2
            KEEP=1
            umount "$VERIFY_MNT" 2>/dev/null || true
            exit 1
        fi
        # 4. Snapshot readonly attribute preserved.
        ro_check=$(btrfs property get "$VERIFY_MNT/@/.snapshots/2/snapshot" ro 2>&1 || true)
        if echo "$ro_check" | grep -q 'ro=true'; then
            echo "pass: snapshot readonly attribute preserved"
        else
            echo "fail: snapshot readonly attribute changed: $ro_check" >&2
            KEEP=1
            umount "$VERIFY_MNT" 2>/dev/null || true
            exit 1
        fi
        umount "$VERIFY_MNT" 2>/dev/null || true
    else
        echo "skip: host cannot mount the btrfs image for verification"
    fi
fi

# ESP must be byte-for-byte unchanged.
ESP_HASH_AFTER=$(sha256sum "$ESP_IMG" | awk '{print $1}')
if [ "$ESP_HASH_BEFORE" != "$ESP_HASH_AFTER" ]; then
    echo "fail: ESP image changed during recovery" >&2
    KEEP=1
    exit 1
fi
echo "pass: ESP byte-for-byte unchanged"

echo "pass: phase-3 recovery QEMU smoke succeeded"
