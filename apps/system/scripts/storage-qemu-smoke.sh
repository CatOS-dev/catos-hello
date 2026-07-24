#!/usr/bin/env bash
# storage-qemu-smoke.sh - real ext4 root + FAT ESP recovery flow in QEMU.
#
# This test creates two writable raw block images without loop devices or
# host mounts, boots the static catos-system binary in a minimal initramfs,
# and verifies:
#   * storage scan finds a CatOS root and an ESP by inspecting their content;
#   * explicit root/ESP selection builds the expected read-only plan;
#   * target mount performs mount -> inspect -> reverse cleanup;
#   * the final session is finished with no active/residual mounts;
#   * both writable disk images are byte-for-byte unchanged after the guest.
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
for tool in cpio gzip timeout mkfs.ext4 mkfs.vfat mkfs.btrfs mcopy mmd sha256sum zstd python3 modinfo ldd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: storage QEMU smoke test missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

if [ -x "$SCRIPT_DIR/verify-static.sh" ]; then
    "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || {
        echo "fail: catos-system is not fully static" >&2
        exit 1
    }
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-storage-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
SERIAL_LOG="$WORKDIR/serial.log"
ROOT_TREE="$WORKDIR/root-tree"
BTREE_TREE="$WORKDIR/btrfs-tree"
ROOT_IMG="$WORKDIR/root.img"
ESP_IMG="$WORKDIR/esp.img"
BTRFS_IMG="$WORKDIR/btrfs.img"
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

rm -rf "$INITRAMFS" "$ROOT_TREE" "$BTREE_TREE"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,usr/bin,usr/sbin,"lib/modules/$KVER/kernel/fs/fat"}
mkdir -p "$ROOT_TREE"/{etc,usr,var/lib/pacman/local,boot/efi}
mkdir -p "$BTREE_TREE/@"/{etc,usr,var/lib/pacman/local,boot,.snapshots/1/snapshot/etc}
cat > "$ROOT_TREE/etc/os-release" <<'EOF'
NAME=CatOS
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS QEMU Fixture"
EOF
cat > "$ROOT_TREE/etc/fstab" <<'EOF'
/dev/vda  /          ext4  defaults  0 1
/dev/vdb  /boot/efi  vfat  defaults  0 2
EOF

truncate -s 128M "$ROOT_IMG"
mkfs.ext4 -q -F -U 11111111-2222-3333-4444-555555555555 -d "$ROOT_TREE" "$ROOT_IMG"
truncate -s 32M "$ESP_IMG"
mkfs.vfat -i C4705E12 "$ESP_IMG" >/dev/null
mmd -i "$ESP_IMG" ::/EFI ::/EFI/CatOS
printf 'CatOS EFI fixture\n' > "$WORKDIR/test.efi"
mcopy -i "$ESP_IMG" "$WORKDIR/test.efi" ::/EFI/CatOS/test.efi

cat > "$BTREE_TREE/@/etc/os-release" <<'EOF'
NAME=CatOS
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS Btrfs QEMU Fixture"
EOF
cat > "$BTREE_TREE/@/etc/fstab" <<'EOF'
/dev/vdc  /  btrfs  subvol=/@  0 0
EOF
cat > "$BTREE_TREE/@/.snapshots/1/snapshot/etc/os-release" <<'EOF'
NAME=CatOS Snapshot
ID=catos
EOF
truncate -s 256M "$BTRFS_IMG"
mkfs.btrfs -q -f -U 22222222-3333-4444-5555-666666666666 \
    -r "$BTREE_TREE" \
    --subvol default:@ \
    --subvol rw:@/.snapshots \
    --subvol ro:@/.snapshots/1/snapshot \
    "$BTRFS_IMG"

ROOT_HASH_BEFORE=$(sha256sum "$ROOT_IMG" | awk '{print $1}')
ESP_HASH_BEFORE=$(sha256sum "$ESP_IMG" | awk '{print $1}')
BTRFS_HASH_BEFORE=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')

cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system"
for applet in sh mount cat echo sleep modprobe poweroff mkdir grep awk find; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

# Include btrfs-progs and its runtime libraries so the guest exercises real
# subvolume enumeration rather than the common-name fallback.
cp /usr/bin/btrfs "$INITRAMFS/usr/bin/btrfs"
ldd /usr/bin/btrfs | awk '
    /=> \/[^ ]+/ { print $3 }
    $1 ~ /^\// { print $1 }
' | while read -r library; do
    [ -f "$library" ] || continue
    mkdir -p "$INITRAMFS$(dirname "$library")"
    cp -L "$library" "$INITRAMFS$library"
done

# The current CatOS kernel builds virtio-blk and ext4 in; FAT may be modular.
# Decompress the exact matching modules so busybox modprobe needs no zstd applet.
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
VERSION_ID=storage-smoke
EOF

cat > "$INITRAMFS/init" <<'INIT_EOF'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t devtmpfs none /dev 2>/dev/null
modprobe vfat 2>/dev/null || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && [ -b /dev/vdb ] && [ -b /dev/vdc ] && break
    sleep 1
done
if [ ! -b /dev/vda ] || [ ! -b /dev/vdb ] || [ ! -b /dev/vdc ]; then
    echo "===STORAGE_SMOKE_FATAL=== missing virtio block devices"
    poweroff -f
fi

mkdir -p /run/udev/data
root_mm=$(cat /sys/class/block/vda/dev)
esp_mm=$(cat /sys/class/block/vdb/dev)
btrfs_mm=$(cat /sys/class/block/vdc/dev)
cat > "/run/udev/data/b${root_mm}" <<'EOF'
E:ID_FS_TYPE=ext4
E:ID_FS_UUID=11111111-2222-3333-4444-555555555555
E:ID_FS_USAGE=filesystem
EOF
cat > "/run/udev/data/b${esp_mm}" <<'EOF'
E:ID_FS_TYPE=vfat
E:ID_FS_UUID=C470-5E12
E:ID_FS_USAGE=filesystem
EOF
cat > "/run/udev/data/b${btrfs_mm}" <<'EOF'
E:ID_FS_TYPE=btrfs
E:ID_FS_UUID=22222222-3333-4444-5555-666666666666
E:ID_FS_USAGE=filesystem
EOF

echo "===STORAGE_SCAN_BEGIN==="
/bin/catos-system storage scan --json
scan_rc=$?
echo "===STORAGE_SCAN_END=== rc=$scan_rc"

echo "===TARGET_PLAN_BEGIN==="
/bin/catos-system target plan --root-device /dev/vda --esp-device /dev/vdb --json
plan_rc=$?
echo "===TARGET_PLAN_END=== rc=$plan_rc"

echo "===TARGET_MOUNT_BEGIN==="
/bin/catos-system target mount --root-device /dev/vda --esp-device /dev/vdb --json
mount_rc=$?
echo "===TARGET_MOUNT_END=== rc=$mount_rc"

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

accel_args=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel_args=(-enable-kvm -cpu host)
fi

timeout 90 "$QEMU_BIN" \
    -M pc \
    -m 512M \
    -no-reboot \
    -nographic \
    "${accel_args[@]}" \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS_IMG" \
    -append "console=ttyS0 panic=1 rdinit=/init" \
    -drive if=none,id=root,file="$ROOT_IMG",format=raw,cache=none \
    -device virtio-blk-pci,drive=root \
    -drive if=none,id=esp,file="$ESP_IMG",format=raw,cache=none \
    -device virtio-blk-pci,drive=esp \
    -drive if=none,id=btrfs,file="$BTRFS_IMG",format=raw,cache=none \
    -device virtio-blk-pci,drive=btrfs \
    < /dev/null > "$SERIAL_LOG" 2>&1
qemu_rc=$?
if [ "$qemu_rc" -eq 124 ]; then
    echo "fail: QEMU storage test timed out" >&2
    KEEP=1
    exit 1
fi

ROOT_HASH_AFTER=$(sha256sum "$ROOT_IMG" | awk '{print $1}')
ESP_HASH_AFTER=$(sha256sum "$ESP_IMG" | awk '{print $1}')
BTRFS_HASH_AFTER=$(sha256sum "$BTRFS_IMG" | awk '{print $1}')
if [ "$ROOT_HASH_BEFORE" != "$ROOT_HASH_AFTER" ]; then
    echo "fail: ext4 root image changed during read-only recovery flow" >&2
    KEEP=1
    exit 1
fi
if [ "$ESP_HASH_BEFORE" != "$ESP_HASH_AFTER" ]; then
    echo "fail: FAT ESP image changed during read-only recovery flow" >&2
    KEEP=1
    exit 1
fi
if [ "$BTRFS_HASH_BEFORE" != "$BTRFS_HASH_AFTER" ]; then
    echo "fail: Btrfs image changed during no-log-replay discovery" >&2
    KEEP=1
    exit 1
fi

python3 - "$SERIAL_LOG" <<'PY'
import json
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()

def document(name):
    match = re.search(
        rf"==={name}_BEGIN===\s*(\{{.*?\}})\s*==={name}_END=== rc=(\d+)",
        text,
        re.S,
    )
    if not match:
        raise SystemExit(f"fail: missing or malformed {name} document")
    if int(match.group(2)) != 0:
        raise SystemExit(f"fail: {name} exited {match.group(2)}")
    return json.loads(match.group(1))

scan = document("STORAGE_SCAN")["payload"]
roots = scan.get("root_candidates", [])
esps = scan.get("esp_candidates", [])
if not any(r.get("source") == "/dev/vda" and r.get("confidence") == "high" and r.get("is_catos", {}).get("status") == "detected" for r in roots):
    raise SystemExit("fail: storage scan did not identify the CatOS root")
if not any(e.get("source") == "/dev/vdb" and e.get("signals", {}).get("has_efi_directory") for e in esps):
    raise SystemExit("fail: storage scan did not identify the ESP content")
btrfs_roots = [r for r in roots if r.get("source") == "/dev/vdc"]
if not any(r.get("subvolume") == "/@" and r.get("confidence") == "high" for r in btrfs_roots):
    raise SystemExit("fail: storage scan did not identify the Btrfs @ root")
if any(".snapshots" in (r.get("subvolume") or "") for r in btrfs_roots):
    raise SystemExit("fail: a Btrfs snapshot was exposed as a root candidate")
subvolumes = scan.get("btrfs_subvolumes", [])
if not any(s.get("path") == "/@" and s.get("kind") == "root_candidate" for s in subvolumes):
    raise SystemExit("fail: Btrfs @ subvolume classification missing")
if not any(s.get("path", "").endswith("/.snapshots/1/snapshot") and s.get("kind") == "read_only_snapshot" for s in subvolumes):
    raise SystemExit("fail: read-only Btrfs snapshot was not classified")

plan = document("TARGET_PLAN")["payload"]["plan"]
steps = plan.get("steps", [])
root_step = next((s for s in steps if s.get("target", "").endswith("/target")), None)
esp_step = next((s for s in steps if s.get("target", "").endswith("/target/boot/efi")), None)
if not root_step or root_step.get("source") != "/dev/vda" or "noload" not in root_step.get("options", []):
    raise SystemExit("fail: ext4 root plan is missing ro,noload")
if not esp_step or esp_step.get("source") != "/dev/vdb" or "ro" not in esp_step.get("options", []):
    raise SystemExit("fail: ESP plan is missing read-only mount")

mounted = document("TARGET_MOUNT")["payload"]
session = mounted["session"]
inspection = mounted["inspection"]
cleanup = mounted["cleanup"]
if session.get("state") != "finished" or session.get("mounts"):
    raise SystemExit("fail: target mount reported a stale active session")
if inspection.get("is_catos_target", {}).get("status") != "detected":
    raise SystemExit("fail: mounted target was not identified as CatOS")
for key in ("has_fstab", "has_usr", "has_pacman_db", "has_boot"):
    if inspection.get(key) != "present":
        raise SystemExit(f"fail: target inspection {key} is not present")
if not cleanup.get("all_clean") or cleanup.get("residual"):
    raise SystemExit("fail: target mount cleanup was incomplete")
if "===SESSION_RESIDUAL=== no" not in text:
    raise SystemExit("fail: runtime session directory remained after cleanup")

print("pass: QEMU storage discovery, mount, inspection, cleanup and no-write checks succeeded")
PY
