#!/usr/bin/env bash
# Real stage-3 mount-repair acceptance in a disposable QEMU guest.
# Exit 77 means a host prerequisite is unavailable. Once QEMU starts every
# missing assertion is a failure: the repair must modify the guest disk, not
# merely produce a plan.

set -u

usage() {
    cat >&2 <<'EOF'
usage: mount-repair-qemu-smoke.sh --bin PATH [--kernel PATH] [--busybox PATH] [--qemu PATH]
EOF
}

BIN=""
KERNEL=""
BUSYBOX=""
QEMU_BIN=""
WORKDIR=""
KEEP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        --kernel) KERNEL="$2"; shift 2 ;;
        --busybox) BUSYBOX="$2"; shift 2 ;;
        --qemu) QEMU_BIN="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[ -n "$QEMU_BIN" ] || QEMU_BIN=$(command -v qemu-system-x86_64 2>/dev/null || true)
[ -n "$BUSYBOX" ] || BUSYBOX=$(command -v busybox 2>/dev/null || true)
if [ -z "$KERNEL" ]; then
    for candidate in "/usr/lib/modules/$(uname -r)/vmlinuz" /usr/lib/modules/*/vmlinuz /boot/vmlinuz-*; do
        if [ -f "$candidate" ]; then KERNEL="$candidate"; break; fi
    done
fi

missing=()
[ -x "$BIN" ] || missing+=("static catos-system binary")
[ -x "$QEMU_BIN" ] || missing+=("qemu-system-x86_64")
[ -x "$BUSYBOX" ] || missing+=("static busybox")
[ -f "$KERNEL" ] || missing+=("kernel image")
for tool in cpio gzip timeout truncate mkfs.btrfs sha256sum grep find ldd awk; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -ne 0 ]; then
    echo "skip: missing mount-repair QEMU prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if ! "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || ! "$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null; then
    echo "skip: mount-repair QEMU requires static binary and busybox" >&2
    exit 77
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-mount-repair-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
IMAGE="$WORKDIR/target.img"
SERIAL_LOG="$WORKDIR/serial.log"
KVER=$(basename "$(dirname "$KERNEL")")
if [ "$KVER" = modules ] || [ ! -d "/usr/lib/modules/$KVER" ]; then KVER=$(uname -r); fi

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "info: keeping workdir $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

fail() {
    echo "fail: $*" >&2
    KEEP=1
    [ ! -f "$SERIAL_LOG" ] || cat "$SERIAL_LOG" >&2
    exit 1
}

truncate -s 256M "$IMAGE"
mkfs.btrfs -q -f -U 11111111-2222-3333-4444-555555555555 -m single -d single "$IMAGE"

rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,run,mnt,target,verify,usr/bin,usr/sbin}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/"*
for applet in sh mount umount cat echo sleep poweroff mkdir grep find sync ln; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

cp /usr/bin/btrfs "$INITRAMFS/usr/bin/btrfs"
ldd /usr/bin/btrfs | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}' | while read -r library; do
    [ -f "$library" ] || continue
    mkdir -p "$INITRAMFS$(dirname "$library")"
    cp -L "$library" "$INITRAMFS$library"
done

cat > "$INITRAMFS/init" <<'GUEST'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
for _ in 1 2 3 4 5; do [ -b /dev/vda ] && break; sleep 1; done
[ -b /dev/vda ] || { echo '===MOUNT_REPAIR_FATAL=== missing vda'; poweroff -f; }

mount /dev/vda /mnt || { echo '===MOUNT_REPAIR_FATAL=== mount top-level'; poweroff -f; }
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@snapshots
mount -o subvol=/@ /dev/vda /target || { echo '===MOUNT_REPAIR_FATAL=== mount root'; poweroff -f; }
mkdir -p /target/etc
cat > /target/etc/os-release <<'EOF'
ID=catos
EOF
cat > /target/etc/fstab <<'EOF'
UUID=old  /  btrfs  defaults,compress=zstd:3,subvol=/wrong  0 1
UUID=target  /.snapshots  btrfs  defaults,subvol=/bad  0 0
EOF
umount /target
umount /mnt

mkdir -p /run/udev/data
major_minor=$(cat /sys/class/block/vda/dev)
cat > "/run/udev/data/b${major_minor}" <<'EOF'
E:ID_FS_TYPE=btrfs
E:ID_FS_UUID=target
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=catos-target
EOF
ln -sf /bin/catos-system /bin/catos-repair
echo '===MOUNT_REPAIR_BEGIN==='
/bin/catos-repair mount --root-device /dev/vda --json
rc=$?
echo "===MOUNT_REPAIR_END=== rc=$rc"

mount /dev/vda /mnt || { echo '===MOUNT_REPAIR_FATAL=== remount top-level'; poweroff -f; }
btrfs subvolume list /mnt | grep -q ' path @home$' || echo '===MOUNT_REPAIR_ASSERT=== missing @home'
btrfs subvolume list /mnt | grep -q ' path @snapshots$' || echo '===MOUNT_REPAIR_ASSERT=== missing @snapshots'
mount -o subvol=/@ /dev/vda /verify || { echo '===MOUNT_REPAIR_FATAL=== verify root'; poweroff -f; }
grep -q 'UUID=target  /  btrfs  defaults,compress=zstd:3,subvol=/@  0 1' /verify/etc/fstab || echo '===MOUNT_REPAIR_ASSERT=== root fstab not repaired'
grep -q 'UUID=target  /.snapshots  btrfs  defaults,subvol=/@snapshots  0 0' /verify/etc/fstab || echo '===MOUNT_REPAIR_ASSERT=== snapshots fstab not repaired'
[ -d /verify/home ] || echo '===MOUNT_REPAIR_ASSERT=== home directory missing'
[ -d /verify/.snapshots ] || echo '===MOUNT_REPAIR_ASSERT=== snapshots directory missing'
umount /verify
umount /mnt
if find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo '===MOUNT_REPAIR_ASSERT=== residual sessions'
fi
echo '===MOUNT_REPAIR_OK==='
sync
poweroff -f
GUEST
chmod +x "$INITRAMFS/init"
(
    cd "$INITRAMFS" || exit 1
    find . -print0 | cpio --null --create --format=newc 2>/dev/null
) | gzip -9 > "$INITRAMFS_IMG"

accel=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then accel=(-enable-kvm -cpu host); fi
timeout 240 "$QEMU_BIN" -M pc -m 1024M -no-reboot -nographic "${accel[@]}" \
    -kernel "$KERNEL" -initrd "$INITRAMFS_IMG" -append 'console=ttyS0 panic=1 rdinit=/init' \
    -drive "if=virtio,file=$IMAGE,format=raw,cache=none" < /dev/null > "$SERIAL_LOG" 2>&1 || fail 'QEMU failed or timed out'

grep -q '===MOUNT_REPAIR_END=== rc=0' "$SERIAL_LOG" || fail 'mount repair did not return success'
grep -q '===MOUNT_REPAIR_OK===' "$SERIAL_LOG" || fail 'guest did not reach success marker'
if grep -q '===MOUNT_REPAIR_ASSERT===' "$SERIAL_LOG" || grep -q '===MOUNT_REPAIR_FATAL===' "$SERIAL_LOG"; then
    fail 'guest assertions failed'
fi
echo 'pass: mount-repair QEMU smoke test succeeded'
