#!/usr/bin/env bash
# Real stage-3 mount-repair acceptance in a disposable QEMU guest.
#
# The guest runs all six supported /boot + ESP layouts against real Btrfs,
# ext4 and FAT filesystems. Each case forces an fstab repair, then verifies
# through the JSON report that the complete repaired fstab was mounted in a
# private namespace (standard subvolumes plus external boot/ESP resources).
# Exit 77 means a host prerequisite is unavailable.

set -eu

usage() {
    cat >&2 <<'USAGE'
usage: mount-repair-qemu-smoke.sh --bin PATH [--kernel PATH] [--busybox PATH] [--qemu PATH] [--workdir DIR] [--keep]
USAGE
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
        *) usage; exit 2 ;;
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
for tool in cpio gzip timeout truncate mkfs.btrfs mkfs.ext4 mkfs.vfat mmd mcopy sfdisk sha256sum grep find ldd awk python3 modinfo zstd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -ne 0 ]; then
    echo "skip: missing mount-repair QEMU prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if ! "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || ! "$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null; then
    echo "skip: mount-repair QEMU requires a static backend and busybox" >&2
    exit 77
fi

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-mount-repair-qemu-XXXXXX)}"
mkdir -p "$WORKDIR"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_IMG="$WORKDIR/initramfs.cpio.gz"
ROOT_IMAGE="$WORKDIR/root.img"
ESP_IMAGE="$WORKDIR/esp.img"
BOOT_IMAGE="$WORKDIR/boot.img"
PLAIN_ROOT_IMAGE="$WORKDIR/plain-root.img"
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

truncate -s 512M "$ROOT_IMAGE"
truncate -s 64M "$ESP_IMAGE"
truncate -s 128M "$BOOT_IMAGE"
truncate -s 256M "$PLAIN_ROOT_IMAGE"
mkfs.vfat -i E5F1A001 -n CATOS_ESP "$ESP_IMAGE" >/dev/null
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/CatOS
printf 'CatOS ESP acceptance marker\n' | mcopy -i "$ESP_IMAGE" - ::/EFI/CatOS/acceptance.txt
mkfs.ext4 -q -F -U 66666666-7777-8888-9999-aaaaaaaaaaaa -L CATOS_BOOT "$BOOT_IMAGE"
mkfs.ext4 -q -F -U 77777777-8888-9999-aaaa-bbbbbbbbbbbb -L CATOS_PLAIN "$PLAIN_ROOT_IMAGE"

rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,mnt,target,verify,bootfs,espfs,usr/bin,usr/sbin,"lib/modules/$KVER"}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/"*
for applet in sh mount umount cat echo sleep poweroff mkdir grep find sync ln modprobe awk sed cut switch_root cp; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

copy_tool() {
    local source
    source=$(command -v "$1")
    mkdir -p "$INITRAMFS$(dirname "$source")"
    cp -L "$source" "$INITRAMFS$source"
    ldd "$source" 2>/dev/null | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}' | while read -r library; do
        [ -f "$library" ] || continue
        mkdir -p "$INITRAMFS$(dirname "$library")"
        cp -L "$library" "$INITRAMFS$library"
    done
}
for tool in btrfs mkfs.btrfs sfdisk; do copy_tool "$tool"; done

copy_module() {
    local name="$1" source destination
    source=$(modinfo -k "$KVER" -n "$name" 2>/dev/null || true)
    [ -n "$source" ] && [ -f "$source" ] || return 0
    destination="$INITRAMFS/lib/modules/$KVER/kernel/fs/$name.ko"
    mkdir -p "$(dirname "$destination")"
    case "$source" in
        *.zst) zstd -q -d -c "$source" > "$destination" ;;
        *.xz) xz -d -c "$source" > "$destination" ;;
        *) cp "$source" "$destination" ;;
    esac
}
for module in fat vfat jbd2 mbcache ext4 btrfs; do copy_module "$module"; done
cat > "$INITRAMFS/lib/modules/$KVER/modules.dep" <<'EOF_MODULES'
kernel/fs/fat.ko:
kernel/fs/vfat.ko: kernel/fs/fat.ko
kernel/fs/jbd2.ko:
kernel/fs/mbcache.ko:
kernel/fs/ext4.ko: kernel/fs/jbd2.ko kernel/fs/mbcache.ko
kernel/fs/btrfs.ko:
EOF_MODULES
: > "$INITRAMFS/lib/modules/$KVER/modules.alias"
: > "$INITRAMFS/lib/modules/$KVER/modules.symbols"

cat > "$INITRAMFS/etc/initrd-release" <<'EOF_RELEASE'
NAME=CatOS
VERSION_ID=mount-repair-six-layouts
EOF_RELEASE

cat > "$INITRAMFS/init" <<'GUEST'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
modprobe btrfs 2>/dev/null || true
modprobe ext4 2>/dev/null || true
modprobe vfat 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && [ -b /dev/vdb ] && [ -b /dev/vdc ] && [ -b /dev/vdd ] && break
    sleep 1
done
[ -b /dev/vda ] && [ -b /dev/vdb ] && [ -b /dev/vdc ] && [ -b /dev/vdd ] || {
    echo '===MOUNT_REPAIR_FATAL=== missing virtio disks'; poweroff -f;
}

printf 'label: dos\n, , L\n' | sfdisk /dev/vda >/dev/null || {
    echo '===MOUNT_REPAIR_FATAL=== partition root'; poweroff -f;
}
for _ in 1 2 3 4 5; do [ -b /dev/vda1 ] && break; sleep 1; done
[ -b /dev/vda1 ] || { echo '===MOUNT_REPAIR_FATAL=== missing vda1'; poweroff -f; }
mkfs.btrfs -q -f -U 11111111-2222-3333-4444-555555555555 -m single -d single /dev/vda1 || {
    echo '===MOUNT_REPAIR_FATAL=== format root'; poweroff -f;
}
mount /dev/vda1 /mnt || { echo '===MOUNT_REPAIR_FATAL=== mount top'; poweroff -f; }
for subvol in @ @home @root @srv @cache @tmp @log @snapshots @boot; do
    btrfs subvolume create "/mnt/$subvol" >/dev/null || {
        echo "===MOUNT_REPAIR_FATAL=== create $subvol"; poweroff -f;
    }
done
echo 'Btrfs boot-subvolume acceptance marker' > /mnt/@boot/acceptance.txt
mount -o subvol=/@ /dev/vda1 /target || { echo '===MOUNT_REPAIR_FATAL=== mount root'; poweroff -f; }
mkdir -p /target/etc /target/usr /target/home /target/root /target/srv /target/var/cache /target/var/tmp /target/var/log /target/.snapshots /target/boot/efi /target/efi
cat > /target/etc/os-release <<'EOF_OS'
ID=catos
EOF_OS
umount /target
umount /mnt

mount /dev/vdc /bootfs || { echo '===MOUNT_REPAIR_FATAL=== mount separate boot'; poweroff -f; }
echo 'Separate boot acceptance marker' > /bootfs/acceptance.txt
umount /bootfs

mount /dev/vdd /verify || { echo '===MOUNT_REPAIR_FATAL=== mount plain root'; poweroff -f; }
mkdir -p /verify/etc /verify/usr /verify/boot
cat > /verify/etc/os-release <<'EOF_PLAIN_OS'
ID=catos
EOF_PLAIN_OS
cat > /verify/etc/fstab <<'EOF_PLAIN_FSTAB'
UUID=old-plain-root / ext4 defaults,noatime,commit=60 0 1
EOF_PLAIN_FSTAB
umount /verify

mkdir -p /run/udev/data
root_mm=$(cat /sys/class/block/vda/vda1/dev)
esp_mm=$(cat /sys/class/block/vdb/dev)
boot_mm=$(cat /sys/class/block/vdc/dev)
plain_mm=$(cat /sys/class/block/vdd/dev)
cat > "/run/udev/data/b${root_mm}" <<'EOF_UDEV_ROOT'
E:ID_FS_TYPE=btrfs
E:ID_FS_UUID=target
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=catos-target
EOF_UDEV_ROOT
cat > "/run/udev/data/b${esp_mm}" <<'EOF_UDEV_ESP'
E:ID_FS_TYPE=vfat
E:ID_FS_UUID=E5F1-A001
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=CATOS_ESP
EOF_UDEV_ESP
cat > "/run/udev/data/b${boot_mm}" <<'EOF_UDEV_BOOT'
E:ID_FS_TYPE=ext4
E:ID_FS_UUID=66666666-7777-8888-9999-aaaaaaaaaaaa
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=CATOS_BOOT
EOF_UDEV_BOOT
cat > "/run/udev/data/b${plain_mm}" <<'EOF_UDEV_PLAIN'
E:ID_FS_TYPE=ext4
E:ID_FS_UUID=77777777-8888-9999-aaaa-bbbbbbbbbbbb
E:ID_FS_USAGE=filesystem
E:ID_FS_LABEL=CATOS_PLAIN
EOF_UDEV_PLAIN
ln -sf /bin/catos-system /bin/catos-repair

write_case_fstab() {
    case_name="$1"
    mount -o subvol=/@ /dev/vda1 /target || return 1
    case "$case_name" in
        esp_at_boot_efi)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
UUID=old-esp /boot/efi vfat defaults,umask=0077 0 2
EOF_CASE
            ;;
        esp_at_efi)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
UUID=old-esp /efi vfat defaults,umask=0077 0 2
EOF_CASE
            ;;
        esp_at_boot)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
UUID=old-esp /boot vfat defaults,umask=0077 0 2
EOF_CASE
            ;;
        separate_boot_and_esp)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
UUID=66666666-7777-8888-9999-aaaaaaaaaaaa /boot ext4 defaults,noatime 0 2
UUID=old-esp /boot/efi vfat defaults,umask=0077 0 2
EOF_CASE
            ;;
        boot_btrfs_subvolume)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
UUID=target /boot btrfs defaults,noatime,subvol=/@boot 0 0
UUID=old-esp /efi vfat defaults,umask=0077 0 2
EOF_CASE
            ;;
        boot_inside_root)
            cat > /target/etc/fstab <<'EOF_CASE'
UUID=target / btrfs defaults,compress=zstd:3,subvol=/wrong 0 1
EOF_CASE
            ;;
        *) umount /target; return 1 ;;
    esac
    sync
    umount /target
}

run_case() {
    case_name="$1"
    write_case_fstab "$case_name" || {
        echo "===MOUNT_REPAIR_FATAL=== prepare $case_name"; poweroff -f;
    }
    echo "===LAYOUT_${case_name}_BEGIN==="
    /bin/catos-repair mount --json
    rc=$?
    echo "===LAYOUT_${case_name}_END=== rc=$rc"
    if find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
        echo "===MOUNT_REPAIR_ASSERT=== residual sessions after $case_name"
    fi
}

for case_name in esp_at_boot_efi esp_at_efi esp_at_boot separate_boot_and_esp boot_btrfs_subvolume boot_inside_root; do
    run_case "$case_name"
done

echo '===LAYOUT_plain_ext4_root_BEGIN==='
/bin/catos-repair mount --root-device /dev/vdd --json
plain_rc=$?
echo "===LAYOUT_plain_ext4_root_END=== rc=$plain_rc"

# Force a post-create verification failure. @home and @log must be created by
# repair and then removed again by the empty-subvolume rollback ioctl.
mount /dev/vda1 /mnt || { echo '===MOUNT_REPAIR_FATAL=== rollback mount top'; poweroff -f; }
btrfs subvolume delete /mnt/@home /mnt/@log >/dev/null || {
    echo '===MOUNT_REPAIR_FATAL=== rollback delete fixtures'; poweroff -f;
}
umount /mnt
mount -o subvol=/@ /dev/vda1 /target || { echo '===MOUNT_REPAIR_FATAL=== rollback mount root'; poweroff -f; }
cat > /target/etc/fstab <<'EOF_ROLLBACK_FSTAB'
UUID=target / btrfs defaults,subvol=/@ 0 0
UUID=target /home btrfs defaults,subvol=/@home 0 0
UUID=target /var/log btrfs defaults,subvol=/@log 0 0
UUID=does-not-exist /mnt/broken ext4 defaults 0 2
EOF_ROLLBACK_FSTAB
mkdir -p /target/mnt/broken
umount /target
echo '===ROLLBACK_EMPTY_SUBVOLS_BEGIN==='
/bin/catos-repair mount --root-device /dev/vda1 --json
rollback_rc=$?
echo "===ROLLBACK_EMPTY_SUBVOLS_END=== rc=$rollback_rc"
mount /dev/vda1 /mnt || { echo '===MOUNT_REPAIR_FATAL=== rollback inspect top'; poweroff -f; }
if [ -e /mnt/@home ] || [ -e /mnt/@log ]; then
    echo '===MOUNT_REPAIR_ASSERT=== empty subvolume rollback left a residual'
fi
umount /mnt

# Last case: make the ext4 filesystem the actual running root and repair its
# own fstab. switch_root cannot return, so this scenario powers off itself.
mount /dev/vdd /verify || { echo '===MOUNT_REPAIR_FATAL=== current-root mount'; poweroff -f; }
mkdir -p /verify/bin /verify/dev /verify/proc /verify/sys /verify/run/udev/data /verify/etc /verify/usr
cp /bin/busybox /verify/bin/busybox
cp /bin/catos-system /verify/bin/catos-system
ln -sf /bin/busybox /verify/bin/sh
ln -sf /bin/busybox /verify/bin/poweroff
ln -sf /bin/catos-system /verify/bin/catos-repair
cp /run/udev/data/* /verify/run/udev/data/
cat > /verify/etc/os-release <<'EOF_CURRENT_OS'
ID=catos
EOF_CURRENT_OS
cat > /verify/etc/fstab <<'EOF_CURRENT_FSTAB'
UUID=stale-current-root / ext4 defaults,noatime,commit=60 0 1
EOF_CURRENT_FSTAB
cat > /verify/init-current <<'EOF_CURRENT_INIT'
#!/bin/sh
PATH=/bin
export PATH
echo '===CURRENT_ROOT_REPAIR_BEGIN==='
/bin/catos-repair mount --root-device /dev/vdd --json
rc=$?
echo "===CURRENT_ROOT_REPAIR_END=== rc=$rc"
echo '===MOUNT_REPAIR_OK==='
poweroff -f
EOF_CURRENT_INIT
chmod +x /verify/init-current
mount --move /dev /verify/dev
mount --move /proc /verify/proc
mount --move /sys /verify/sys
exec /bin/switch_root /verify /init-current
GUEST
chmod +x "$INITRAMFS/init"
(
    cd "$INITRAMFS" || exit 1
    find . -print0 | cpio --null --create --format=newc 2>/dev/null
) | gzip -9 > "$INITRAMFS_IMG"

accel=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then accel=(-enable-kvm -cpu host); fi
timeout 360 "$QEMU_BIN" -M pc -m 1024M -no-reboot -nographic "${accel[@]}" \
    -kernel "$KERNEL" -initrd "$INITRAMFS_IMG" -append 'console=ttyS0 panic=1 rdinit=/init' \
    -drive "if=none,id=root,file=$ROOT_IMAGE,format=raw,cache=none" -device virtio-blk-pci,drive=root \
    -drive "if=none,id=esp,file=$ESP_IMAGE,format=raw,cache=none" -device virtio-blk-pci,drive=esp \
    -drive "if=none,id=boot,file=$BOOT_IMAGE,format=raw,cache=none" -device virtio-blk-pci,drive=boot \
    -drive "if=none,id=plain,file=$PLAIN_ROOT_IMAGE,format=raw,cache=none" -device virtio-blk-pci,drive=plain \
    < /dev/null > "$SERIAL_LOG" 2>&1 || fail 'QEMU failed or timed out'

python3 - "$SERIAL_LOG" <<'PY'
import json
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
expectations = {
    "esp_at_boot_efi": ("esp_at_boot_efi", {"/", "/boot/efi"}),
    "esp_at_efi": ("esp_at_efi", {"/", "/efi"}),
    "esp_at_boot": ("esp_at_boot", {"/", "/boot"}),
    "separate_boot_and_esp": ("separate_boot_and_esp", {"/", "/boot", "/boot/efi"}),
    "boot_btrfs_subvolume": ("boot_btrfs_subvolume", {"/", "/boot", "/efi"}),
    "boot_inside_root": ("boot_inside_root", {"/"}),
}
for name, (kind, required_targets) in expectations.items():
    match = re.search(
        rf"===LAYOUT_{name}_BEGIN===\s*(\{{.*?\}})\s*===LAYOUT_{name}_END=== rc=(-?\d+)",
        text,
        re.S,
    )
    if not match:
        raise SystemExit(f"missing JSON report for {name}")
    report = json.loads(match.group(1))
    rc = int(match.group(2))
    payload = report["payload"]
    if rc != 0:
        raise SystemExit(f"{name} returned {rc}: {payload}")
    observed = payload["target"]["boot_layout"]["kind"]
    if observed != kind:
        raise SystemExit(f"{name}: expected layout {kind}, got {observed}")
    verification = payload.get("verification") or {}
    if verification.get("mounted") is not True:
        raise SystemExit(f"{name}: complete verification did not succeed: {verification}")
    mounted = set(verification.get("mounted_targets", []))
    missing = required_targets - mounted
    if missing:
        raise SystemExit(f"{name}: verification did not mount {sorted(missing)}; mounted={sorted(mounted)}")
    if payload.get("cleanup", {}).get("all_clean") is not True:
        raise SystemExit(f"{name}: cleanup incomplete")
plain_match = re.search(
    r"===LAYOUT_plain_ext4_root_BEGIN===\s*(\{.*?\})\s*===LAYOUT_plain_ext4_root_END=== rc=(-?\d+)",
    text,
    re.S,
)
if not plain_match:
    raise SystemExit("missing plain ext4 root report")
plain = json.loads(plain_match.group(1))["payload"]
if int(plain_match.group(2)) != 0:
    raise SystemExit(f"plain ext4 root failed: {plain}")
if plain["target"]["root_fstype"] != "ext4":
    raise SystemExit(f"plain root fstype mismatch: {plain['target']}")
if plain["target"]["boot_layout"]["kind"] != "boot_inside_root":
    raise SystemExit(f"plain root layout mismatch: {plain['target']}")
if plain.get("verification", {}).get("mounted") is not True:
    raise SystemExit(f"plain ext4 verification failed: {plain.get('verification')}")
rollback_match = re.search(
    r"===ROLLBACK_EMPTY_SUBVOLS_BEGIN===\s*(\{.*?\})\s*===ROLLBACK_EMPTY_SUBVOLS_END=== rc=(-?\d+)",
    text,
    re.S,
)
if not rollback_match:
    raise SystemExit("missing empty-subvolume rollback report")
rollback = json.loads(rollback_match.group(1))["payload"]
if int(rollback_match.group(2)) == 0:
    raise SystemExit("rollback scenario unexpectedly returned success")
if rollback["final_outcome"] != "verification_failed":
    raise SystemExit(f"rollback scenario outcome mismatch: {rollback}")
action_kinds = [action["kind"] for action in rollback.get("actions", [])]
if action_kinds.count("subvolume_rolled_back") < 2:
    raise SystemExit(f"missing successful subvolume rollback actions: {action_kinds}")
current_match = re.search(
    r"===CURRENT_ROOT_REPAIR_BEGIN===\s*(\{.*?\})\s*===CURRENT_ROOT_REPAIR_END=== rc=(-?\d+)",
    text,
    re.S,
)
if not current_match:
    raise SystemExit("missing current-root repair report")
current = json.loads(current_match.group(1))["payload"]
if int(current_match.group(2)) != 0:
    raise SystemExit(f"current-root repair failed: {current}")
if current["target"]["root_fstype"] != "ext4":
    raise SystemExit(f"current-root target mismatch: {current['target']}")
if current.get("verification", {}).get("mounted") is not True:
    raise SystemExit(f"current-root verification failed: {current.get('verification')}")
if "===MOUNT_REPAIR_ASSERT===" in text or "===MOUNT_REPAIR_FATAL===" in text:
    raise SystemExit("guest emitted an assertion/fatal marker")
if "===MOUNT_REPAIR_OK===" not in text:
    raise SystemExit("guest did not reach success marker")
print("pass: six layouts, offline/current ext4 roots, and empty-subvolume rollback passed")
PY

echo 'pass: mount-repair QEMU six-layout acceptance succeeded'
