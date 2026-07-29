#!/usr/bin/env bash
# Real-QEMU acceptance for the catos-doctor multicall entry.
#
# Fixtures are built without host mounts. Root filesystems are generated with
# mkfs.btrfs --rootdir/--subvol and ESP filesystems with mtools. Every guest
# drive is attached read-only and is also hashed before and after the run.

set -euo pipefail

usage() {
    cat >&2 <<USAGE
usage: $0 [options]

options:
  --kernel PATH   Kernel image. Default: auto-detect.
  --busybox PATH  Static busybox. Default: search PATH.
  --bin PATH      Static catos-system multicall binary.
  --qemu PATH     qemu-system-x86_64. Default: search PATH.
  --workdir DIR   Work directory. Default: temporary directory.
  --keep          Keep workdir after completion.
USAGE
}

KERNEL=""
BUSYBOX=""
BIN=""
QEMU_BIN=""
WORKDIR=""
KEEP=0
while (($#)); do
    case "$1" in
        --kernel) KERNEL=$2; shift 2 ;;
        --busybox) BUSYBOX=$2; shift 2 ;;
        --bin) BIN=$2; shift 2 ;;
        --qemu) QEMU_BIN=$2; shift 2 ;;
        --workdir) WORKDIR=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SYSTEM_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
if [[ -z $BIN ]]; then
    for candidate in \
        "$SYSTEM_DIR/target/x86_64-unknown-linux-musl/release/catos-system" \
        "$SYSTEM_DIR/../../build/apps/system/cargo-target/x86_64-unknown-linux-musl/release/catos-system"; do
        if [[ -x $candidate ]]; then BIN=$candidate; break; fi
    done
fi
if [[ -z $QEMU_BIN ]] && command -v qemu-system-x86_64 >/dev/null 2>&1; then
    QEMU_BIN=$(command -v qemu-system-x86_64)
fi
if [[ -z $BUSYBOX ]] && command -v busybox >/dev/null 2>&1; then
    BUSYBOX=$(command -v busybox)
fi
if [[ -z $KERNEL ]]; then
    for candidate in \
        "/usr/lib/modules/$(uname -r)/vmlinuz" \
        /usr/lib/modules/*/vmlinuz \
        /boot/vmlinuz-linux \
        /boot/vmlinuz-linux-lts \
        /boot/vmlinuz-*; do
        if [[ -e $candidate ]]; then KERNEL=$candidate; break; fi
    done
fi

missing=()
[[ -x ${BIN:-} ]] || missing+=("static catos-system binary")
[[ -x ${QEMU_BIN:-} ]] || missing+=("qemu-system-x86_64")
[[ -x ${BUSYBOX:-} ]] || missing+=("static busybox")
[[ -f ${KERNEL:-} ]] || missing+=("kernel image")
for tool in cpio gzip timeout mkfs.btrfs btrfs btrfs-map-logical \
            mkfs.fat mcopy mmd mke2fs sha256sum python3 cargo ldd modprobe zstd xz; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
    echo "skip: doctor QEMU acceptance missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi
if [[ -x $SCRIPT_DIR/verify-static.sh ]]; then
    "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || {
        echo "fail: catos-system is not fully static" >&2
        exit 1
    }
fi

WORKDIR=${WORKDIR:-$(mktemp -d -t catos-doctor-qemu-XXXXXX)}
INITRAMFS=$WORKDIR/initramfs
INITRAMFS_IMG=$WORKDIR/initramfs.cpio.gz
KEEP_ON_FAILURE=0
cleanup() {
    if ((KEEP || KEEP_ON_FAILURE)); then
        echo "info: keeping workdir $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

ESP_UUID=C0DE-0001
ESP_VOLUME_ID=C0DE0001
UUID_GRUB=11111111-1111-4111-8111-111111111111
UUID_LIMINE=22222222-2222-4222-8222-222222222222
UUID_SYSTEMD=33333333-3333-4333-8333-333333333333
UUID_UKI=44444444-4444-4444-8444-444444444444
UUID_BROKEN=55555555-5555-4555-8555-555555555555
UUID_NO_FSTAB=5f5f5f5f-5f5f-4f5f-8f5f-5f5f5f5f5f5f
UUID_CORRUPT=66666666-6666-4666-8666-666666666666
UUID_INTERRUPTED=77777777-7777-4777-8777-777777777777
UUID_AMBIG_A=88888888-8888-4888-8888-888888888888
UUID_AMBIG_B=99999999-9999-4999-8999-999999999999
UUID_RUNNING=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa

ROOT_GRUB=$WORKDIR/root-grub.img
ROOT_LIMINE=$WORKDIR/root-limine.img
ROOT_SYSTEMD=$WORKDIR/root-systemd.img
ROOT_UKI=$WORKDIR/root-uki.img
ROOT_BROKEN=$WORKDIR/root-broken.img
ROOT_NO_FSTAB=$WORKDIR/root-no-fstab.img
ROOT_CORRUPT=$WORKDIR/root-corrupt.img
ROOT_INTERRUPTED=$WORKDIR/root-interrupted.img
ROOT_AMBIG_A=$WORKDIR/root-ambiguous-a.img
ROOT_AMBIG_B=$WORKDIR/root-ambiguous-b.img
ROOT_RUNNING=$WORKDIR/root-running.img
ESP_GRUB=$WORKDIR/esp-grub.img
ESP_LIMINE=$WORKDIR/esp-limine.img
ESP_SYSTEMD=$WORKDIR/esp-systemd.img
ESP_UKI=$WORKDIR/esp-uki.img

write_provider_root() {
    local tree=$1 provider=$2 root_uuid=$3
    case "$provider" in
        grub)
            mkdir -p "$tree/@/etc/default/grub.d" "$tree/@/boot/grub"
            cat > "$tree/@/etc/default/grub.d/00-catos.cfg" <<'CFG'
GRUB_DISTRIBUTOR=CatOS
GRUB_CMDLINE_LINUX_DEFAULT="quiet rw"
CFG
            cat > "$tree/@/boot/grub/grub.cfg" <<CFG
menuentry 'CatOS' {
    linux /vmlinuz-linux root=UUID=$root_uuid rw
    initrd /initramfs-linux.img
}
CFG
            ;;
        limine)
            mkdir -p "$tree/@/etc/default"
            cat > "$tree/@/etc/default/limine" <<'CFG'
ESP_PATH="/boot/efi"
KERNEL_CMDLINE[default]=quiet rw
ENABLE_UKI=no
CFG
            ;;
        systemd_boot)
            mkdir -p "$tree/@/etc/kernel/install.conf.d"
            cat > "$tree/@/etc/kernel/install.conf.d/20-catos-bootloadu.conf" <<'CFG'
BOOT_ROOT=/boot/efi
layout=bls
CFG
            ;;
        uki)
            mkdir -p "$tree/@/etc/catos"
            cat > "$tree/@/etc/catos/firmware-boot.conf" <<'CFG'
method = uki
esp_path = /boot/efi
CFG
            ;;
        *) echo "unsupported provider $provider" >&2; return 1 ;;
    esac
}

build_root_image() {
    local image=$1 root_uuid=$2 provider=$3 fstab_uuid=$4 metadata_dup=$5 runtime_tree=${6:-}
    local omit_fstab=${7:-no}
    local tree
    tree=$WORKDIR/tree-$(basename "$image" .img)
    rm -rf "$tree"
    mkdir -p \
        "$tree/@/etc" \
        "$tree/@/etc/kernel" \
        "$tree/@/home" \
        "$tree/@/root" \
        "$tree/@/srv" \
        "$tree/@/var/cache" \
        "$tree/@/var/tmp" \
        "$tree/@/var/log" \
        "$tree/@/.snapshots" \
        "$tree/@/boot/efi" \
        "$tree/@/var/lib/pacman/local/catos-base-1" \
        "$tree/@/usr/lib/modules/6.12.0-catos" \
        "$tree/@home" "$tree/@root" "$tree/@srv" "$tree/@cache" \
        "$tree/@tmp" "$tree/@log" "$tree/@snapshots" "$tree/@snapshot-source" \
        "$tree/.catos-recovery/transactions"
    if [[ -n $runtime_tree ]]; then
        cp -a "$runtime_tree"/. "$tree/@/"
        mkdir -p "$tree/@/sbin"
        cp "$runtime_tree/bin/running-root-init" "$tree/@/sbin/init"
        chmod +x "$tree/@/sbin/init"
    fi
    cat > "$tree/@/etc/os-release" <<'OS_RELEASE'
NAME="CatOS"
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS QEMU Fixture"
OS_RELEASE
    if [[ $omit_fstab != yes ]]; then
        cat > "$tree/@/etc/fstab" <<FSTAB
UUID=$fstab_uuid / btrfs defaults,subvol=/@ 0 0
UUID=$root_uuid /home btrfs defaults,subvol=/@home 0 0
UUID=$root_uuid /root btrfs defaults,subvol=/@root 0 0
UUID=$root_uuid /srv btrfs defaults,subvol=/@srv 0 0
UUID=$root_uuid /var/cache btrfs defaults,subvol=/@cache 0 0
UUID=$root_uuid /var/tmp btrfs defaults,subvol=/@tmp 0 0
UUID=$root_uuid /var/log btrfs defaults,subvol=/@log 0 0
UUID=$root_uuid /.snapshots btrfs defaults,subvol=/@snapshots 0 0
UUID=$ESP_UUID /boot/efi vfat umask=0077 0 2
FSTAB
    fi
    cat > "$tree/@/var/lib/pacman/local/catos-base-1/desc" <<'DESC'
%NAME%
catos-base

%VERSION%
1-1
DESC
    printf '%s\n' linux-catos > "$tree/@/usr/lib/modules/6.12.0-catos/pkgbase"
    printf 'fixture kernel\n' > "$tree/@/usr/lib/modules/6.12.0-catos/vmlinuz"
    printf 'quiet rw\n' > "$tree/@/etc/kernel/cmdline"
    write_provider_root "$tree" "$provider" "$root_uuid"

    rm -f "$image"
    truncate -s 384M "$image"
    local args=(-q -f -U "$root_uuid" -L "catos-$provider")
    if [[ $metadata_dup == yes ]]; then
        args+=(-m dup -d single)
    fi
    args+=(-r "$tree"
        --subvol default:@
        --subvol rw:@home
        --subvol rw:@root
        --subvol rw:@srv
        --subvol rw:@cache
        --subvol rw:@tmp
        --subvol rw:@log
        --subvol rw:@snapshots
        --subvol ro:@snapshot-source)
    mkfs.btrfs "${args[@]}" "$image" >/dev/null
    rm -rf "$tree"
}

build_ext4_root_image() {
    local image=$1 root_uuid=$2
    local tree
    tree=$WORKDIR/tree-$(basename "$image" .img)
    rm -rf "$tree"
    mkdir -p \
        "$tree/etc/default/grub.d" \
        "$tree/etc/kernel" \
        "$tree/boot/grub" \
        "$tree/boot/efi" \
        "$tree/var/lib/pacman/local/catos-base-1" \
        "$tree/usr/lib/modules/6.12.0-catos"
    cat > "$tree/etc/os-release" <<'OS_RELEASE'
NAME="CatOS"
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS QEMU Fixture"
OS_RELEASE
    cat > "$tree/etc/fstab" <<FSTAB
UUID=$root_uuid / ext4 defaults 0 1
UUID=$ESP_UUID /boot/efi vfat umask=0077 0 2
FSTAB
    cat > "$tree/etc/default/grub.d/00-catos.cfg" <<'CFG'
GRUB_DISTRIBUTOR=CatOS
GRUB_CMDLINE_LINUX_DEFAULT="quiet rw"
CFG
    cat > "$tree/boot/grub/grub.cfg" <<CFG
menuentry 'CatOS ext4 fixture' {
    linux /vmlinuz-linux root=UUID=$root_uuid rw
    initrd /initramfs-linux.img
}
CFG
    cat > "$tree/var/lib/pacman/local/catos-base-1/desc" <<'DESC'
%NAME%
catos-base

%VERSION%
1-1
DESC
    printf '%s\n' linux-catos > "$tree/usr/lib/modules/6.12.0-catos/pkgbase"
    printf 'fixture kernel\n' > "$tree/usr/lib/modules/6.12.0-catos/vmlinuz"
    printf 'quiet rw\n' > "$tree/etc/kernel/cmdline"
    rm -f "$image"
    truncate -s 256M "$image"
    mke2fs -q -F -t ext4 -U "$root_uuid" -L catos-ambig \
        -d "$tree" "$image"
    rm -rf "$tree"
}

build_esp_image() {
    local image=$1 provider=$2
    local tree=$WORKDIR/esp-tree-$provider
    rm -rf "$tree"
    mkdir -p "$tree"
    case "$provider" in
        grub)
            mkdir -p "$tree/EFI/GRUB"
            printf 'grub efi fixture\n' > "$tree/EFI/GRUB/grubx64.efi"
            ;;
        limine)
            mkdir -p "$tree/EFI/BOOT"
            cat > "$tree/limine.conf" <<'CFG'
:CatOS
KERNEL_PATH=boot():/vmlinuz-linux
MODULE_PATH=boot():/initramfs-linux.img
CFG
            printf 'limine efi fixture\n' > "$tree/EFI/BOOT/liminex64.efi"
            ;;
        systemd_boot)
            mkdir -p "$tree/loader/entries" "$tree/EFI/systemd"
            printf 'default catos.conf\n' > "$tree/loader/loader.conf"
            cat > "$tree/loader/entries/catos.conf" <<'CFG'
title CatOS
linux /vmlinuz-linux
initrd /initramfs-linux.img
options quiet rw
CFG
            printf 'systemd boot efi fixture\n' > "$tree/EFI/systemd/systemd-bootx64.efi"
            ;;
        uki)
            mkdir -p "$tree/EFI/Linux"
            printf 'uki fixture\n' > "$tree/EFI/Linux/catos-test.efi"
            ;;
        *) echo "unsupported provider $provider" >&2; return 1 ;;
    esac
    rm -f "$image"
    truncate -s 64M "$image"
    mkfs.fat -F 32 -i "$ESP_VOLUME_ID" -n CATOS_ESP "$image" >/dev/null
    MTOOLS_SKIP_CHECK=1 mcopy -s -i "$image" "$tree"/* ::/
    rm -rf "$tree"
}

corrupt_btrfs_metadata_mirror() {
    local image=$1
    local logical map_output physical
    logical=$(btrfs inspect-internal dump-tree -t root "$image" 2>/dev/null \
        | awk '/^leaf [0-9]+/ && !found { print $2; found=1 }')
    [[ -n $logical ]] || { echo "fail: cannot identify Btrfs root-tree block" >&2; return 1; }
    map_output=$(btrfs-map-logical -l "$logical" -c 1 -b 16384 \
        -o "$WORKDIR/btrfs-root-copy.bin" "$image" 2>&1)
    physical=$(awk '/^mirror 1 logical / { print $6; exit }' <<<"$map_output")
    [[ -n $physical ]] || {
        echo "fail: cannot map Btrfs metadata mirror" >&2
        echo "$map_output" >&2
        return 1
    }
    python3 - "$image" "$((physical + 1024))" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, "r+b", buffering=0) as image:
    image.seek(offset)
    original = image.read(1)
    if len(original) != 1:
        raise SystemExit("cannot read Btrfs corruption byte")
    image.seek(offset)
    image.write(bytes([original[0] ^ 0x5A]))
PY
    set +e
    btrfs check --readonly "$image" > "$WORKDIR/corrupt-precheck.log" 2>&1
    local rc=$?
    set -e
    if ! grep -q 'checksum verify failed' "$WORKDIR/corrupt-precheck.log"; then
        echo "fail: corruption fixture did not expose checksum failure (rc=$rc)" >&2
        cat "$WORKDIR/corrupt-precheck.log" >&2
        return 1
    fi
}

echo "info: building unprivileged Doctor fixtures"
build_esp_image "$ESP_GRUB" grub
build_esp_image "$ESP_LIMINE" limine
build_esp_image "$ESP_SYSTEMD" systemd_boot
build_esp_image "$ESP_UKI" uki
build_root_image "$ROOT_GRUB" "$UUID_GRUB" grub "$UUID_GRUB" no
build_root_image "$ROOT_LIMINE" "$UUID_LIMINE" limine "$UUID_LIMINE" no
build_root_image "$ROOT_SYSTEMD" "$UUID_SYSTEMD" systemd_boot "$UUID_SYSTEMD" no
build_root_image "$ROOT_UKI" "$UUID_UKI" uki "$UUID_UKI" no
build_root_image "$ROOT_BROKEN" "$UUID_BROKEN" grub deadbeef-dead-4bad-8bad-deadbeefdead no
build_root_image "$ROOT_NO_FSTAB" "$UUID_NO_FSTAB" grub "$UUID_NO_FSTAB" no "" yes
build_root_image "$ROOT_CORRUPT" "$UUID_CORRUPT" grub "$UUID_CORRUPT" yes
corrupt_btrfs_metadata_mirror "$ROOT_CORRUPT"
build_root_image "$ROOT_INTERRUPTED" "$UUID_INTERRUPTED" grub "$UUID_INTERRUPTED" no
build_root_image "$ROOT_AMBIG_A" "$UUID_AMBIG_A" grub "$UUID_AMBIG_A" no
build_ext4_root_image "$ROOT_AMBIG_B" "$UUID_AMBIG_B"

KVER=$(basename "$(dirname "$KERNEL")")
if [[ $KVER == modules || ! -d /usr/lib/modules/$KVER ]]; then
    KVER=$(uname -r)
fi

(
    cd "$SYSTEM_DIR"
    cargo build --quiet --release --target x86_64-unknown-linux-musl \
        --example doctor_transaction_fixture
)
FIXTURE_HELPER=$SYSTEM_DIR/target/x86_64-unknown-linux-musl/release/examples/doctor_transaction_fixture
[[ -x $FIXTURE_HELPER ]] || {
    echo "fail: Doctor transaction fixture helper was not built" >&2
    exit 1
}

rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,run,tmp,etc,usr/bin,usr/sbin,lib/modules/load}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
cp "$FIXTURE_HELPER" "$INITRAMFS/bin/doctor-transaction-fixture"
chmod +x \
    "$INITRAMFS/bin/busybox" \
    "$INITRAMFS/bin/catos-system" \
    "$INITRAMFS/bin/doctor-transaction-fixture"
ln -s catos-system "$INITRAMFS/bin/catos-doctor"
ln -s catos-system "$INITRAMFS/bin/catos-chroot"
for applet in sh mount umount cat echo printf sleep poweroff mkdir grep awk find \
              sync sed head tr insmod script timeout sha256sum chmod ln readlink basename dirname switch_root; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

copy_tool_with_deps() {
    local name=$1 src dest library
    src=$(command -v "$name")
    dest=$INITRAMFS$src
    mkdir -p "$(dirname "$dest")"
    cp -L "$src" "$dest"
    while read -r library; do
        [[ -f $library ]] || continue
        mkdir -p "$INITRAMFS$(dirname "$library")"
        cp -L "$library" "$INITRAMFS$library"
    done < <(ldd "$src" 2>/dev/null | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}')
}
copy_tool_with_deps btrfs
copy_tool_with_deps blkid
copy_tool_with_deps e2fsck

MODULE_LIST=$INITRAMFS/etc/modules.load
: > "$MODULE_LIST"
module_index=0
copy_module() {
    local source=$1 target
    [[ -f $source ]] || return 0
    module_index=$((module_index + 1))
    target=$(printf '/lib/modules/load/%03d-%s' "$module_index" "$(basename "$source")")
    target=${target%.zst}
    target=${target%.xz}
    target=${target%.gz}
    case "$source" in
        *.zst) zstd -q -d -c "$source" > "$INITRAMFS$target" ;;
        *.xz) xz -d -c "$source" > "$INITRAMFS$target" ;;
        *.gz) gzip -d -c "$source" > "$INITRAMFS$target" ;;
        *) cp "$source" "$INITRAMFS$target" ;;
    esac
    echo "$target" >> "$MODULE_LIST"
}
for module in btrfs vfat; do
    while read -r action module_path _; do
        [[ $action == insmod ]] || continue
        copy_module "$module_path"
    done < <(modprobe --show-depends -S "$KVER" "$module" 2>/dev/null || true)
done

cat > "$INITRAMFS/bin/doctor-child" <<'CHILD'
#!/bin/sh
/bin/catos-doctor
echo $? > /tmp/doctor.rc
CHILD
chmod +x "$INITRAMFS/bin/doctor-child"

cat > "$INITRAMFS/bin/doctor-workflow-child" <<'CHILD'
#!/bin/sh
/bin/catos-system
echo $? > /tmp/doctor.rc
CHILD
chmod +x "$INITRAMFS/bin/doctor-workflow-child"

cat > "$INITRAMFS/bin/running-root-init" <<'RUNNING_INIT'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mkdir -p /tmp /run /dev/pts
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp

rm -f /tmp/doctor.rc /tmp/doctor.out /tmp/doctor.err /tmp/typescript
printf '\n\n\n\n\n\n' | timeout -s KILL 30 script -q -c /bin/doctor-child /tmp/typescript \
    > /tmp/doctor.out 2> /tmp/doctor.err
rc=$(cat /tmp/doctor.rc 2>/dev/null || echo 255)
echo "__DOCTOR_BEGIN__"
cat /tmp/doctor.out
echo "__DOCTOR_STDERR__"
cat /tmp/doctor.err
echo "__DOCTOR_RC__=$rc"
echo "__DOCTOR_END__"
if grep -Fq '/run/catos-system/sessions/' /proc/self/mountinfo; then
    echo "__DOCTOR_RESIDUAL_MOUNTS__"
    grep -F '/run/catos-system/sessions/' /proc/self/mountinfo
else
    echo "__DOCTOR_NO_RESIDUAL_MOUNTS__"
fi
if [ -d /run/catos-system/sessions ] \
    && find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo "__DOCTOR_RESIDUAL_SESSION_DIRS__"
    find /run/catos-system/sessions -mindepth 1 -maxdepth 2 -print
else
    echo "__DOCTOR_NO_RESIDUAL_SESSION_DIRS__"
fi
poweroff -f
RUNNING_INIT
chmod +x "$INITRAMFS/bin/running-root-init"

cat > "$INITRAMFS/init" <<'GUEST'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run /tmp
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
chmod 0755 /run
chmod 1777 /tmp
while read -r module; do
    [ -n "$module" ] && insmod "$module" 2>/dev/null || true
done < /etc/modules.load
for device in /dev/vda /dev/vdb; do
    i=0
    while [ ! -b "$device" ] && [ "$i" -lt 100 ]; do
        sleep 0.05
        i=$((i + 1))
    done
done
SCENARIO=""
for arg in $(cat /proc/cmdline); do
    case "$arg" in catos_doctor_scenario=*) SCENARIO=${arg#catos_doctor_scenario=} ;; esac
done

if [ "$SCENARIO" = running_root ]; then
    mkdir -p /newroot
    if ! mount -t btrfs -o ro,norecovery,subvol=@ /dev/vda /newroot; then
        echo __RUNNING_ROOT_PREPARE_FAILED__=mount
        poweroff -f
    fi
    for path in proc sys dev run; do
        mkdir -p "/newroot/$path"
        mount --move "/$path" "/newroot/$path" || {
            echo "__RUNNING_ROOT_PREPARE_FAILED__=move-$path"
            poweroff -f
        }
    done
    exec switch_root /newroot /sbin/init
fi

if [ "$SCENARIO" = prepare_interrupted ]; then
    mkdir -p /tmp/prepare-root
    if ! mount -t btrfs -o rw,subvolid=5 /dev/vda /tmp/prepare-root; then
        echo __FIXTURE_PREPARE_FAILED__=mount
        poweroff -f
    fi
    fsid=$(btrfs filesystem show /dev/vda | awk '/uuid:/ { print $NF; exit }')
    major_minor=$(cat /sys/class/block/vda/dev)
    root_info=$(btrfs subvolume show /tmp/prepare-root/@)
    source_info=$(btrfs subvolume show /tmp/prepare-root/@snapshot-source)
    root_id=$(printf '%s\n' "$root_info" | awk '$1 == "Subvolume" && $2 == "ID:" { print $3; exit }')
    root_generation=$(printf '%s\n' "$root_info" | awk '$1 == "Generation:" { print $2; exit }')
    root_uuid=$(printf '%s\n' "$root_info" | awk '$1 == "UUID:" { print $2; exit }')
    source_id=$(printf '%s\n' "$source_info" | awk '$1 == "Subvolume" && $2 == "ID:" { print $3; exit }')
    source_generation=$(printf '%s\n' "$source_info" | awk '$1 == "Generation:" { print $2; exit }')
    source_uuid=$(printf '%s\n' "$source_info" | awk '$1 == "UUID:" { print $2; exit }')
    if [ -z "$fsid" ] || [ -z "$major_minor" ] || [ -z "$root_id" ] \
        || [ -z "$root_generation" ] || [ -z "$root_uuid" ] \
        || [ -z "$source_id" ] || [ -z "$source_generation" ] \
        || [ -z "$source_uuid" ]; then
        echo __FIXTURE_PREPARE_FAILED__=facts
        umount /tmp/prepare-root 2>/dev/null || true
        poweroff -f
    fi
    if /bin/doctor-transaction-fixture \
        /tmp/prepare-root \
        "$fsid" \
        "$major_minor" \
        "$root_id" \
        "$root_generation" \
        "$root_uuid" \
        "$source_id" \
        "$source_generation" \
        "$source_uuid"; then
        sync
        umount /tmp/prepare-root
        echo __FIXTURE_PREPARED__
    else
        echo __FIXTURE_PREPARE_FAILED__=helper
        umount /tmp/prepare-root 2>/dev/null || true
    fi
    poweroff -f
fi

run_tty() {
    input=$1
    command=${2:-/bin/doctor-child}
    rm -f /tmp/doctor.rc /tmp/doctor.out /tmp/doctor.err /tmp/typescript
    printf '%b' "$input" | timeout -s KILL 60 script -q -c "$command" /tmp/typescript \
        > /tmp/doctor.out 2> /tmp/doctor.err
    rc=$(cat /tmp/doctor.rc 2>/dev/null || echo 255)
    echo "__DOCTOR_BEGIN__"
    cat /tmp/doctor.out
    echo "__DOCTOR_STDERR__"
    cat /tmp/doctor.err
    echo "__DOCTOR_RC__=$rc"
    echo "__DOCTOR_END__"
}

if [ "$SCENARIO" = workflow_broken_fstab ]; then
    run_tty '1\ny\n1\ny\n\n\ny\n0\n' /bin/doctor-workflow-child
    mkdir -p /tmp/workflow-verify
    root_uuid=$(btrfs filesystem show /dev/vda | awk '/uuid:/ { print $NF; exit }')
    if mount -t btrfs -o ro,norecovery,subvol=@ /dev/vda /tmp/workflow-verify; then
        root_source=$(awk '$2 == "/" { print $1; exit }' /tmp/workflow-verify/etc/fstab)
        echo "__DOCTOR_WORKFLOW_ROOT_IDENTITY__=$root_source:$root_uuid"
        if [ "$root_source" = "UUID=$root_uuid" ]; then
            echo "__DOCTOR_WORKFLOW_FSTAB_REPAIRED__"
        else
            echo "__DOCTOR_WORKFLOW_FSTAB_NOT_REPAIRED__"
            cat /tmp/workflow-verify/etc/fstab
        fi
        if [ -f /tmp/workflow-verify/etc/fstab.catos-repair.backup ]; then
            echo "__DOCTOR_WORKFLOW_BACKUP_PRESENT__"
        else
            echo "__DOCTOR_WORKFLOW_BACKUP_MISSING__"
        fi
        umount /tmp/workflow-verify
    else
        echo "__DOCTOR_WORKFLOW_VERIFY_MOUNT_FAILED__"
    fi
elif [ "$SCENARIO" = ambiguous ]; then
    timeout -s KILL 30 /bin/catos-doctor \
        </dev/null > /tmp/non-tty.out 2> /tmp/non-tty.err
    non_tty_rc=$?
    echo "__NONTTY_BEGIN__"
    cat /tmp/non-tty.out
    cat /tmp/non-tty.err
    echo "__NONTTY_RC__=$non_tty_rc"
    echo "__NONTTY_END__"
    run_tty '1\n'
elif [ "$SCENARIO" = cancel ]; then
    run_tty 'n\n'
elif [ "$SCENARIO" = missing_fstab ]; then
    run_tty 'y\n\n\n\n\n\n\n\n\n\n'
else
    run_tty 'y\n'
fi
if grep -Fq '/run/catos-system/sessions/' /proc/self/mountinfo; then
    echo "__DOCTOR_RESIDUAL_MOUNTS__"
    grep -F '/run/catos-system/sessions/' /proc/self/mountinfo
else
    echo "__DOCTOR_NO_RESIDUAL_MOUNTS__"
fi
if [ -d /run/catos-system/sessions ] \
    && find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo "__DOCTOR_RESIDUAL_SESSION_DIRS__"
    find /run/catos-system/sessions -mindepth 1 -maxdepth 2 -print
else
    echo "__DOCTOR_NO_RESIDUAL_SESSION_DIRS__"
fi
sync
poweroff -f
GUEST
chmod +x "$INITRAMFS/init"
build_root_image "$ROOT_RUNNING" "$UUID_RUNNING" grub "$UUID_RUNNING" no "$INITRAMFS"
(
    cd "$INITRAMFS"
    find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -q -1 > "$INITRAMFS_IMG"
)

hash_image() { sha256sum "$1" | awk '{print $1}'; }
fail() { echo "fail: $*" >&2; KEEP_ON_FAILURE=1; exit 1; }
assert_contains() {
    local body=$1 needle=$2 context=$3
    grep -Fq -- "$needle" <<<"$body" || fail "$context: missing '$needle'"
}
assert_not_contains() {
    local body=$1 needle=$2 context=$3
    if grep -Fq -- "$needle" <<<"$body"; then fail "$context: unexpectedly contains '$needle'"; fi
}

LAST_LOG=""
run_qemu() {
    local scenario=$1 root_image=$2 esp_image=$3 extra_root=${4:-}
    local log=$WORKDIR/$scenario.serial.log
    local root_before esp_before extra_before=""
    root_before=$(hash_image "$root_image")
    esp_before=$(hash_image "$esp_image")
    [[ -z $extra_root ]] || extra_before=$(hash_image "$extra_root")
    local args=(
        -nodefaults -no-reboot -nographic -m 512M
        -kernel "$KERNEL" -initrd "$INITRAMFS_IMG"
        -append "console=ttyS0 quiet panic=-1 catos_doctor_scenario=$scenario"
        -drive "file=$root_image,format=raw,if=virtio,readonly=on"
        -drive "file=$esp_image,format=raw,if=virtio,readonly=on"
        -serial "file:$log"
    )
    [[ -z $extra_root ]] || args+=(
        -drive "file=$extra_root,format=raw,if=virtio,readonly=on"
    )
    if [[ -w /dev/kvm ]]; then args+=(-enable-kvm -cpu host); fi
    set +e
    timeout 120 "$QEMU_BIN" "${args[@]}" >/dev/null 2>&1
    local rc=$?
    set -e
    [[ $rc -ne 124 ]] || fail "$scenario: QEMU timed out"
    [[ -f $log ]] || fail "$scenario: no serial log"
    tr -d '\r' < "$log" > "$log.normalized"
    LAST_LOG=$(cat "$log.normalized")
    assert_contains "$LAST_LOG" "__DOCTOR_END__" "$scenario"
    [[ $(hash_image "$root_image") == "$root_before" ]] || fail "$scenario: root image changed"
    [[ $(hash_image "$esp_image") == "$esp_before" ]] || fail "$scenario: ESP image changed"
    if [[ -n $extra_root ]]; then
        [[ $(hash_image "$extra_root") == "$extra_before" ]] || fail "$scenario: second root image changed"
    fi
}

run_qemu_workflow() {
    local scenario=$1 root_image=$2 esp_image=$3
    local log=$WORKDIR/$scenario.serial.log
    local root_before esp_before
    root_before=$(hash_image "$root_image")
    esp_before=$(hash_image "$esp_image")
    local args=(
        -nodefaults -no-reboot -nographic -m 512M
        -kernel "$KERNEL" -initrd "$INITRAMFS_IMG"
        -append "console=ttyS0 quiet panic=-1 catos_doctor_scenario=$scenario"
        -drive "file=$root_image,format=raw,if=virtio"
        -drive "file=$esp_image,format=raw,if=virtio"
        -serial "file:$log"
    )
    if [[ -w /dev/kvm ]]; then args+=(-enable-kvm -cpu host); fi
    set +e
    timeout 120 "$QEMU_BIN" "${args[@]}" >/dev/null 2>&1
    local rc=$?
    set -e
    [[ $rc -ne 124 ]] || fail "$scenario: QEMU timed out"
    [[ -f $log ]] || fail "$scenario: no serial log"
    tr -d '\r' < "$log" > "$log.normalized"
    LAST_LOG=$(cat "$log.normalized")
    assert_contains "$LAST_LOG" "__DOCTOR_END__" "$scenario"
    [[ $(hash_image "$root_image") != "$root_before" ]] \
        || fail "$scenario: repair did not change root image"
    [[ $(hash_image "$esp_image") == "$esp_before" ]] \
        || fail "$scenario: ESP image changed"
}

prepare_interrupted_fixture() {
    local log=$WORKDIR/prepare_interrupted.serial.log
    local esp_before
    esp_before=$(hash_image "$ESP_GRUB")
    local args=(
        -nodefaults -no-reboot -nographic -m 512M
        -kernel "$KERNEL" -initrd "$INITRAMFS_IMG"
        -append "console=ttyS0 quiet panic=-1 catos_doctor_scenario=prepare_interrupted"
        -drive "file=$ROOT_INTERRUPTED,format=raw,if=virtio"
        -drive "file=$ESP_GRUB,format=raw,if=virtio,readonly=on"
        -serial "file:$log"
    )
    if [[ -w /dev/kvm ]]; then args+=(-enable-kvm -cpu host); fi
    set +e
    timeout 120 "$QEMU_BIN" "${args[@]}" >/dev/null 2>&1
    local rc=$?
    set -e
    [[ $rc -ne 124 ]] || fail "prepare_interrupted: QEMU timed out"
    [[ -f $log ]] || fail "prepare_interrupted: no serial log"
    tr -d '\r' < "$log" > "$log.normalized"
    local body
    body=$(cat "$log.normalized")
    assert_contains "$body" "__FIXTURE_PREPARED__" prepare_interrupted
    assert_not_contains "$body" "__FIXTURE_PREPARE_FAILED__" prepare_interrupted
    [[ $(hash_image "$ESP_GRUB") == "$esp_before" ]] \
        || fail "prepare_interrupted: ESP image changed"
}

assert_doctor_success() {
    local body=$1 scenario=$2
    assert_contains "$body" "__DOCTOR_RC__=0" "$scenario"
    assert_contains "$body" "Item          | Status" "$scenario"
    assert_contains "$body" "__DOCTOR_NO_RESIDUAL_MOUNTS__" "$scenario"
    assert_contains "$body" "__DOCTOR_NO_RESIDUAL_SESSION_DIRS__" "$scenario"
    assert_not_contains "$body" "__DOCTOR_RESIDUAL_MOUNTS__" "$scenario"
    assert_not_contains "$body" "__DOCTOR_RESIDUAL_SESSION_DIRS__" "$scenario"
}

assert_provider() {
    local scenario=$1 root=$2 esp=$3 uuid=$4 provider=$5
    echo "=== scenario: provider-$provider ==="
    run_qemu "$scenario" "$root" "$esp"
    local out=$LAST_LOG
    assert_doctor_success "$out" "$scenario"
    assert_contains "$out" "Selected target: CatOS QEMU Fixture" "$scenario"
    assert_contains "$out" "UUID=$uuid" "$scenario"
    assert_contains "$out" "Overall       |" "$scenario"
    assert_contains "$out" "target=offline" "$scenario"
    assert_contains "$out" "Storage       | healthy    | /dev/vda; btrfs; /@" "$scenario"
    assert_contains "$out" "Mount layout  | healthy" "$scenario"
    assert_contains "$out" "Boot          | healthy    | provider=$provider" "$scenario"
    assert_not_contains "$out" "BOOT_ASSET_MISSING" "$scenario"
    assert_not_contains "$out" "STANDARD_SUBVOLUME_MISSING" "$scenario"
}

echo "=== scenario: prepare-interrupted-transaction ==="
prepare_interrupted_fixture

assert_provider provider_grub "$ROOT_GRUB" "$ESP_GRUB" "$UUID_GRUB" grub
assert_contains "$LAST_LOG" "Recovery      | healthy    | no in-flight recovery transactions on target" "healthy"

assert_provider provider_limine "$ROOT_LIMINE" "$ESP_LIMINE" "$UUID_LIMINE" limine
assert_provider provider_systemd "$ROOT_SYSTEMD" "$ESP_SYSTEMD" "$UUID_SYSTEMD" systemd-boot
assert_provider provider_uki "$ROOT_UKI" "$ESP_UKI" "$UUID_UKI" uki

echo "=== scenario: running-root ==="
run_qemu running_root "$ROOT_RUNNING" "$ESP_GRUB" "$ROOT_LIMINE"
assert_doctor_success "$LAST_LOG" running_root
assert_contains "$LAST_LOG" "Selected target: CatOS QEMU Fixture" running_root
assert_contains "$LAST_LOG" "UUID=$UUID_RUNNING" running_root
assert_contains "$LAST_LOG" "target=running" running_root
assert_contains "$LAST_LOG" "Storage       | healthy    | /dev/vda; btrfs; /@" running_root
assert_not_contains "$LAST_LOG" "target=offline" running_root
assert_not_contains "$LAST_LOG" "TARGET_NOT_FOUND" running_root
assert_not_contains "$LAST_LOG" "OFFLINE_FIRMWARE_STATE_UNAVAILABLE" running_root
assert_contains "$LAST_LOG" "Secure Boot   | n/a" running_root
assert_not_contains "$LAST_LOG" "FIRMWARE_SECURE_BOOT_UNAVAILABLE" running_root
assert_not_contains "$LAST_LOG" "__RUNNING_ROOT_PREPARE_FAILED__" running_root

echo "=== scenario: decline-target ==="
run_qemu cancel "$ROOT_GRUB" "$ESP_GRUB"
assert_contains "$LAST_LOG" "Use this target? [y/N]" cancel
assert_contains "$LAST_LOG" "__DOCTOR_RC__=0" cancel
assert_contains "$LAST_LOG" "__DOCTOR_NO_RESIDUAL_MOUNTS__" cancel
assert_contains "$LAST_LOG" "__DOCTOR_NO_RESIDUAL_SESSION_DIRS__" cancel
assert_not_contains "$LAST_LOG" "Item          | Status" cancel
assert_not_contains "$LAST_LOG" "TARGET_NOT_FOUND" cancel

echo "=== scenario: missing-fstab-partial-diagnosis ==="
run_qemu missing_fstab "$ROOT_NO_FSTAB" "$ESP_GRUB"
assert_doctor_success "$LAST_LOG" missing_fstab
assert_contains "$LAST_LOG" "Selected target: CatOS QEMU Fixture" missing_fstab
assert_contains "$LAST_LOG" "MOUNT_FACTS_INCOMPLETE" missing_fstab
assert_contains "$LAST_LOG" "ESP_FACTS_INCOMPLETE" missing_fstab
assert_contains "$LAST_LOG" "BOOT_LAYOUT_FACTS_INCOMPLETE" missing_fstab
assert_contains "$LAST_LOG" "BOOT_FILES_INCOMPLETE" missing_fstab
assert_contains "$LAST_LOG" "Filesystem    |" missing_fstab
assert_contains "$LAST_LOG" "Recovery      |" missing_fstab
assert_not_contains "$LAST_LOG" "DOCTOR_CONTEXT_OPEN_FAILED" missing_fstab

echo "=== scenario: broken-fstab ==="
run_qemu broken_fstab "$ROOT_BROKEN" "$ESP_GRUB"
assert_doctor_success "$LAST_LOG" broken_fstab
assert_contains "$LAST_LOG" "FSTAB_ROOT_SOURCE_MISMATCH" broken_fstab
assert_contains "$LAST_LOG" "Mount layout  | unhealthy" broken_fstab

echo "=== scenario: Doctor-recommended mount repair and automatic recheck ==="
build_root_image "$ROOT_BROKEN" "$UUID_BROKEN" grub deadbeef-dead-4bad-8bad-deadbeefdead no
run_qemu_workflow workflow_broken_fstab "$ROOT_BROKEN" "$ESP_GRUB"
assert_contains "$LAST_LOG" "Doctor Recommended Actions" workflow_broken_fstab
assert_contains "$LAST_LOG" "Repair mount layout on /dev/vda" workflow_broken_fstab
assert_contains "$LAST_LOG" "Re-running Doctor to verify the selected target" workflow_broken_fstab
assert_contains "$LAST_LOG" "__DOCTOR_WORKFLOW_FSTAB_REPAIRED__" workflow_broken_fstab
assert_contains "$LAST_LOG" "__DOCTOR_WORKFLOW_BACKUP_PRESENT__" workflow_broken_fstab
assert_not_contains "$LAST_LOG" "__DOCTOR_WORKFLOW_FSTAB_NOT_REPAIRED__" workflow_broken_fstab
assert_not_contains "$LAST_LOG" "__DOCTOR_WORKFLOW_VERIFY_MOUNT_FAILED__" workflow_broken_fstab
post_recheck=${LAST_LOG#*Re-running Doctor to verify the selected target...}
assert_contains "$post_recheck" "Mount layout  | healthy" workflow_broken_fstab
assert_contains "$post_recheck" "No directly executable Doctor recommendations remain." workflow_broken_fstab
assert_contains "$LAST_LOG" "__DOCTOR_RC__=0" workflow_broken_fstab
assert_contains "$LAST_LOG" "__DOCTOR_NO_RESIDUAL_MOUNTS__" workflow_broken_fstab
assert_contains "$LAST_LOG" "__DOCTOR_NO_RESIDUAL_SESSION_DIRS__" workflow_broken_fstab

echo "=== scenario: filesystem-corruption ==="
run_qemu filesystem_corruption "$ROOT_CORRUPT" "$ESP_GRUB"
assert_doctor_success "$LAST_LOG" filesystem_corruption
assert_contains "$LAST_LOG" "FS_CORRUPTION_DETECTED" filesystem_corruption
assert_contains "$LAST_LOG" "Filesystem    | critical" filesystem_corruption

echo "=== scenario: ambiguous-targets ==="
run_qemu ambiguous "$ROOT_AMBIG_A" "$ESP_GRUB" "$ROOT_AMBIG_B"
assert_contains "$LAST_LOG" "__NONTTY_RC__=" ambiguous
non_tty_rc=$(sed -n 's/^__NONTTY_RC__=//p' <<<"$LAST_LOG" | tail -1)
[[ -n $non_tty_rc && $non_tty_rc != 0 ]] || fail "ambiguous: non-TTY call did not fail"
assert_contains "$LAST_LOG" "TARGET_AMBIGUOUS" ambiguous
assert_contains "$LAST_LOG" "  [1] CatOS QEMU Fixture" ambiguous
assert_contains "$LAST_LOG" "  [2] CatOS QEMU Fixture" ambiguous
assert_contains "$LAST_LOG" "  [0] Back" ambiguous
assert_contains "$LAST_LOG" "__DOCTOR_RC__=0" ambiguous
index_one=$(sed -n 's/^  \[1\] //p' <<<"$LAST_LOG" | head -1)
selected=$(sed -n 's/.*Selected target: //p' <<<"$LAST_LOG" | tail -1)
[[ -n $index_one && $selected == "$index_one" ]] \
    || fail "ambiguous: selected target does not match displayed index 1 (index='$index_one', selected='$selected')"

echo "=== scenario: interrupted-transaction ==="
run_qemu interrupted_transaction "$ROOT_INTERRUPTED" "$ESP_GRUB"
assert_doctor_success "$LAST_LOG" interrupted_transaction
assert_contains "$LAST_LOG" "RECOVERY_TRANSACTION_INTERRUPTED" interrupted_transaction
assert_contains "$LAST_LOG" "catos-recovery resume" interrupted_transaction
assert_contains "$LAST_LOG" "tx-00000000000000000000000000000004" interrupted_transaction

echo "pass: Doctor QEMU acceptance exercised read-only diagnosis, typed recommendation execution, automatic recheck, provider matrix, partial diagnosis without fstab, corruption, ambiguity, recovery, cleanup and no-write hashes"
