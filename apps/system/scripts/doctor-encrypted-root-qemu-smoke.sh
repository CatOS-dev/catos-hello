#!/usr/bin/env bash
# Real encrypted-running-root acceptance for catos-doctor.
#
# The guest opens a LUKS2 device, creates a CatOS Btrfs layout on the mapper,
# mounts /@ as the real process root with switch_root, then runs the production
# Doctor binary. This proves that /dev/dm-N inventory entries are associated
# with mountinfo sources such as /dev/mapper/cryptroot even though Btrfs uses an
# anonymous 0:NN mountinfo device number.

set -euo pipefail

BIN=""
KERNEL=""
BUSYBOX=""
QEMU_BIN=""
WORKDIR=""
KEEP=0

usage() {
    cat >&2 <<EOF
usage: $0 --bin PATH [--kernel PATH] [--busybox PATH] [--qemu PATH] [--workdir DIR] [--keep]
EOF
}

while (($#)); do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --kernel) KERNEL=$2; shift 2 ;;
        --busybox) BUSYBOX=$2; shift 2 ;;
        --qemu) QEMU_BIN=$2; shift 2 ;;
        --workdir) WORKDIR=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
[[ -n $QEMU_BIN ]] || QEMU_BIN=$(command -v qemu-system-x86_64 2>/dev/null || true)
[[ -n $BUSYBOX ]] || BUSYBOX=$(command -v busybox 2>/dev/null || true)
if [[ -z $KERNEL ]]; then
    for candidate in \
        "/usr/lib/modules/$(uname -r)/vmlinuz" \
        /usr/lib/modules/*/vmlinuz \
        /boot/vmlinuz-linux \
        /boot/vmlinuz-linux-lts \
        /boot/vmlinuz-*; do
        if [[ -f $candidate ]]; then KERNEL=$candidate; break; fi
    done
fi

missing=()
[[ -x $BIN ]] || missing+=("static catos-system binary")
[[ -x $QEMU_BIN ]] || missing+=("qemu-system-x86_64")
[[ -x $BUSYBOX ]] || missing+=("static busybox")
[[ -f $KERNEL ]] || missing+=("kernel image")
for tool in cpio gzip timeout truncate cryptsetup ldd modprobe zstd xz; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
    echo "skip: encrypted-root Doctor QEMU prerequisites are missing:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi
if ! "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null \
    || ! "$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null; then
    echo "skip: encrypted-root Doctor QEMU requires static catos-system and busybox" >&2
    exit 77
fi

WORKDIR=${WORKDIR:-$(mktemp -d -t catos-doctor-crypt-qemu-XXXXXX)}
INITRAMFS=$WORKDIR/initramfs
INITRAMFS_IMG=$WORKDIR/initramfs.cpio.gz
LUKS_IMG=$WORKDIR/luks-root.img
KEY_FILE=$WORKDIR/crypt.key
SERIAL_LOG=$WORKDIR/serial.log
KVER=$(basename "$(dirname "$KERNEL")")
if [[ $KVER == modules || ! -d /usr/lib/modules/$KVER ]]; then KVER=$(uname -r); fi

cleanup() {
    if ((KEEP)); then
        echo "info: keeping workdir $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT
fail() { echo "fail: $*" >&2; KEEP=1; exit 1; }

mkdir -p "$INITRAMFS"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,run,tmp,mnt,newroot,etc,lib/modules/load}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod 755 "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system"
ln -s catos-system "$INITRAMFS/bin/catos-doctor"
for applet in sh mount umount switch_root cat echo printf sleep poweroff mkdir grep awk \
              find sync sed head tr insmod chmod ln readlink cp rm touch; do
    ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
done
ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

copy_tool_with_deps() {
    local name=$1 src library
    src=$(command -v "$name")
    mkdir -p "$INITRAMFS$(dirname "$src")"
    cp -L "$src" "$INITRAMFS$src"
    while read -r library; do
        [[ -f $library ]] || continue
        mkdir -p "$INITRAMFS$(dirname "$library")"
        cp -L "$library" "$INITRAMFS$library"
    done < <(ldd "$src" 2>/dev/null | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}')
}
for tool in cryptsetup btrfs mkfs.btrfs blkid; do copy_tool_with_deps "$tool"; done

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
for module in dm_crypt btrfs; do
    while read -r action module_path _; do
        [[ $action == insmod ]] || continue
        copy_module "$module_path"
    done < <(modprobe --show-depends -S "$KVER" "$module" 2>/dev/null || true)
done

printf 'catos-encrypted-root-qemu-key\n' > "$KEY_FILE"
chmod 600 "$KEY_FILE"
cp "$KEY_FILE" "$INITRAMFS/etc/crypt.key"
truncate -s 768M "$LUKS_IMG"
cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 \
    --key-file "$KEY_FILE" "$LUKS_IMG"

cat > "$INITRAMFS/init" <<'GUEST_INIT'
#!/bin/sh
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
chmod 1777 /tmp
while read -r module; do
    [ -n "$module" ] && insmod "$module" 2>/dev/null || true
done < /etc/modules.load
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && break
    sleep 1
done
[ -b /dev/vda ] || { echo '__CRYPT_DOCTOR_FATAL__ missing /dev/vda'; poweroff -f; }
mkdir -p /dev/mapper /run/cryptsetup
if ! cryptsetup open --type luks --disable-locks --key-file /etc/crypt.key /dev/vda cryptroot; then
    echo '__CRYPT_DOCTOR_FATAL__ cryptsetup open failed'
    poweroff -f
fi
for _ in 1 2 3 4 5; do
    [ -b /dev/mapper/cryptroot ] && break
    sleep 1
done
[ -b /dev/mapper/cryptroot ] || { echo '__CRYPT_DOCTOR_FATAL__ mapper node missing'; poweroff -f; }

ROOT_UUID=12345678-1234-4234-8234-123456789abc
mkfs.btrfs -q -f -U "$ROOT_UUID" -L catos-crypt-root /dev/mapper/cryptroot
mount /dev/mapper/cryptroot /mnt
for subvol in @ @home @root @srv @cache @tmp @log @snapshots; do
    btrfs subvolume create "/mnt/$subvol" >/dev/null
done
root=/mnt/@
mkdir -p "$root/bin" "$root/sbin" "$root/usr" "$root/lib" "$root/lib64" \
    "$root/etc" "$root/proc" "$root/sys" "$root/dev" "$root/run" "$root/tmp" \
    "$root/home" "$root/root" "$root/srv" "$root/var/cache" "$root/var/tmp" \
    "$root/var/log" "$root/.snapshots" "$root/boot/grub"
for tree in bin sbin usr lib lib64; do
    [ -e "/$tree" ] && cp -a "/$tree" "$root/"
done
rm -f "$root/etc/initrd-release"
mkdir -p "$root/etc/default/grub.d" "$root/etc/kernel" \
    "$root/var/lib/pacman/local/catos-base-1" "$root/usr/lib/modules/6.12.0-catos"
cat > "$root/etc/os-release" <<'EOF'
NAME="CatOS"
ID=catos
ID_LIKE=arch
PRETTY_NAME="CatOS Encrypted Root QEMU"
EOF
cat > "$root/etc/fstab" <<EOF
UUID=$ROOT_UUID / btrfs defaults,subvol=/@ 0 0
UUID=$ROOT_UUID /home btrfs defaults,subvol=/@home 0 0
UUID=$ROOT_UUID /root btrfs defaults,subvol=/@root 0 0
UUID=$ROOT_UUID /srv btrfs defaults,subvol=/@srv 0 0
UUID=$ROOT_UUID /var/cache btrfs defaults,subvol=/@cache 0 0
UUID=$ROOT_UUID /var/tmp btrfs defaults,subvol=/@tmp 0 0
UUID=$ROOT_UUID /var/log btrfs defaults,subvol=/@log 0 0
UUID=$ROOT_UUID /.snapshots btrfs defaults,subvol=/@snapshots 0 0
EOF
cat > "$root/etc/default/grub.d/00-catos.cfg" <<'EOF'
GRUB_DISTRIBUTOR=CatOS
GRUB_CMDLINE_LINUX_DEFAULT="quiet rw"
EOF
cat > "$root/boot/grub/grub.cfg" <<EOF
menuentry 'CatOS encrypted fixture' {
    linux /vmlinuz-linux root=UUID=$ROOT_UUID rw rootflags=subvol=/@
    initrd /initramfs-linux.img
}
EOF
printf 'fixture kernel\n' > "$root/boot/vmlinuz-linux"
printf 'fixture initramfs\n' > "$root/boot/initramfs-linux.img"
printf 'quiet rw\n' > "$root/etc/kernel/cmdline"
cat > "$root/var/lib/pacman/local/catos-base-1/desc" <<'EOF'
%NAME%
catos-base

%VERSION%
1-1
EOF
printf 'linux-catos\n' > "$root/usr/lib/modules/6.12.0-catos/pkgbase"
printf 'fixture kernel\n' > "$root/usr/lib/modules/6.12.0-catos/vmlinuz"
cat > "$root/sbin/init" <<'ROOT_INIT'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
echo '__CRYPT_DOCTOR_BEGIN__'
/bin/catos-doctor </dev/null
rc=$?
echo "__CRYPT_DOCTOR_RC__=$rc"
root_line=$(awk '$5 == "/" { print; exit }' /proc/self/mountinfo)
echo "__CRYPT_ROOT_MOUNTINFO__=$root_line"
if grep -Fq '/run/catos-system/sessions/' /proc/self/mountinfo; then
    echo '__CRYPT_DOCTOR_RESIDUAL_MOUNTS__'
else
    echo '__CRYPT_DOCTOR_NO_RESIDUAL_MOUNTS__'
fi
echo '__CRYPT_DOCTOR_END__'
sync
poweroff -f
ROOT_INIT
chmod 755 "$root/sbin/init"
sync
umount /mnt
mount -o subvol=/@ /dev/mapper/cryptroot /newroot
mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
mount --move /dev /newroot/dev
mount --move /run /newroot/run
exec switch_root /newroot /sbin/init
GUEST_INIT
chmod 755 "$INITRAMFS/init"
(
    cd "$INITRAMFS"
    find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -q -1 > "$INITRAMFS_IMG"
)

accel=()
if [[ -w /dev/kvm ]] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel=(-enable-kvm -cpu host)
fi
set +e
timeout 180 "$QEMU_BIN" -nodefaults -no-reboot -nographic -m 1024M \
    "${accel[@]}" -kernel "$KERNEL" -initrd "$INITRAMFS_IMG" \
    -append 'console=ttyS0 quiet panic=-1 rdinit=/init' \
    -drive "file=$LUKS_IMG,format=raw,if=virtio" \
    -serial "file:$SERIAL_LOG" >/dev/null 2>&1
qemu_rc=$?
set -e
[[ $qemu_rc -ne 124 ]] || fail "QEMU timed out"
[[ -f $SERIAL_LOG ]] || fail "QEMU produced no serial log"
tr -d '\r' < "$SERIAL_LOG" > "$SERIAL_LOG.normalized"
body=$(cat "$SERIAL_LOG.normalized")

[[ $body == *'__CRYPT_DOCTOR_END__'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "guest did not complete"; }
[[ $body != *'__CRYPT_DOCTOR_FATAL__'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "guest setup failed"; }
[[ $body == *'__CRYPT_DOCTOR_RC__=0'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "Doctor returned nonzero"; }
[[ $body == *'target=running'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "encrypted current root was not selected as running"; }
[[ $body == *'catos-repair boot --root-device /dev/dm-0'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "Doctor did not bind its repair action to the selected dm inventory identity"; }
[[ $body == *'subvol=/@'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "running root subvolume identity missing"; }
[[ $body == *'/dev/mapper/cryptroot'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "root mountinfo did not retain mapper source"; }
[[ $body == *'__CRYPT_DOCTOR_NO_RESIDUAL_MOUNTS__'* ]] || { cat "$SERIAL_LOG.normalized" >&2; fail "Doctor left residual mounts"; }
[[ $body != *'TARGET_NOT_FOUND'* ]] || fail "Doctor reported target not found"
[[ $body != *'target=offline'* ]] || fail "encrypted running root was misclassified as offline"
[[ $body != *'FS_CORRUPTION_DETECTED'* ]] || fail "Doctor ran an invalid online corruption path"

echo "pass: encrypted Btrfs running root is selected through /dev/dm-* and /dev/mapper alias identity"
