#!/usr/bin/env bash
# Stage-4 state-changing boot repair acceptance.
#
# This test builds real CatOS-style target disks, runs the static backend from
# an independent rescue initramfs, then boots the repaired target from its own
# firmware/bootloader until a systemd userspace marker is emitted.
#
# Covered providers:
#   * GRUB BIOS
#   * GRUB UEFI
#   * Limine with CatOS limine-tool (never the legacy entity package)
#   * systemd-boot with catos-systemd-boot-config
#   * UKI with catos-firmware-boot + systemd-ukify
#   * EFI Stub with catos-firmware-boot
#
# The harness also runs a real provider-command failure/rollback scenario and
# a real shared-device-lock contention scenario. Exit 77 is reserved for an
# unavailable host capability or provider package; an unexecuted scenario is
# never reported as passed.

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: boot-repair-qemu-smoke.sh --bin PATH [options]

Options:
  --kernel PATH
  --busybox PATH
  --qemu PATH
  --workdir DIR
  --scenario NAME                 Run one provider scenario.
  --limine-pkg PATH
  --limine-tool-pkg PATH
  --systemd-boot-config-pkg PATH
  --firmware-boot-pkg PATH
  --keep
USAGE
}

BIN=""
KERNEL=""
BUSYBOX=""
QEMU_BIN=""
WORKDIR=""
SCENARIO=""
LIMINE_PKG=""
LIMINE_TOOL_PKG=""
SYSTEMD_BOOT_CONFIG_PKG=""
FIRMWARE_BOOT_PKG=""
KEEP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        --kernel) KERNEL="$2"; shift 2 ;;
        --busybox) BUSYBOX="$2"; shift 2 ;;
        --qemu) QEMU_BIN="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --limine-pkg) LIMINE_PKG="$2"; shift 2 ;;
        --limine-tool-pkg) LIMINE_TOOL_PKG="$2"; shift 2 ;;
        --systemd-boot-config-pkg) SYSTEMD_BOOT_CONFIG_PKG="$2"; shift 2 ;;
        --firmware-boot-pkg) FIRMWARE_BOOT_PKG="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
BUILDBOT_ROOT=$(cd "$REPO_ROOT/../.." && pwd)
ORIGINAL_UID=${SUDO_UID:-$(id -u)}
ORIGINAL_GID=${SUDO_GID:-$(id -g)}
ORIGINAL_USER=${SUDO_USER:-$(id -un)}

skip() {
    echo "skip: $*" >&2
    exit 77
}

fail() {
    echo "fail: $*" >&2
    KEEP=1
    exit 1
}

[ -n "$QEMU_BIN" ] || QEMU_BIN=$(command -v qemu-system-x86_64 2>/dev/null || true)
[ -n "$BUSYBOX" ] || BUSYBOX=$(command -v busybox 2>/dev/null || true)
if [ -z "$KERNEL" ]; then
    for candidate in "/usr/lib/modules/$(uname -r)/vmlinuz" /usr/lib/modules/*/vmlinuz /boot/vmlinuz-*; do
        if [ -f "$candidate" ]; then KERNEL="$candidate"; break; fi
    done
fi

OVMF_CODE=""
OVMF_VARS_TEMPLATE=""
for candidate in \
    /usr/share/ovmf/x64/OVMF_CODE.4m.fd \
    /usr/share/edk2/x64/OVMF_CODE.4m.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd \
    /usr/share/edk2/x64/OVMF_CODE.fd; do
    if [ -f "$candidate" ]; then OVMF_CODE="$candidate"; break; fi
done
for candidate in \
    /usr/share/ovmf/x64/OVMF_VARS.4m.fd \
    /usr/share/edk2/x64/OVMF_VARS.4m.fd \
    /usr/share/edk2/ovmf/OVMF_VARS.fd \
    /usr/share/edk2/x64/OVMF_VARS.fd; do
    if [ -f "$candidate" ]; then OVMF_VARS_TEMPLATE="$candidate"; break; fi
done

missing=()
[ -x "$BIN" ] || missing+=("static catos-system binary")
[ -x "$QEMU_BIN" ] || missing+=("qemu-system-x86_64")
[ -x "$BUSYBOX" ] || missing+=("static busybox")
[ -f "$KERNEL" ] || missing+=("kernel image")
for tool in \
    arch-chroot awk blkid bsdtar chown cpio depmod find flock gpgconf gzip \
    ldd losetup makepkg mkfs.ext4 mkfs.vfat modinfo mount mountpoint pacman \
    pacstrap python3 readelf runuser sfdisk sgdisk sha256sum sort timeout \
    truncate udevadm umount unshare zstd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -ne 0 ]; then
    echo "skip: missing boot-repair QEMU prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi

if [ "$(id -u)" -ne 0 ]; then
    skip "real boot-repair QEMU acceptance needs root for private loop mounts; run this test through sudo"
fi
if [ "${CATOS_BOOT_REPAIR_PRIVATE_NS:-0}" != 1 ]; then
    exec unshare --mount --propagation private \
        env CATOS_BOOT_REPAIR_PRIVATE_NS=1 \
        SUDO_UID="$ORIGINAL_UID" SUDO_GID="$ORIGINAL_GID" SUDO_USER="$ORIGINAL_USER" \
        "$0" --bin "$BIN" --kernel "$KERNEL" --busybox "$BUSYBOX" --qemu "$QEMU_BIN" \
        ${WORKDIR:+--workdir "$WORKDIR"} ${SCENARIO:+--scenario "$SCENARIO"} \
        ${LIMINE_PKG:+--limine-pkg "$LIMINE_PKG"} \
        ${LIMINE_TOOL_PKG:+--limine-tool-pkg "$LIMINE_TOOL_PKG"} \
        ${SYSTEMD_BOOT_CONFIG_PKG:+--systemd-boot-config-pkg "$SYSTEMD_BOOT_CONFIG_PKG"} \
        ${FIRMWARE_BOOT_PKG:+--firmware-boot-pkg "$FIRMWARE_BOOT_PKG"} \
        $([ "$KEEP" -eq 1 ] && printf '%s' --keep)
fi

"$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || skip "catos-system is not static"
"$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null || skip "busybox is not static"

WORKDIR=${WORKDIR:-$(mktemp -d -t catos-boot-repair-qemu-XXXXXX)}
mkdir -p "$WORKDIR" "$WORKDIR/packages" "$WORKDIR/logs"
PACKAGE_DIR="$WORKDIR/packages"
UEFI_BASE="$WORKDIR/base-uefi.img"
BIOS_BASE="$WORKDIR/base-bios.img"
RESCUE_ROOT="$WORKDIR/rescue-root"
RESCUE_IMAGE="$WORKDIR/rescue.cpio.gz"
KVER=$(basename "$(dirname "$KERNEL")")
if [ ! -d "/usr/lib/modules/$KVER" ]; then KVER=$(uname -r); fi

cleanup() {
    set +e
    for image in "$WORKDIR"/*.img; do
        [ -e "$image" ] || continue
        losetup -j "$image" 2>/dev/null | cut -d: -f1 | while read -r loop; do
            [ -z "$loop" ] || losetup -d "$loop" 2>/dev/null || true
        done
    done
    if [ "$KEEP" -eq 1 ]; then
        echo "info: keeping boot-repair workdir $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

find_latest() {
    python3 - "$@" <<'PY'
import glob, os, sys
items=[]
for pattern in sys.argv[1:]:
    items.extend(path for path in glob.glob(pattern) if not path.endswith('.sig'))
items=sorted(set(items), key=lambda path: os.path.getmtime(path))
print(items[-1] if items else '')
PY
}

pkg_name() {
    bsdtar -xOf "$1" .PKGINFO | awk '$1 == "pkgname" && $2 == "=" { print $3; exit }'
}

require_pkg_name() {
    local path="$1" expected="$2" actual
    [ -f "$path" ] || return 1
    actual=$(pkg_name "$path")
    [ "$actual" = "$expected" ] || fail "package $path has pkgname=$actual, expected $expected"
}

download_pkg() {
    local name="$1"
    pacman -Sw --noconfirm --cachedir "$PACKAGE_DIR" "$name" >/dev/null 2>&1 || return 1
    find_latest "$PACKAGE_DIR/${name}-*.pkg.tar.*"
}

build_simple_pkg() {
    local name="$1" source_dir="$2" build_dir="$WORKDIR/pkgbuild-$name" result
    [ -d "$source_dir" ] || return 1
    [ "$ORIGINAL_UID" -ne 0 ] || return 1
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cp -a "$source_dir"/. "$build_dir"/
    rm -rf "$build_dir/pkg" "$build_dir/src"
    find "$build_dir" -maxdepth 1 -type f -name '*.pkg.tar.*' -delete
    chown -R "$ORIGINAL_UID:$ORIGINAL_GID" "$build_dir"
    runuser -u "$ORIGINAL_USER" -- sh -c 'cd "$1" && makepkg --cleanbuild --clean --noconfirm' sh "$build_dir" \
        >"$WORKDIR/logs/build-$name.log" 2>&1 || return 1
    result=$(find_latest "$build_dir/${name}-*.pkg.tar.*")
    [ -n "$result" ] || return 1
    printf '%s\n' "$result"
}

resolve_packages() {
    if [ -z "$LIMINE_PKG" ]; then
        LIMINE_PKG=$(find_latest /var/cache/pacman/pkg/limine-[0-9]*.pkg.tar.*)
        [ -n "$LIMINE_PKG" ] || LIMINE_PKG=$(download_pkg limine || true)
    fi
    if [ -z "$LIMINE_TOOL_PKG" ]; then
        LIMINE_TOOL_PKG=$(find_latest \
            "$BUILDBOT_ROOT/CatOS/limine-tool/packaging/arch/limine-tool-*.pkg.tar.*" \
            /var/cache/pacman/pkg/limine-tool-*.pkg.tar.*)
        [ -n "$LIMINE_TOOL_PKG" ] || LIMINE_TOOL_PKG=$(download_pkg limine-tool || true)
    fi
    if [ -z "$SYSTEMD_BOOT_CONFIG_PKG" ]; then
        SYSTEMD_BOOT_CONFIG_PKG=$(find_latest \
            "$BUILDBOT_ROOT/CatOS-PKGBUILD/catos-systemd-boot-config/catos-systemd-boot-config-*.pkg.tar.*" \
            /var/cache/pacman/pkg/catos-systemd-boot-config-*.pkg.tar.*)
        [ -n "$SYSTEMD_BOOT_CONFIG_PKG" ] || \
            SYSTEMD_BOOT_CONFIG_PKG=$(download_pkg catos-systemd-boot-config || true)
        [ -n "$SYSTEMD_BOOT_CONFIG_PKG" ] || \
            SYSTEMD_BOOT_CONFIG_PKG=$(build_simple_pkg catos-systemd-boot-config \
                "$BUILDBOT_ROOT/CatOS-PKGBUILD/catos-systemd-boot-config" || true)
    fi
    if [ -z "$FIRMWARE_BOOT_PKG" ]; then
        FIRMWARE_BOOT_PKG=$(find_latest \
            "$BUILDBOT_ROOT/CatOS-PKGBUILD/catos-firmware-boot/catos-firmware-boot-*.pkg.tar.*" \
            /var/cache/pacman/pkg/catos-firmware-boot-*.pkg.tar.*)
        [ -n "$FIRMWARE_BOOT_PKG" ] || FIRMWARE_BOOT_PKG=$(download_pkg catos-firmware-boot || true)
        [ -n "$FIRMWARE_BOOT_PKG" ] || \
            FIRMWARE_BOOT_PKG=$(build_simple_pkg catos-firmware-boot \
                "$BUILDBOT_ROOT/CatOS-PKGBUILD/catos-firmware-boot" || true)
    fi
    [ -z "$LIMINE_PKG" ] || require_pkg_name "$LIMINE_PKG" limine
    [ -z "$LIMINE_TOOL_PKG" ] || require_pkg_name "$LIMINE_TOOL_PKG" limine-tool
    [ -z "$SYSTEMD_BOOT_CONFIG_PKG" ] || \
        require_pkg_name "$SYSTEMD_BOOT_CONFIG_PKG" catos-systemd-boot-config
    [ -z "$FIRMWARE_BOOT_PKG" ] || require_pkg_name "$FIRMWARE_BOOT_PKG" catos-firmware-boot
}
resolve_packages

ALL_SCENARIOS=(grub-bios grub-uefi limine systemd-boot uki efistub)
if [ -n "$SCENARIO" ]; then
    case "$SCENARIO" in
        grub-bios|grub-uefi|limine|systemd-boot|uki|efistub) SCENARIOS=("$SCENARIO") ;;
        failure-suite) SCENARIOS=() ;;
        *) fail "unknown scenario $SCENARIO" ;;
    esac
else
    SCENARIOS=("${ALL_SCENARIOS[@]}")
fi

scenario_available() {
    case "$1" in
        grub-bios) return 0 ;;
        grub-uefi) [ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_TEMPLATE" ] ;;
        limine)
            [ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_TEMPLATE" ] &&
            [ -n "$LIMINE_PKG" ] && [ -n "$LIMINE_TOOL_PKG" ]
            ;;
        systemd-boot)
            [ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_TEMPLATE" ] &&
            [ -n "$SYSTEMD_BOOT_CONFIG_PKG" ]
            ;;
        uki|efistub)
            [ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_TEMPLATE" ] &&
            [ -n "$FIRMWARE_BOOT_PKG" ]
            ;;
    esac
}

build_base_image() (
    set -e
    local firmware="$1"
    local image="$2"
    local mnt="$WORKDIR/base-$firmware-root"
    local loop=""
    cleanup_base() {
        set +e
        if [ -d "$mnt/etc/pacman.d/gnupg" ]; then
            gpgconf --homedir "$mnt/etc/pacman.d/gnupg" --kill gpg-agent 2>/dev/null || true
        fi
        mountpoint -q "$mnt/boot/efi" && umount -l "$mnt/boot/efi"
        mountpoint -q "$mnt" && umount -R "$mnt"
        [ -z "$loop" ] || losetup -d "$loop" 2>/dev/null || true
    }
    trap cleanup_base EXIT INT TERM
    rm -f "$image"
    mkdir -p "$mnt"
    truncate -s 6G "$image"
    if [ "$firmware" = uefi ]; then
        sgdisk --zap-all "$image" >/dev/null
        sgdisk -n 1:1MiB:+256MiB -t 1:ef00 -c 1:CATOS_ESP "$image" >/dev/null
        sgdisk -n 2:0:0 -t 2:8300 -c 2:CATOS_ROOT "$image" >/dev/null
    else
        sfdisk "$image" >/dev/null <<'PT'
label: dos
unit: sectors
start=2048, type=83, bootable
PT
    fi
    loop=$(losetup --find --show --partscan "$image")
    udevadm settle
    if [ "$firmware" = uefi ]; then
        rootdev=${loop}p2
        espdev=${loop}p1
        mkfs.vfat -F 32 -n CATOS_ESP "$espdev" >/dev/null
    else
        rootdev=${loop}p1
        espdev=""
    fi
    mkfs.ext4 -q -F -L CATOS_ROOT "$rootdev"
    mount "$rootdev" "$mnt"
    if [ -n "$espdev" ]; then
        mkdir -p "$mnt/boot/efi"
        mount "$espdev" "$mnt/boot/efi"
    fi

    set +e
    pacstrap -c "$mnt" base linux grub efibootmgr \
        >"$WORKDIR/logs/pacstrap-$firmware.log" 2>&1
    set -e
    [ -x "$mnt/usr/bin/grub-install" ] || fail "pacstrap did not install grub"
    [ -x "$mnt/usr/bin/mkinitcpio" ] || fail "pacstrap did not install mkinitcpio"
    [ -x "$mnt/usr/lib/systemd/systemd" ] || fail "pacstrap did not install systemd"

    root_uuid=$(blkid -s UUID -o value "$rootdev")
    cat >"$mnt/etc/fstab" <<FSTAB
UUID=$root_uuid / ext4 defaults,noatime 0 1
FSTAB
    if [ -n "$espdev" ]; then
        esp_uuid=$(blkid -s UUID -o value "$espdev")
        printf 'UUID=%s /boot/efi vfat defaults,umask=0077 0 2\n' "$esp_uuid" >>"$mnt/etc/fstab"
    fi
    cat >"$mnt/etc/os-release" <<'OS'
NAME=CatOS
ID=catos
PRETTY_NAME="CatOS QEMU Target"
OS
    tr -d '-' </proc/sys/kernel/random/uuid | head -c 32 >"$mnt/etc/machine-id"
    printf '\n' >>"$mnt/etc/machine-id"
    mkdir -p "$mnt/etc/kernel" "$mnt/etc/mkinitcpio.d" "$mnt/usr/local/sbin" \
        "$mnt/etc/systemd/system/multi-user.target.wants"
    cat >"$mnt/etc/kernel/cmdline" <<'CMDLINE'
console=ttyS0,115200n8 systemd.show_status=yes
CMDLINE
    python3 - "$mnt/etc/mkinitcpio.conf" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
text=path.read_text()
lines=[]
found=False
for line in text.splitlines():
    if line.lstrip().startswith('MODULES='):
        line='MODULES=(virtio_pci virtio_blk ext4 vfat)'
        found=True
    lines.append(line)
if not found:
    lines.append('MODULES=(virtio_pci virtio_blk ext4 vfat)')
path.write_text('\n'.join(lines)+'\n')
PY
    module_dir=""
    for candidate in "$mnt"/usr/lib/modules/*; do
        [ -f "$candidate/pkgbase" ] && [ -f "$candidate/vmlinuz" ] || continue
        module_dir="$candidate"
        break
    done
    [ -n "$module_dir" ] || fail "target kernel module tree is incomplete"
    pkgbase=$(tr -d '\n' <"$module_dir/pkgbase")
    cp "$module_dir/vmlinuz" "$mnt/boot/vmlinuz-$pkgbase"
    cat >"$mnt/etc/mkinitcpio.d/$pkgbase.preset" <<PRESET
ALL_kver="/boot/vmlinuz-$pkgbase"
PRESETS=('default')
default_image="/boot/initramfs-$pkgbase.img"
PRESET
    cat >"$mnt/usr/local/sbin/catos-qemu-marker" <<'MARKER'
#!/bin/sh
echo '===CATOS_BOOT_REPAIR_USERSPACE_MARKER===' > /dev/ttyS0
systemctl poweroff --force
MARKER
    chmod 755 "$mnt/usr/local/sbin/catos-qemu-marker"
    cat >"$mnt/etc/systemd/system/catos-qemu-marker.service" <<'UNIT'
[Unit]
Description=CatOS boot repair QEMU acceptance marker
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/catos-qemu-marker
[Install]
WantedBy=multi-user.target
UNIT
    ln -sf ../catos-qemu-marker.service \
        "$mnt/etc/systemd/system/multi-user.target.wants/catos-qemu-marker.service"
    sync
    cleanup_base
    trap - EXIT INT TERM
    chown "$ORIGINAL_UID:$ORIGINAL_GID" "$image"
)

prepare_scenario() (
    set -e
    local scenario="$1"
    local base="$2"
    local image="$3"
    local firmware="$4"
    local mnt="$WORKDIR/$scenario-root"
    local loop=""
    cp --reflink=auto --sparse=always "$base" "$image"
    cleanup_scenario_mounts() {
        set +e
        mountpoint -q "$mnt/boot/efi" && umount -l "$mnt/boot/efi"
        mountpoint -q "$mnt" && umount -R "$mnt"
        [ -z "$loop" ] || losetup -d "$loop" 2>/dev/null || true
    }
    trap cleanup_scenario_mounts EXIT INT TERM
    mkdir -p "$mnt"
    loop=$(losetup --find --show --partscan "$image")
    udevadm settle
    if [ "$firmware" = uefi ]; then
        mount ${loop}p2 "$mnt"
        mkdir -p "$mnt/boot/efi"
        mount ${loop}p1 "$mnt/boot/efi"
    else
        mount ${loop}p1 "$mnt"
    fi
    mkdir -p "$mnt/root/fixture-packages" "$mnt/run/calamares"
    cat >"$mnt/root/fixture-packages/pacman.conf" <<'PACMAN'
[options]
Architecture = auto
DBPath = /var/lib/pacman/
CacheDir = /var/cache/pacman/pkg/
LogFile = /var/log/pacman.log
GPGDir = /etc/pacman.d/gnupg/
HookDir = /etc/pacman.d/hooks/
SigLevel = Never
LocalFileSigLevel = Never
PACMAN
    case "$scenario" in
        limine)
            cp "$LIMINE_PKG" "$LIMINE_TOOL_PKG" "$mnt/root/fixture-packages/"
            touch "$mnt/run/calamares/bootloadu-installing"
            arch-chroot "$mnt" pacman -U --noconfirm --config /root/fixture-packages/pacman.conf \
                "/root/fixture-packages/$(basename "$LIMINE_PKG")" \
                "/root/fixture-packages/$(basename "$LIMINE_TOOL_PKG")" \
                >"$WORKDIR/logs/install-$scenario.log" 2>&1
            rm -f "$mnt/run/calamares/bootloadu-installing"
            ;;
        systemd-boot)
            cp "$SYSTEMD_BOOT_CONFIG_PKG" "$mnt/root/fixture-packages/"
            touch "$mnt/run/calamares/bootloadu-installing"
            arch-chroot "$mnt" pacman -U --noconfirm --config /root/fixture-packages/pacman.conf \
                "/root/fixture-packages/$(basename "$SYSTEMD_BOOT_CONFIG_PKG")" \
                >"$WORKDIR/logs/install-$scenario.log" 2>&1
            rm -f "$mnt/run/calamares/bootloadu-installing"
            ;;
        uki|efistub)
            arch-chroot "$mnt" pacman -S --noconfirm python \
                >"$WORKDIR/logs/install-$scenario.log" 2>&1
            if [ "$scenario" = uki ]; then
                arch-chroot "$mnt" pacman -S --noconfirm systemd-ukify \
                    >>"$WORKDIR/logs/install-$scenario.log" 2>&1
            fi
            cp "$FIRMWARE_BOOT_PKG" "$mnt/root/fixture-packages/"
            touch "$mnt/run/calamares/bootloadu-installing"
            arch-chroot "$mnt" pacman -U --noconfirm --config /root/fixture-packages/pacman.conf \
                "/root/fixture-packages/$(basename "$FIRMWARE_BOOT_PKG")" \
                >>"$WORKDIR/logs/install-$scenario.log" 2>&1
            rm -f "$mnt/run/calamares/bootloadu-installing"
            ;;
    esac

    python3 - "$mnt" "$scenario" <<'PY'
from pathlib import Path
import shutil, sys
root=Path(sys.argv[1]); scenario=sys.argv[2]
for relative in [
    'etc/default/grub.d/00-catos.cfg',
    'etc/default/grub.d/99-catos-qemu.cfg',
    'etc/default/limine',
    'etc/kernel/install.conf.d/20-catos-bootloadu.conf',
    'etc/catos/firmware-boot.conf',
]:
    path=root/relative
    if path.exists() or path.is_symlink(): path.unlink()
shutil.rmtree(root/'boot/grub', ignore_errors=True)
esp=root/'boot/efi'
if esp.is_dir():
    for child in list(esp.iterdir()):
        if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
        else: child.unlink()
(root/'etc/kernel').mkdir(parents=True, exist_ok=True)
(root/'etc/kernel/cmdline').write_text('console=ttyS0,115200n8 systemd.show_status=yes\n')
if scenario in ('grub-bios','grub-uefi','grub-uefi-failure','lock-conflict'):
    directory=root/'etc/default/grub.d'; directory.mkdir(parents=True, exist_ok=True)
    (directory/'00-catos.cfg').write_text('GRUB_DISTRIBUTOR=CatOS\nGRUB_TIMEOUT=1\nGRUB_TERMINAL_OUTPUT=console\n')
    (directory/'99-catos-qemu.cfg').write_text('GRUB_TIMEOUT=1\nGRUB_TERMINAL=console\n')
elif scenario == 'limine':
    path=root/'etc/default/limine'; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('TARGET_OS_NAME="CatOS"\nESP_PATH="/boot/efi"\nKERNEL_CMDLINE[default]=console=ttyS0,115200n8 systemd.show_status=yes\nENABLE_UKI=no\nENABLE_LIMINE_FALLBACK=yes\n')
elif scenario == 'systemd-boot':
    path=root/'etc/kernel/install.conf.d/20-catos-bootloadu.conf'; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('BOOT_ROOT=/boot/efi\nlayout=bls\n')
elif scenario in ('uki','efistub'):
    path=root/'etc/catos/firmware-boot.conf'; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('[boot]\nmethod = '+scenario+'\nesp_path = /boot/efi\nefi_disk = /dev/vda\nefi_partition = 1\nlabel_prefix = CatOS\ndefault_kernel = linux\n')
PY
    if [ "$scenario" = grub-uefi-failure ]; then
        mv "$mnt/usr/bin/grub-mkconfig" "$mnt/usr/bin/grub-mkconfig.catos-real"
        cat >"$mnt/usr/bin/grub-mkconfig" <<'FAILCMD'
#!/bin/sh
echo 'synthetic target grub-mkconfig failure' >&2
exit 42
FAILCMD
        chmod 755 "$mnt/usr/bin/grub-mkconfig"
    fi
    sync
    cleanup_scenario_mounts
    trap - EXIT INT TERM
    chown "$ORIGINAL_UID:$ORIGINAL_GID" "$image"
)

copy_dynamic() {
    local source="$1" destination="$RESCUE_ROOT$1"
    mkdir -p "$(dirname "$destination")"
    cp -L "$source" "$destination"
    ldd "$source" 2>/dev/null | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}' | while read -r library; do
        [ -f "$library" ] || continue
        mkdir -p "$RESCUE_ROOT$(dirname "$library")"
        cp -L "$library" "$RESCUE_ROOT$library"
    done
}

copy_module_tree() {
    local module="$1"
    modprobe --show-depends -S "$KVER" "$module" 2>/dev/null | awk '$1 == "insmod" {print $2}' | while read -r source; do
        [ -f "$source" ] || continue
        relative=${source#*/lib/modules/$KVER/}
        destination="$RESCUE_ROOT/lib/modules/$KVER/$relative"
        mkdir -p "$(dirname "$destination")"
        case "$source" in
            *.zst) zstd -q -d -c "$source" >"${destination%.zst}" ;;
            *.xz) xz -d -c "$source" >"${destination%.xz}" ;;
            *) cp "$source" "$destination" ;;
        esac
    done
}

build_rescue() {
    rm -rf "$RESCUE_ROOT"
    mkdir -p "$RESCUE_ROOT"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,run,etc,"lib/modules/$KVER"}
    cp "$BUSYBOX" "$RESCUE_ROOT/bin/busybox"
    cp "$BIN" "$RESCUE_ROOT/bin/catos-system"
    chmod 755 "$RESCUE_ROOT/bin/"*
    ln -sf /bin/catos-system "$RESCUE_ROOT/bin/catos-repair"
    for applet in sh mount umount modprobe poweroff sleep cat echo mkdir ln find grep awk sed cut chroot blkid flock kill; do
        ln -sf /bin/busybox "$RESCUE_ROOT/bin/$applet"
    done
    ln -sf /bin/busybox "$RESCUE_ROOT/usr/bin/chroot"
    copy_dynamic /usr/bin/blkid
    for module in virtio_pci virtio_blk ext4 vfat efivarfs; do copy_module_tree "$module"; done
    depmod -b "$RESCUE_ROOT" "$KVER"
    cat >"$RESCUE_ROOT/etc/initrd-release" <<'REL'
NAME=CatOS boot repair acceptance
ID=catos-boot-repair
REL
    cat >"$RESCUE_ROOT/init" <<'INIT'
#!/bin/sh
PATH=/usr/bin:/usr/sbin:/bin:/sbin
export PATH
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
ln -sf /proc/self/fd /dev/fd
ln -sf /proc/self/fd/0 /dev/stdin
ln -sf /proc/self/fd/1 /dev/stdout
ln -sf /proc/self/fd/2 /dev/stderr
mkdir -p /run /sys/firmware/efi/efivars
modprobe virtio_pci 2>/dev/null || true
modprobe virtio_blk 2>/dev/null || true
modprobe ext4 2>/dev/null || true
modprobe vfat 2>/dev/null || true
modprobe efivarfs 2>/dev/null || true
if [ -d /sys/firmware/efi ]; then
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda1 ] && break
    sleep 1
done
scenario=$(sed -n 's/.*catos_scenario=\([^ ]*\).*/\1/p' /proc/cmdline)
case "$scenario" in
    grub-bios) root=/dev/vda1; esp="" ;;
    *) root=/dev/vda2; esp=/dev/vda1 ;;
esac
if [ "$scenario" = lock-conflict ]; then
    flock -x "$root" sleep 60 &
    lock_pid=$!
    sleep 1
fi
echo '===BOOT_REPAIR_BEGIN==='
if [ -n "$esp" ]; then
    /bin/catos-repair boot --root-device "$root" --esp-device "$esp" --json
else
    /bin/catos-repair boot --root-device "$root" --json
fi
rc=$?
echo "===BOOT_REPAIR_END=== rc=$rc"
if [ -n "${lock_pid:-}" ]; then kill "$lock_pid" 2>/dev/null || true; fi
if find /run/catos-system/sessions -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo '===BOOT_REPAIR_RESIDUAL_SESSION==='
fi
sync
poweroff -f
INIT
    chmod 755 "$RESCUE_ROOT/init"
    (cd "$RESCUE_ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null) | gzip -9 >"$RESCUE_IMAGE"
}

ACCEL=()
if [ -r /dev/kvm ] && [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    ACCEL=(-enable-kvm -cpu host)
fi

expected_provider() {
    case "$1" in grub-bios|grub-uefi) echo grub ;; *) echo "$1" ;; esac
}

assert_repair_report() {
    local scenario="$1" log="$2"
    python3 - "$scenario" "$log" <<'PY'
import json, sys
scenario, path = sys.argv[1:]
text=open(path, errors='replace').read().replace('\r','')
if '===BOOT_REPAIR_RESIDUAL_SESSION===' in text:
    raise SystemExit('repair left a residual session mount')
try:
    chunk=text.split('===BOOT_REPAIR_BEGIN===',1)[1].split('===BOOT_REPAIR_END===',1)[0]
except IndexError:
    raise SystemExit('repair markers are missing')
start=chunk.find('{')
report=json.JSONDecoder().raw_decode(chunk[start:])[0]
payload=report['payload']
provider='grub' if scenario.startswith('grub-') else scenario
if payload.get('detected_provider') != provider:
    raise SystemExit(f'provider mismatch: {payload.get("detected_provider")} != {provider}')
if payload.get('final_outcome') != 'repaired':
    raise SystemExit(f'repair outcome is {payload.get("final_outcome")}: {payload}')
if payload.get('fully_complete') is not True:
    raise SystemExit('repair is not fully complete')
if payload.get('verification',{}).get('passed') is not True:
    raise SystemExit(f'verification failed: {payload.get("verification")}')
if payload.get('cleanup',{}).get('all_clean') is not True:
    raise SystemExit(f'cleanup failed: {payload.get("cleanup")}')
commands=[a.get('result',{}).get('command',{}).get('binary') for a in payload.get('actions',[]) if a.get('kind')=='target_command']
required={
    'grub-bios': {'mkinitcpio','grub-install','grub-mkconfig'},
    'grub-uefi': {'mkinitcpio','grub-install','grub-mkconfig'},
    'limine': {'limine-install','limine-update','limine-list'},
    'systemd-boot': {'bootctl','kernel-install'},
    'uki': {'catos-firmware-boot-update'},
    'efistub': {'catos-firmware-boot-update'},
}[scenario]
missing=required-set(commands)
if missing:
    raise SystemExit(f'missing target commands: {sorted(missing)}; commands={commands}')
print(f'pass: {scenario} repair report')
PY
}

assert_failure_report() {
    local log="$1"
    python3 - "$log" <<'PY'
import json, sys
text=open(sys.argv[1], errors='replace').read().replace('\r','')
if '===BOOT_REPAIR_RESIDUAL_SESSION===' in text:
    raise SystemExit('provider failure left a residual mount')
chunk=text.split('===BOOT_REPAIR_BEGIN===',1)[1].split('===BOOT_REPAIR_END===',1)[0]
report=json.JSONDecoder().raw_decode(chunk[chunk.find('{'):])[0]['payload']
if report.get('detected_provider') != 'grub':
    raise SystemExit(f'wrong provider in failure scenario: {report.get("detected_provider")}')
if report.get('final_outcome') in ('clean','repaired') or report.get('fully_complete') is True:
    raise SystemExit(f'provider failure was reported as success: {report}')
if report.get('cleanup',{}).get('all_clean') is not True:
    raise SystemExit(f'provider failure cleanup is incomplete: {report.get("cleanup")}')
results=[a.get('result',{}) for a in report.get('actions',[]) if a.get('kind')=='target_command']
failed=[r for r in results if r.get('command',{}).get('binary')=='grub-mkconfig' and r.get('exit_code')==42]
if not failed:
    raise SystemExit(f'synthetic target failure was not audited: {results}')
print('pass: target provider failure was reported and cleaned up')
PY
}

assert_lock_report() {
    local log="$1"
    python3 - "$log" <<'PY'
import json, sys
text=open(sys.argv[1], errors='replace').read().replace('\r','')
if '===BOOT_REPAIR_RESIDUAL_SESSION===' in text:
    raise SystemExit('lock contention left a residual mount')
chunk=text.split('===BOOT_REPAIR_BEGIN===',1)[1].split('===BOOT_REPAIR_END===',1)[0]
report=json.JSONDecoder().raw_decode(chunk[chunk.find('{'):])[0]['payload']
if report.get('final_outcome') != 'ambiguous_target':
    raise SystemExit(f'lock contention outcome mismatch: {report.get("final_outcome")}')
if report.get('actions'):
    raise SystemExit(f'lock contention executed mutations: {report.get("actions")}')
if report.get('fully_complete') is True:
    raise SystemExit('lock contention was reported as complete')
print('pass: shared device lock rejected boot repair before mutation')
PY
}

root_file_hash() (
    set -e
    local image="$1"
    local rooted="$2"
    local loop=""
    local mnt="$WORKDIR/hash-root"
    cleanup_hash_mount() {
        set +e
        mountpoint -q "$mnt" && umount -R "$mnt"
        [ -z "$loop" ] || losetup -d "$loop" 2>/dev/null || true
    }
    trap cleanup_hash_mount EXIT INT TERM
    mkdir -p "$mnt"
    loop=$(losetup --find --show --partscan "$image")
    udevadm settle
    mount ${loop}p2 "$mnt"
    sha256sum "$mnt/${rooted#/}" | awk '{print $1}'
    cleanup_hash_mount
    trap - EXIT INT TERM
)

run_qemu_repair() {
    local scenario="$1" image="$2" log="$3" vars="$4"
    if [ "$scenario" = grub-bios ]; then
        timeout 300 "$QEMU_BIN" -M pc -m 2048 -nographic -no-reboot "${ACCEL[@]}" \
            -kernel "$KERNEL" -initrd "$RESCUE_IMAGE" \
            -append "console=ttyS0 panic=1 rdinit=/init catos_scenario=$scenario" \
            -drive if=none,id=disk,file="$image",format=raw,cache=none \
            -device virtio-blk-pci,drive=disk < /dev/null >"$log" 2>&1
    else
        cp "$OVMF_VARS_TEMPLATE" "$vars"
        timeout 300 "$QEMU_BIN" -M q35 -m 2048 -nographic -no-reboot "${ACCEL[@]}" \
            -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
            -drive if=pflash,format=raw,file="$vars" \
            -kernel "$KERNEL" -initrd "$RESCUE_IMAGE" \
            -append "console=ttyS0 panic=1 rdinit=/init catos_scenario=$scenario" \
            -drive if=none,id=disk,file="$image",format=raw,cache=none \
            -device virtio-blk-pci,drive=disk < /dev/null >"$log" 2>&1
    fi
}

run_qemu_boot() {
    local scenario="$1" image="$2" log="$3" vars="$4"
    if [ "$scenario" = grub-bios ]; then
        timeout 240 "$QEMU_BIN" -M pc -m 2048 -nographic -no-reboot "${ACCEL[@]}" \
            -drive if=none,id=disk,file="$image",format=raw,cache=none \
            -device virtio-blk-pci,drive=disk < /dev/null >"$log" 2>&1
    else
        timeout 240 "$QEMU_BIN" -M q35 -m 2048 -nographic -no-reboot "${ACCEL[@]}" \
            -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
            -drive if=pflash,format=raw,file="$vars" \
            -drive if=none,id=disk,file="$image",format=raw,cache=none \
            -device virtio-blk-pci,drive=disk < /dev/null >"$log" 2>&1
    fi
    grep -q '===CATOS_BOOT_REPAIR_USERSPACE_MARKER===' "$log" || {
        tail -300 "$log" >&2
        fail "$scenario did not reach the target userspace marker"
    }
}

build_rescue
need_uefi=0
need_bios=0
if [ "$SCENARIO" = failure-suite ]; then need_uefi=1; fi
for scenario in "${SCENARIOS[@]}"; do
    if [ "$scenario" = grub-bios ]; then need_bios=1; else need_uefi=1; fi
done
[ "$need_uefi" -eq 0 ] || {
    [ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_TEMPLATE" ] || skip "OVMF firmware is unavailable"
    build_base_image uefi "$UEFI_BASE"
}
[ "$need_bios" -eq 0 ] || build_base_image bios "$BIOS_BASE"

PASSED=()
SKIPPED=()
for scenario in "${SCENARIOS[@]}"; do
    if ! scenario_available "$scenario"; then
        echo "skip: $scenario is missing its CatOS provider package or OVMF" >&2
        SKIPPED+=("$scenario")
        continue
    fi
    if [ "$scenario" = grub-bios ]; then firmware=bios; base="$BIOS_BASE"; else firmware=uefi; base="$UEFI_BASE"; fi
    image="$WORKDIR/$scenario.img"
    repair_log="$WORKDIR/logs/$scenario-repair.log"
    boot_log="$WORKDIR/logs/$scenario-boot.log"
    vars="$WORKDIR/$scenario-vars.fd"
    prepare_scenario "$scenario" "$base" "$image" "$firmware"
    run_qemu_repair "$scenario" "$image" "$repair_log" "$vars"
    assert_repair_report "$scenario" "$repair_log"
    run_qemu_boot "$scenario" "$image" "$boot_log" "$vars"
    echo "pass: $scenario repair -> verification -> reboot -> userspace"
    PASSED+=("$scenario")
    if [ "$KEEP" -eq 0 ]; then rm -f "$image" "$vars"; fi
done

FAILURE_SUITE_PASSED=0
if [ -z "$SCENARIO" ] || [ "$SCENARIO" = failure-suite ]; then
    echo 'info: running provider failure + rollback acceptance'
    failure_image="$WORKDIR/grub-uefi-failure.img"
    failure_vars="$WORKDIR/grub-uefi-failure-vars.fd"
    failure_log="$WORKDIR/logs/grub-uefi-failure-repair.log"
    prepare_scenario grub-uefi-failure "$UEFI_BASE" "$failure_image" uefi
    config_before=$(root_file_hash "$failure_image" /etc/default/grub.d/00-catos.cfg)
    run_qemu_repair grub-uefi-failure "$failure_image" "$failure_log" "$failure_vars"
    assert_failure_report "$failure_log"
    config_after=$(root_file_hash "$failure_image" /etc/default/grub.d/00-catos.cfg)
    [ "$config_before" = "$config_after" ] || fail 'provider failure did not roll back GRUB configuration'
    echo 'pass: provider failure restored the original target configuration'

    echo 'info: running shared device lock contention acceptance'
    lock_image="$WORKDIR/lock-conflict.img"
    lock_vars="$WORKDIR/lock-conflict-vars.fd"
    lock_log="$WORKDIR/logs/lock-conflict-repair.log"
    prepare_scenario lock-conflict "$UEFI_BASE" "$lock_image" uefi
    lock_hash_before=$(sha256sum "$lock_image" | awk '{print $1}')
    run_qemu_repair lock-conflict "$lock_image" "$lock_log" "$lock_vars"
    assert_lock_report "$lock_log"
    lock_hash_after=$(sha256sum "$lock_image" | awk '{print $1}')
    [ "$lock_hash_before" = "$lock_hash_after" ] || fail 'lock contention changed the target image'
    echo 'pass: lock contention left the target image byte-identical'
    FAILURE_SUITE_PASSED=1
fi

printf '\nboot-repair QEMU summary:\n'
printf '  passed:  %s\n' "${PASSED[*]:-(none)}"
printf '  skipped: %s\n' "${SKIPPED[*]:-(none)}"
[ "${#PASSED[@]}" -gt 0 ] || [ "$FAILURE_SUITE_PASSED" -eq 1 ] || exit 77
