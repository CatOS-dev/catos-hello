#!/usr/bin/env bash
# Real-QEMU acceptance for the /bin/catos-chroot multicall entry.
# The host never mounts the fixture. mkfs.btrfs builds the target image and
# the guest kernel performs discovery, mount assembly, verification, chroot,
# reverse cleanup, and session-root removal.

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
for tool in cpio gzip timeout mkfs.btrfs btrfs sha256sum modprobe zstd xz ldd blkid; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
    echo "skip: chroot QEMU acceptance missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi
if [[ -x $SCRIPT_DIR/verify-static.sh ]]; then
    "$SCRIPT_DIR/verify-static.sh" "$BIN" >/dev/null || {
        echo "fail: catos-system is not fully static" >&2
        exit 1
    }
    "$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null || {
        echo "fail: busybox is not fully static" >&2
        exit 1
    }
fi

WORKDIR=${WORKDIR:-$(mktemp -d -t catos-chroot-qemu-XXXXXX)}
INITRAMFS=$WORKDIR/initramfs
INITRAMFS_IMG=$WORKDIR/initramfs.cpio.gz
BASE_IMAGE=$WORKDIR/base.img
KEEP_ON_FAILURE=0
cleanup() {
    if ((KEEP || KEEP_ON_FAILURE)); then
        echo "info: keeping workdir $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT
fail() { echo "fail: $*" >&2; KEEP_ON_FAILURE=1; exit 1; }
assert_contains() {
    local body=$1 needle=$2 context=$3
    grep -Fq -- "$needle" <<<"$body" || fail "$context: missing '$needle'"
}
assert_not_contains() {
    local body=$1 needle=$2 context=$3
    if grep -Fq -- "$needle" <<<"$body"; then
        fail "$context: unexpectedly contains '$needle'"
    fi
}

ROOT_UUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
TREE=$WORKDIR/tree
mkdir -p \
    "$TREE/@/etc" "$TREE/@/usr/bin" "$TREE/@/usr/lib" "$TREE/@/home" "$TREE/@/root" \
    "$TREE/@/srv" "$TREE/@/var/cache" "$TREE/@/var/tmp" \
    "$TREE/@/var/log" "$TREE/@/.snapshots" "$TREE/@/proc" \
    "$TREE/@/sys" "$TREE/@/dev/pts" "$TREE/@/dev/shm" "$TREE/@/run" "$TREE/@/tmp" \
    "$TREE/@home" "$TREE/@root" "$TREE/@srv" "$TREE/@cache" \
    "$TREE/@tmp" "$TREE/@log" "$TREE/@snapshots" \
    "$TREE/@snapshots/1/snapshot/etc" "$TREE/@snapshots/1/snapshot/usr/lib"
cat > "$TREE/@/usr/lib/os-release" <<'OS_RELEASE'
NAME="CatOS"
ID=catos
PRETTY_NAME="CatOS Chroot QEMU Fixture"
OS_RELEASE
ln -s ../usr/lib/os-release "$TREE/@/etc/os-release"
cat > "$TREE/@/etc/fstab" <<FSTAB
UUID=$ROOT_UUID / btrfs defaults,subvol=/@ 0 0
UUID=$ROOT_UUID /home btrfs defaults,subvol=/@home 0 0
UUID=$ROOT_UUID /root btrfs defaults,subvol=/@root 0 0
UUID=$ROOT_UUID /srv btrfs defaults,subvol=/@srv 0 0
UUID=$ROOT_UUID /var/cache btrfs defaults,subvol=/@cache 0 0
UUID=$ROOT_UUID /var/tmp btrfs defaults,subvol=/@tmp 0 0
UUID=$ROOT_UUID /var/log btrfs defaults,subvol=/@log 0 0
UUID=$ROOT_UUID /.snapshots btrfs defaults,subvol=/@snapshots 0 0
FSTAB
printf 'home-subvolume\n' > "$TREE/@home/.catos-home-marker"
printf 'root-subvolume\n' > "$TREE/@root/.catos-root-marker"
printf 'srv-subvolume\n' > "$TREE/@srv/.catos-srv-marker"
printf 'cache-subvolume\n' > "$TREE/@cache/.catos-cache-marker"
printf 'tmp-subvolume\n' > "$TREE/@tmp/.catos-tmp-marker"
printf 'log-subvolume\n' > "$TREE/@log/.catos-log-marker"
printf 'snapshots-subvolume\n' > "$TREE/@snapshots/.catos-snapshots-marker"
cat > "$TREE/@snapshots/1/snapshot/usr/lib/os-release" <<'OS_RELEASE'
NAME="CatOS"
ID=catos
PRETTY_NAME="CatOS Historical Snapshot"
OS_RELEASE
ln -s ../usr/lib/os-release "$TREE/@snapshots/1/snapshot/etc/os-release"
cat > "$TREE/@snapshots/1/snapshot/etc/fstab" <<FSTAB
UUID=$ROOT_UUID / btrfs defaults,subvol=/@snapshots/1/snapshot 0 0
FSTAB
cp "$BUSYBOX" "$TREE/@/usr/bin/busybox"
chmod +x "$TREE/@/usr/bin/busybox"
ln -s usr/bin "$TREE/@/bin"
for applet in sh cat grep test readlink; do
    ln -sf busybox "$TREE/@/usr/bin/$applet"
done
cat > "$TREE/@/usr/bin/chroot-acceptance" <<'TARGET'
#!/bin/sh
set -eu
[ "$(cat /home/.catos-home-marker)" = home-subvolume ]
[ "$(cat /root/.catos-root-marker)" = root-subvolume ]
[ "$(cat /srv/.catos-srv-marker)" = srv-subvolume ]
[ "$(cat /var/cache/.catos-cache-marker)" = cache-subvolume ]
[ "$(cat /var/tmp/.catos-tmp-marker)" = tmp-subvolume ]
[ "$(cat /var/log/.catos-log-marker)" = log-subvolume ]
[ "$(cat /.snapshots/.catos-snapshots-marker)" = snapshots-subvolume ]
[ -r /proc/self/mountinfo ]
[ -d /sys/class ]
[ -d /dev ]
[ -d /run ]
echo __CHROOT_TARGET_VERIFIED__
TARGET
chmod +x "$TREE/@/usr/bin/chroot-acceptance"
cat > "$TREE/@/usr/bin/bash" <<'TARGET_BASH'
#!/usr/bin/sh
set -eu
echo "__ARCH_CHROOT_BASH_ARGC__=$#"
echo "__ARCH_CHROOT_BASH_ARG1__=${1-}"
[ "$#" -eq 1 ]
[ "$1" = -i ]
exec /usr/bin/chroot-acceptance
TARGET_BASH
chmod +x "$TREE/@/usr/bin/bash"

truncate -s 384M "$BASE_IMAGE"
mkfs.btrfs -q -f -U "$ROOT_UUID" -L catos-chroot -r "$TREE" \
    --subvol default:@ \
    --subvol rw:@home \
    --subvol rw:@root \
    --subvol rw:@srv \
    --subvol rw:@cache \
    --subvol rw:@tmp \
    --subvol rw:@log \
    --subvol rw:@snapshots \
    --subvol ro:@snapshots/1/snapshot \
    "$BASE_IMAGE" >/dev/null
rm -rf "$TREE"

rm -rf "$INITRAMFS"
mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,run,tmp,etc,usr/bin,usr/sbin,lib/modules/load}
cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
cp "$BIN" "$INITRAMFS/bin/catos-system"
chmod +x "$INITRAMFS/bin/busybox" "$INITRAMFS/bin/catos-system"
ln -s catos-system "$INITRAMFS/bin/catos-chroot"
for applet in sh cat echo printf sleep poweroff mkdir grep awk \
              find sync sed head tr insmod script timeout chmod ln readlink rm touch; do
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
for tool in btrfs blkid bash mount umount chroot unshare mountpoint arch-chroot; do
    copy_tool_with_deps "$tool"
done
ln -sf /usr/bin/bash "$INITRAMFS/bin/bash"

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
KVER=$(basename "$(dirname "$KERNEL")")
if [[ $KVER == modules || ! -d /usr/lib/modules/$KVER ]]; then KVER=$(uname -r); fi
while read -r action module_path _; do
    [[ $action == insmod ]] || continue
    copy_module "$module_path"
done < <(modprobe --show-depends -S "$KVER" btrfs 2>/dev/null || true)

cat > "$INITRAMFS/bin/chroot-child" <<'CHILD'
#!/bin/sh
scenario=$1
case "$scenario" in
    default|cancel) /bin/catos-chroot --no-systemd-chroot ;;
    show_snapshots|show_snapshots_cancel) /bin/catos-chroot --no-systemd-chroot --show-btrfs-dot-snapshots ;;
    *) echo "unknown scenario $scenario" >&2; exit 2 ;;
esac
echo $? > /tmp/chroot.rc
CHILD
chmod +x "$INITRAMFS/bin/chroot-child"

cat > "$INITRAMFS/init" <<'GUEST'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /tmp
mount -t devpts devpts /dev/pts
mount -t tmpfs -o mode=0755 tmpfs /run
chmod 1777 /tmp
while read -r module; do
    [ -n "$module" ] && insmod "$module" 2>/dev/null || true
done < /etc/modules.load
i=0
while [ ! -b /dev/vda ] && [ "$i" -lt 100 ]; do
    sleep 0.05
    i=$((i + 1))
done
scenario=default
for arg in $(cat /proc/cmdline); do
    case "$arg" in catos_chroot_scenario=*) scenario=${arg#catos_chroot_scenario=} ;; esac
done
case "$scenario" in
    default) input='y\nn\n' ;;
    show_snapshots) input='1\nn\n' ;;
    cancel) input='n\n' ;;
    show_snapshots_cancel) input='0\n' ;;
    *) input='' ;;
esac
rm -f /tmp/chroot.rc /tmp/chroot.out /tmp/chroot.err /tmp/typescript
printf '%b' "$input" | timeout -s KILL 45 script -q \
    -c "/bin/chroot-child $scenario" /tmp/typescript \
    > /tmp/chroot.out 2> /tmp/chroot.err
echo __CHROOT_BEGIN__
cat /tmp/chroot.out
echo __CHROOT_STDERR__
cat /tmp/chroot.err
rc=$(cat /tmp/chroot.rc 2>/dev/null || echo 255)
echo "__CHROOT_RC__=$rc"
if grep -Fq '/run/catos-system/sessions/' /proc/self/mountinfo; then
    echo __RESIDUAL_CHROOT_MOUNT__
    grep -F '/run/catos-system/sessions/' /proc/self/mountinfo
else
    echo __NO_RESIDUAL_CHROOT_MOUNTS__
fi
if [ -d /run/catos-system/sessions ] \
    && find /run/catos-system/sessions -mindepth 1 -maxdepth 1 | grep -q .; then
    echo __RESIDUAL_CHROOT_SESSION__
    find /run/catos-system/sessions -mindepth 1 -maxdepth 2
else
    echo __NO_RESIDUAL_CHROOT_SESSIONS__
fi
echo __CHROOT_END__
sync
poweroff -f
GUEST
chmod +x "$INITRAMFS/init"
(
    cd "$INITRAMFS"
    find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -q -1 > "$INITRAMFS_IMG"
)

LAST_LOG=""
run_qemu() {
    local scenario=$1
    local image=$WORKDIR/$scenario.img
    local log=$WORKDIR/$scenario.serial.log
    cp --reflink=auto "$BASE_IMAGE" "$image"
    local args=(
        -nodefaults -no-reboot -nographic -m 512M
        -kernel "$KERNEL" -initrd "$INITRAMFS_IMG"
        -append "console=ttyS0 quiet panic=-1 catos_chroot_scenario=$scenario"
        -drive "file=$image,format=raw,if=virtio"
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
    assert_contains "$LAST_LOG" "__CHROOT_END__" "$scenario"
    assert_contains "$LAST_LOG" "__CHROOT_RC__=0" "$scenario"
    case "$scenario" in
        cancel|show_snapshots_cancel)
            assert_not_contains "$LAST_LOG" "__CHROOT_TARGET_VERIFIED__" "$scenario"
            assert_not_contains "$LAST_LOG" "__ARCH_CHROOT_BASH_ARGC__" "$scenario"
            ;;
        *)
            assert_contains "$LAST_LOG" "__CHROOT_TARGET_VERIFIED__" "$scenario"
            assert_contains "$LAST_LOG" "__ARCH_CHROOT_BASH_ARGC__=1" "$scenario"
            assert_contains "$LAST_LOG" "__ARCH_CHROOT_BASH_ARG1__=-i" "$scenario"
            ;;
    esac
    assert_contains "$LAST_LOG" "__NO_RESIDUAL_CHROOT_MOUNTS__" "$scenario"
    assert_contains "$LAST_LOG" "__NO_RESIDUAL_CHROOT_SESSIONS__" "$scenario"
    assert_not_contains "$LAST_LOG" "__RESIDUAL_CHROOT_MOUNT__" "$scenario"
    assert_not_contains "$LAST_LOG" "__RESIDUAL_CHROOT_SESSION__" "$scenario"
    btrfs check --readonly "$image" > "$WORKDIR/$scenario.btrfs-check.log" 2>&1 \
        || fail "$scenario: target image failed post-chroot btrfs check"
}

echo "=== scenario: default-hidden-snapshots ==="
run_qemu default
assert_contains "$LAST_LOG" "Selected target: CatOS Chroot QEMU Fixture" default
assert_not_contains "$LAST_LOG" "Available CatOS targets:" default
assert_not_contains "$LAST_LOG" "CatOS Historical Snapshot" default

echo "=== scenario: explicit-show-snapshots ==="
run_qemu show_snapshots
assert_contains "$LAST_LOG" "Available CatOS targets:" show_snapshots
assert_contains "$LAST_LOG" "CatOS Historical Snapshot" show_snapshots
assert_contains "$LAST_LOG" "subvol=/@snapshots/1/snapshot" show_snapshots
assert_contains "$LAST_LOG" "Selected target: CatOS Chroot QEMU Fixture" show_snapshots

echo "=== scenario: decline-single-target ==="
run_qemu cancel
assert_contains "$LAST_LOG" "Use this target? [y/N]" cancel

echo "=== scenario: back-from-multiple-targets ==="
run_qemu show_snapshots_cancel
assert_contains "$LAST_LOG" "  [0] Back" show_snapshots_cancel

echo "pass: Chroot QEMU acceptance exercised /bin/catos-chroot, the host arch-chroot implementation, its /bin/bash -i default entrypoint, target selection, snapshot visibility, same-filesystem Btrfs subvolume assembly, mount verification, reverse cleanup and session removal"
