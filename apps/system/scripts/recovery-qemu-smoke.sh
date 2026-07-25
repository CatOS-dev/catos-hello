#!/usr/bin/env bash
# Authoritative phase-3 recovery acceptance on a real Btrfs image in QEMU.
# Exit 77 is reserved for missing host prerequisites. Once QEMU starts,
# every missing marker, skipped assertion, unexpected exit code, or
# unverifiable filesystem state is a hard failure.

set -u

usage() {
    cat >&2 <<EOF
usage: $0 [options]

options:
  --kernel PATH       Kernel image (default: auto-detect)
  --busybox PATH      Static busybox (default: PATH)
  --bin PATH          Production static catos-system musl binary
  --test-bin PATH     Static binary with recovery_fault_injection
  --qemu PATH         qemu-system-x86_64 (default: PATH)
  --workdir DIR       Work directory (default: temporary)
  --keep              Preserve work directory
  --skip-crash        Skip the three crash-window matrices
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
        "$SCRIPT_DIR/../../target-fault/x86_64-unknown-linux-musl/release/catos-system" \
        "$SCRIPT_DIR/../../build/apps/system/cargo-target-fault/x86_64-unknown-linux-musl/release/catos-system"; do
        if [ -x "$candidate" ]; then TEST_BIN="$candidate"; break; fi
    done
fi
[ -n "$QEMU_BIN" ] || QEMU_BIN=$(command -v qemu-system-x86_64 2>/dev/null || true)
[ -n "$BUSYBOX" ] || BUSYBOX=$(command -v busybox 2>/dev/null || true)
if [ -z "$KERNEL" ]; then
    for candidate in "/usr/lib/modules/$(uname -r)/vmlinuz" /usr/lib/modules/*/vmlinuz /boot/vmlinuz-*; do
        if [ -f "$candidate" ]; then KERNEL="$candidate"; break; fi
    done
fi

missing=()
[ -x "$BIN" ] || missing+=("production catos-system musl binary")
[ -x "$TEST_BIN" ] || missing+=("fault-injection catos-system musl binary")
[ -x "$QEMU_BIN" ] || missing+=("qemu-system-x86_64")
[ -x "$BUSYBOX" ] || missing+=("static busybox")
[ -f "$KERNEL" ] || missing+=("kernel image")
for tool in cpio gzip timeout mkfs.btrfs mkfs.vfat mmd mcopy sha256sum python3 ldd readelf awk sed grep head find; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "skip: missing recovery QEMU prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 77
fi
if ! "$SCRIPT_DIR/verify-static.sh" "$BUSYBOX" >/dev/null; then
    echo "skip: busybox is not static: $BUSYBOX" >&2
    exit 77
fi
for binary in "$BIN" "$TEST_BIN"; do
    if ! "$SCRIPT_DIR/verify-static.sh" "$binary" >/dev/null; then
        echo "fail: QEMU binary is not fully static: $binary" >&2
        exit 1
    fi
done

WORKDIR="${WORKDIR:-$(mktemp -d -t catos-recovery-qemu-XXXXXX)}"
INITRAMFS="$WORKDIR/initramfs"
INITRAMFS_PLAN="$WORKDIR/initramfs-plan.cpio.gz"
INITRAMFS_RUN="$WORKDIR/initramfs-run.cpio.gz"
PLAN_FILE="$WORKDIR/plan.json"
BTRFS_IMG="$WORKDIR/btrfs.img"
ESP_IMG="$WORKDIR/esp.img"
TREE="$WORKDIR/tree"
LAST_LOG=""
RUN_INDEX=0
KVER=$(basename "$(dirname "$KERNEL")")
if [ "$KVER" = modules ] || [ ! -d "/usr/lib/modules/$KVER" ]; then
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

fail() {
    echo "fail: $*" >&2
    KEEP=1
    if [ -n "$LAST_LOG" ] && [ -f "$LAST_LOG" ]; then
        echo "--- serial log: $LAST_LOG ---" >&2
        cat "$LAST_LOG" >&2
    fi
    exit 1
}

prepare_initramfs() {
    rm -rf "$INITRAMFS"
    mkdir -p "$INITRAMFS"/{bin,sbin,proc,sys,dev,etc,run,tmp,mnt,usr/bin,usr/sbin}
    cp "$BUSYBOX" "$INITRAMFS/bin/busybox"
    cp "$BIN" "$INITRAMFS/bin/catos-system"
    cp "$TEST_BIN" "$INITRAMFS/bin/catos-system-test"
    chmod +x "$INITRAMFS/bin/"*
    for applet in sh mount umount cat echo sleep poweroff mkdir grep awk find ls sync sed head test; do
        ln -sf /bin/busybox "$INITRAMFS/bin/$applet"
    done
    ln -sf /bin/busybox "$INITRAMFS/sbin/poweroff"

    cp /usr/bin/btrfs "$INITRAMFS/usr/bin/btrfs"
    ldd /usr/bin/btrfs | awk '/=> \/[^ ]+/ {print $3} $1 ~ /^\// {print $1}' \
        | while read -r library; do
            [ -f "$library" ] || continue
            mkdir -p "$INITRAMFS$(dirname "$library")"
            cp -L "$library" "$INITRAMFS$library"
        done

    cat > "$INITRAMFS/etc/initrd-release" <<'EOF'
NAME=CatOS
VERSION_ID=recovery-acceptance
EOF

    cat > "$INITRAMFS/init" <<'GUEST'
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
mount -t proc none /proc 2>/dev/null
mount -t sysfs none /sys 2>/dev/null
mount -t devtmpfs none /dev 2>/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -b /dev/vda ] && [ -b /dev/vdb ] && break
    sleep 1
done
if [ ! -b /dev/vda ] || [ ! -b /dev/vdb ]; then
    echo "===RECOVERY_FATAL=== missing virtio block devices"
    poweroff -f
fi

scenario=""
plan_id=""
token=""
post_fault=""
pre_fault=""
before_fault=""
root_subvol="/@"
for arg in $(cat /proc/cmdline); do
    case "$arg" in
        RECOVERY_SCENARIO=*) scenario=${arg#RECOVERY_SCENARIO=} ;;
        RECOVERY_PLAN_ID=*) plan_id=${arg#RECOVERY_PLAN_ID=} ;;
        RECOVERY_TOKEN=*) token=${arg#RECOVERY_TOKEN=} ;;
        RECOVERY_POST_FAULT_AT=*) post_fault=${arg#RECOVERY_POST_FAULT_AT=} ;;
        RECOVERY_PRE_FAULT_AT=*) pre_fault=${arg#RECOVERY_PRE_FAULT_AT=} ;;
        RECOVERY_BEFORE_FAULT_AT=*) before_fault=${arg#RECOVERY_BEFORE_FAULT_AT=} ;;
        RECOVERY_ROOT_SUBVOL=*) root_subvol=${arg#RECOVERY_ROOT_SUBVOL=} ;;
    esac
done
[ -n "$post_fault" ] && export CATOS_RECOVERY_FAULT_AT="$post_fault"
[ -n "$pre_fault" ] && export CATOS_RECOVERY_FAULT_PRE_AT="$pre_fault"
[ -n "$before_fault" ] && export CATOS_RECOVERY_FAULT_BEFORE_AT="$before_fault"

ROOT_ARGS="--root-device /dev/vda --root-subvolume $root_subvol"
SNAPSHOT_ARGS="--snapshot-subvolume /@snapshots/2"
BIN=/bin/catos-system
case "$scenario" in
    apply_fault|resume_fault|revert_fault) BIN=/bin/catos-system-test ;;
esac

run_and_poweroff() {
    label=$1
    shift
    echo "===RECOVERY_${label}_BEGIN==="
    "$@"
    rc=$?
    echo "===RECOVERY_${label}_END=== rc=$rc"
    sync
    poweroff -f
}

case "$scenario" in
    plan)
        # shellcheck disable=SC2086
        run_and_poweroff PLAN /bin/catos-system recovery plan $ROOT_ARGS $SNAPSHOT_ARGS --json
        ;;
    plan_nested)
        # shellcheck disable=SC2086
        run_and_poweroff PLAN /bin/catos-system recovery plan $ROOT_ARGS \
            --snapshot-subvolume /@/.snapshots/2/snapshot --json
        ;;
    inspect)
        # shellcheck disable=SC2086
        run_and_poweroff INSPECT /bin/catos-system recovery inspect $ROOT_ARGS $SNAPSHOT_ARGS --json
        ;;
    status)
        [ -n "$plan_id" ] || { echo "===RECOVERY_FATAL=== status missing plan id"; poweroff -f; }
        # shellcheck disable=SC2086
        run_and_poweroff STATUS /bin/catos-system recovery status $ROOT_ARGS \
            --transaction "$plan_id" --json
        ;;
    apply|apply_fault)
        [ -n "$plan_id" ] && [ -n "$token" ] && [ -f /plan.json ] \
            || { echo "===RECOVERY_FATAL=== apply missing plan inputs"; poweroff -f; }
        # shellcheck disable=SC2086
        run_and_poweroff APPLY "$BIN" recovery apply $ROOT_ARGS $SNAPSHOT_ARGS \
            --plan-file /plan.json --plan-id "$plan_id" --confirm "$token" --json
        ;;
    resume|resume_fault)
        [ -n "$plan_id" ] || { echo "===RECOVERY_FATAL=== resume missing plan id"; poweroff -f; }
        # shellcheck disable=SC2086
        run_and_poweroff RESUME "$BIN" recovery resume $ROOT_ARGS \
            --transaction "$plan_id" --json
        ;;
    revert|revert_fault)
        [ -n "$plan_id" ] && [ -n "$token" ] \
            || { echo "===RECOVERY_FATAL=== revert missing confirmation"; poweroff -f; }
        # shellcheck disable=SC2086
        run_and_poweroff REVERT "$BIN" recovery revert $ROOT_ARGS \
            --transaction "$plan_id" --confirm "$token" --json
        ;;
    verify_applied|verify_reverted|verify_untouched)
        mkdir -p /mnt
        if ! mount -t btrfs -o ro,subvolid=5 /dev/vda /mnt; then
            echo "===VERIFY_FAIL=== cannot mount btrfs image"
            poweroff -f
        fi
        ok=1
        if ! grep -q 'home-data-must-not-change' /mnt/@home/user-file; then
            echo "===VERIFY_FAIL=== @home changed"; ok=0
        fi
        snapshot_path=/mnt/@snapshots/2
        [ -e "$snapshot_path" ] || snapshot_path=/mnt/@/.snapshots/2/snapshot
        snapshot_ro=$(btrfs property get "$snapshot_path" ro 2>&1)
        if ! echo "$snapshot_ro" | grep -q 'ro=true'; then
            echo "===VERIFY_FAIL=== source snapshot is not readonly: $snapshot_ro"; ok=0
        fi
        active_root_dir="/mnt$root_subvol"
        case "$scenario" in
            verify_applied)
                [ -f "$active_root_dir/var/lib/pacman/local/SNAPSHOT_2_MARKER" ] \
                    || { echo "===VERIFY_FAIL=== active root lacks snapshot marker"; ok=0; }
                [ -f "/mnt/.catos-recovery/backups/$plan_id/root-before/var/lib/pacman/local/CURRENT_MARKER" ] \
                    || { echo "===VERIFY_FAIL=== backup lacks original marker"; ok=0; }
                ;;
            verify_reverted)
                [ -f "$active_root_dir/var/lib/pacman/local/CURRENT_MARKER" ] \
                    || { echo "===VERIFY_FAIL=== active root was not restored"; ok=0; }
                [ ! -f "$active_root_dir/var/lib/pacman/local/SNAPSHOT_2_MARKER" ] \
                    || { echo "===VERIFY_FAIL=== reverted root still has snapshot marker"; ok=0; }
                ;;
            verify_untouched)
                [ -f "$active_root_dir/var/lib/pacman/local/CURRENT_MARKER" ] \
                    || { echo "===VERIFY_FAIL=== untouched root marker missing"; ok=0; }
                [ ! -e /mnt/.catos-recovery/transactions ] \
                    || { echo "===VERIFY_FAIL=== refusal path wrote a transaction"; ok=0; }
                ;;
        esac
        umount /mnt
        if [ "$ok" -eq 1 ]; then echo "===VERIFY_OK==="; else echo "===VERIFY_FAILED==="; fi
        sync
        poweroff -f
        ;;
    *)
        echo "===RECOVERY_FATAL=== unknown scenario $scenario"
        poweroff -f
        ;;
esac
GUEST
    chmod +x "$INITRAMFS/init"
}

build_initramfs() {
    plan=${1:-}
    output=$2
    if [ -n "$plan" ]; then cp "$plan" "$INITRAMFS/plan.json"; else rm -f "$INITRAMFS/plan.json"; fi
    (cd "$INITRAMFS" && find . -print0 | cpio --null --create --format=newc 2>/dev/null) \
        | gzip -9 > "$output"
}

write_root() {
    root=$1
    pretty=$2
    marker=$3
    external_esp=$4
    subvol=$5
    [ -n "$subvol" ] || subvol='/@'
    mkdir -p "$root"/{etc,usr/lib/modules,boot,var/lib/pacman/local}
    cat > "$root/etc/os-release" <<EOF
NAME=CatOS
ID=catos
ID_LIKE=arch
PRETTY_NAME="$pretty"
EOF
    if [ "$marker" = current ]; then
        echo current-root-marker > "$root/var/lib/pacman/local/CURRENT_MARKER"
    else
        echo snapshot-2-marker > "$root/var/lib/pacman/local/SNAPSHOT_2_MARKER"
    fi
    cat > "$root/etc/fstab" <<EOF
UUID=22222222-3333-4444-5555-666666666666 / btrfs rw,subvol=$subvol 0 0
EOF
    if [ "$external_esp" -eq 1 ]; then
        mkdir -p "$root/boot/efi"
        echo '/dev/vdb /boot/efi vfat defaults 0 0' >> "$root/etc/fstab"
    fi
}

create_fixture() {
    layout=$1
    rm -rf "$TREE" "$BTRFS_IMG" "$ESP_IMG"
    mkdir -p "$TREE/@home"
    echo home-data-must-not-change > "$TREE/@home/user-file"
    external=0
    [ "$layout" = external ] && external=1
    if [ "$layout" = nondefault_root ]; then
        current_subvol='@root'
        write_root "$TREE/@root" "CatOS Recovery Current Root" current "$external" '/@root'
    else
        current_subvol='@'
        write_root "$TREE/@" "CatOS Recovery Current Root" current "$external" '/@'
    fi
    if [ "$layout" = nested ]; then
        source_dir="$TREE/@/.snapshots/2/snapshot"
        source_subvol='@/.snapshots/2/snapshot'
    else
        source_dir="$TREE/@snapshots/2"
        source_subvol='@snapshots/2'
    fi
    write_root "$source_dir" "CatOS Recovery Snapshot 2" snapshot "$external" '/@'

    truncate -s 512M "$BTRFS_IMG"
    mkfs.btrfs -q -f -U 22222222-3333-4444-5555-666666666666 \
        -r "$TREE" --subvol "default:$current_subvol" --subvol rw:@home --subvol "ro:$source_subvol" \
        "$BTRFS_IMG" || fail "mkfs.btrfs failed for $layout fixture"

    truncate -s 32M "$ESP_IMG"
    mkfs.vfat -i C4705E12 "$ESP_IMG" >/dev/null || fail "mkfs.vfat failed"
    mmd -i "$ESP_IMG" ::/EFI ::/EFI/CatOS >/dev/null || fail "cannot create ESP dirs"
    printf 'CatOS ESP fixture\n' > "$WORKDIR/test.efi"
    mcopy -i "$ESP_IMG" "$WORKDIR/test.efi" ::/EFI/CatOS/test.efi >/dev/null \
        || fail "cannot populate ESP"
    ESP_HASH_BEFORE=$(sha256sum "$ESP_IMG" | awk '{print $1}')
}

prepare_initramfs
build_initramfs "" "$INITRAMFS_PLAN"

accel=()
if [ -w /dev/kvm ] && "$QEMU_BIN" -accel help 2>&1 | grep -q '^kvm$'; then
    accel=(-enable-kvm -cpu host)
fi

run_guest() {
    scenario=$1
    fault=${2:-}
    plan_id=${3:-}
    token=${4:-}
    initramfs=${5:-$INITRAMFS_RUN}
    root_subvol=${6:-/@}
    RUN_INDEX=$((RUN_INDEX + 1))
    LAST_LOG="$WORKDIR/serial-$(printf '%03d' "$RUN_INDEX")-$scenario.log"
    append="console=ttyS0 panic=1 rdinit=/init RECOVERY_SCENARIO=$scenario RECOVERY_ROOT_SUBVOL=$root_subvol"
    case "$fault" in
        post:*) append="$append RECOVERY_POST_FAULT_AT=${fault#post:}" ;;
        pre:*) append="$append RECOVERY_PRE_FAULT_AT=${fault#pre:}" ;;
        before:*) append="$append RECOVERY_BEFORE_FAULT_AT=${fault#before:}" ;;
        '') ;;
        *) fail "unknown fault selector: $fault" ;;
    esac
    [ -n "$plan_id" ] && append="$append RECOVERY_PLAN_ID=$plan_id"
    [ -n "$token" ] && append="$append RECOVERY_TOKEN=$token"
    timeout 120 "$QEMU_BIN" -M pc -m 1024M -no-reboot -nographic \
        "${accel[@]}" -kernel "$KERNEL" -initrd "$initramfs" -append "$append" \
        -drive if=none,id=btrfs,file="$BTRFS_IMG",format=raw,cache=none \
        -device virtio-blk-pci,drive=btrfs \
        -drive if=none,id=esp,file="$ESP_IMG",format=raw,cache=none \
        -device virtio-blk-pci,drive=esp < /dev/null > "$LAST_LOG" 2>&1
    qemu_rc=$?
    [ "$qemu_rc" -ne 124 ] || fail "QEMU timed out for $scenario"
    [ "$qemu_rc" -eq 0 ] || fail "QEMU exited $qemu_rc for $scenario"
    grep -q '===RECOVERY_FATAL===' "$LAST_LOG" && fail "guest reported fatal error for $scenario"
}

command_rc() {
    label=$1
    sed -n "s/.*===RECOVERY_${label}_END=== rc=\([0-9][0-9]*\).*/\1/p" "$LAST_LOG" | tail -1
}

assert_rc() {
    label=$1
    expected=$2
    actual=$(command_rc "$label")
    [ -n "$actual" ] || fail "missing $label end marker"
    [ "$actual" = "$expected" ] || fail "$label returned $actual, expected $expected"
}

assert_nonzero_rc() {
    label=$1
    actual=$(command_rc "$label")
    [ -n "$actual" ] || fail "missing $label end marker"
    [ "$actual" -ne 0 ] || fail "$label unexpectedly succeeded"
}

capture_json() {
    label=$1
    output=$2
    python3 - "$LAST_LOG" "$label" "$output" <<'PY'
import json, pathlib, sys
log, label, output = sys.argv[1:]
lines = pathlib.Path(log).read_text(errors='replace').splitlines()
start = f"===RECOVERY_{label}_BEGIN==="
end_prefix = f"===RECOVERY_{label}_END==="
inside = False
document = []
for line in lines:
    if line.strip() == start:
        inside = True
        continue
    if inside and line.startswith(end_prefix):
        break
    if inside:
        document.append(line.rstrip('\r'))
while document and not document[0].lstrip().startswith('{'):
    document.pop(0)
if not document:
    raise SystemExit(f"no JSON object found between {start} and {end_prefix}")
text = '\n'.join(document)
try:
    value, _ = json.JSONDecoder().raw_decode(text.lstrip())
except json.JSONDecodeError as error:
    raise SystemExit(f"invalid JSON between {start} and {end_prefix}: {error}")
pathlib.Path(output).write_text(json.dumps(value))
PY
    [ "$?" -eq 0 ] || fail "could not capture $label JSON"
}

json_value() {
    file=$1
    path=$2
    python3 - "$file" "$path" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
for part in sys.argv[2].split('.'):
    value = value[part]
if isinstance(value, bool): print(str(value).lower())
elif value is None: print('')
else: print(value)
PY
}

assert_json_value() {
    file=$1 path=$2 expected=$3
    actual=$(json_value "$file" "$path") || fail "missing JSON field $path"
    [ "$actual" = "$expected" ] || fail "$path=$actual, expected $expected"
}

assert_esp_unchanged() {
    after=$(sha256sum "$ESP_IMG" | awk '{print $1}')
    [ "$after" = "$ESP_HASH_BEFORE" ] || fail "ESP image changed"
}

emit_plan() {
    expected_boot=$1
    run_guest plan "" "" "" "$INITRAMFS_PLAN" "/@"
    assert_rc PLAN 0
    capture_json PLAN "$PLAN_FILE"
    assert_json_value "$PLAN_FILE" kind recovery_plan
    assert_json_value "$PLAN_FILE" payload.schema_version 4
    assert_json_value "$PLAN_FILE" payload.boot_consistency.status "$expected_boot"
    PLAN_ID=$(json_value "$PLAN_FILE" payload.plan_id)
    APPLY_TOKEN=$(json_value "$PLAN_FILE" payload.confirmation_token)
    [ -n "$PLAN_ID" ] && [ -n "$APPLY_TOKEN" ] || fail "plan lacks id/token"
    build_initramfs "$PLAN_FILE" "$INITRAMFS_RUN"
}

emit_plan_with_root_subvol() {
    expected_boot=$1
    root_subvol=$2
    run_guest plan "" "" "" "$INITRAMFS_PLAN" "$root_subvol"
    assert_rc PLAN 0
    capture_json PLAN "$PLAN_FILE"
    assert_json_value "$PLAN_FILE" kind recovery_plan
    assert_json_value "$PLAN_FILE" payload.schema_version 4
    assert_json_value "$PLAN_FILE" payload.boot_consistency.status "$expected_boot"
    assert_json_value "$PLAN_FILE" payload.current_root.path "$root_subvol"
    PLAN_ID=$(json_value "$PLAN_FILE" payload.plan_id)
    APPLY_TOKEN=$(json_value "$PLAN_FILE" payload.confirmation_token)
    [ -n "$PLAN_ID" ] && [ -n "$APPLY_TOKEN" ] || fail "plan lacks id/token"
    build_initramfs "$PLAN_FILE" "$INITRAMFS_RUN"
}

assert_completed_and_verify() {
    run_guest status "" "$PLAN_ID" ""
    assert_rc STATUS 0
    capture_json STATUS "$WORKDIR/status.json"
    assert_json_value "$WORKDIR/status.json" payload.reconciled_state completed
    run_guest verify_applied "" "$PLAN_ID" ""
    grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "guest applied-state verification failed"
    assert_esp_unchanged
}

run_fault_matrix() {
    phase=$1
    shift
    create_fixture internal
    emit_plan consistent
    index=0
    for point in "$@"; do
        index=$((index + 1))
        if [ "$index" -eq 1 ]; then scenario=apply_fault; label=APPLY; else scenario=resume_fault; label=RESUME; fi
        echo "info: $phase fault at $point"
        run_guest "$scenario" "$point" "$PLAN_ID" "$APPLY_TOKEN"
        assert_rc "$label" 137
    done
    run_guest resume "" "$PLAN_ID" ""
    assert_rc RESUME 0
    assert_completed_and_verify
    echo "pass: $phase crash matrix"
}

# Happy path is always exercised, even when crash matrices are skipped.
create_fixture internal
emit_plan consistent
run_guest apply "" "$PLAN_ID" "$APPLY_TOKEN"
assert_rc APPLY 0
assert_completed_and_verify
echo "pass: real Btrfs apply happy path"

if [ "$SKIP_CRASH" -eq 0 ]; then
    run_fault_matrix before-operation \
        before:create_backup before:create_replacement before:swap_roots
    run_fault_matrix after-operation-before-state \
        pre:create_backup pre:create_replacement pre:swap_roots
    run_fault_matrix after-state-persist \
        post:backup_created post:replacement_created post:old_root_moved post:new_root_installed
fi

# Completed revert, including the reverse-swap pre-persist crash window.
create_fixture internal
emit_plan consistent
run_guest inspect "" "$PLAN_ID" ""
assert_rc INSPECT 0
capture_json INSPECT "$WORKDIR/inspect-pre.json"
pre_id=$(json_value "$WORKDIR/inspect-pre.json" payload.current_root.subvolume_id)
run_guest apply "" "$PLAN_ID" "$APPLY_TOKEN"
assert_rc APPLY 0
run_guest inspect "" "$PLAN_ID" ""
assert_rc INSPECT 0
capture_json INSPECT "$WORKDIR/inspect-post.json"
post_id=$(json_value "$WORKDIR/inspect-post.json" payload.current_root.subvolume_id)
[ -n "$pre_id" ] && [ -n "$post_id" ] && [ "$pre_id" != "$post_id" ] \
    || fail "root identity did not change after apply (pre=$pre_id post=$post_id)"
run_guest status "" "$PLAN_ID" ""
assert_rc STATUS 0
capture_json STATUS "$WORKDIR/status-completed.json"
assert_json_value "$WORKDIR/status-completed.json" payload.reconciled_state completed
REVERT_TOKEN=$(json_value "$WORKDIR/status-completed.json" payload.revert_confirmation_token)
[ -n "$REVERT_TOKEN" ] || fail "completed status did not emit revert token"
run_guest revert_fault pre:swap_roots_back "$PLAN_ID" "$REVERT_TOKEN"
assert_rc REVERT 137
run_guest status "" "$PLAN_ID" ""
assert_rc STATUS 0
capture_json STATUS "$WORKDIR/status-reconciled-reverted.json"
assert_json_value "$WORKDIR/status-reconciled-reverted.json" payload.reconciled_state reverted
REVERT_TOKEN=$(json_value "$WORKDIR/status-reconciled-reverted.json" payload.revert_confirmation_token)
[ -n "$REVERT_TOKEN" ] || fail "reconciled Reverted status did not emit idempotent token"
run_guest revert "" "$PLAN_ID" "$REVERT_TOKEN"
assert_rc REVERT 0
run_guest inspect "" "$PLAN_ID" ""
assert_rc INSPECT 0
capture_json INSPECT "$WORKDIR/inspect-reverted.json"
reverted_id=$(json_value "$WORKDIR/inspect-reverted.json" payload.current_root.subvolume_id)
[ "$reverted_id" = "$pre_id" ] || fail "revert restored id $reverted_id, expected $pre_id"
run_guest verify_reverted "" "$PLAN_ID" ""
grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "guest reverted-state verification failed"
assert_esp_unchanged
echo "pass: completed revert and reverse-swap crash recovery"

# Nested Snapper-style source is explicitly unsupported and must not write.
create_fixture nested
run_guest plan_nested "" "" "" "$INITRAMFS_PLAN"
assert_nonzero_rc PLAN
capture_json PLAN "$WORKDIR/nested-error.json"
assert_json_value "$WORKDIR/nested-error.json" kind error
assert_json_value "$WORKDIR/nested-error.json" payload.kind unsupported_nested_snapshot_layout
run_guest verify_untouched "" "" "" "$INITRAMFS_PLAN"
grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "nested-layout refusal wrote to target"
assert_esp_unchanged
echo "pass: nested snapshot layout refused without target writes"

# External ESP is understood but unsupported: plan reports it, apply refuses
# before Engine::begin, and neither target nor ESP may change.
create_fixture external
emit_plan unsupported
run_guest apply "" "$PLAN_ID" "$APPLY_TOKEN"
assert_nonzero_rc APPLY
capture_json APPLY "$WORKDIR/external-error.json"
assert_json_value "$WORKDIR/external-error.json" kind error
assert_json_value "$WORKDIR/external-error.json" payload.kind unsupported_external_boot_layout
run_guest verify_untouched "" "$PLAN_ID" "" "$INITRAMFS_PLAN"
grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "external-ESP refusal wrote to target"
assert_esp_unchanged
echo "pass: external ESP refused before persistent recovery writes"

# Non-default root subvolume /@root: end-to-end plan/apply/status/revert.
# Guards against a regression that hardcodes /@ in the swap, the
# backup path, the replacement source, or the revert restoration.
# Every guest invocation passes /@root as both the kernel cmdline
# RECOVERY_ROOT_SUBVOL and (via ROOT_ARGS) the catos-system
# --root-subvolume flag.
create_fixture nondefault_root
emit_plan_with_root_subvol consistent /@root
run_guest apply "" "$PLAN_ID" "$APPLY_TOKEN" "$INITRAMFS_RUN" /@root
assert_rc APPLY 0
run_guest status "" "$PLAN_ID" "" "$INITRAMFS_RUN" /@root
assert_rc STATUS 0
capture_json STATUS "$WORKDIR/status-nondefault-root.json"
assert_json_value "$WORKDIR/status-nondefault-root.json" payload.reconciled_state completed
run_guest verify_applied "" "$PLAN_ID" "" "$INITRAMFS_RUN" /@root
grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "non-default-root applied-state verification failed"
assert_esp_unchanged
REVERT_TOKEN_NONDEFAULT=$(json_value "$WORKDIR/status-nondefault-root.json" payload.revert_confirmation_token)
[ -n "$REVERT_TOKEN_NONDEFAULT" ] || fail "non-default-root status did not emit revert token"
run_guest revert "" "$PLAN_ID" "$REVERT_TOKEN_NONDEFAULT" "$INITRAMFS_RUN" /@root
assert_rc REVERT 0
run_guest verify_reverted "" "$PLAN_ID" "" "$INITRAMFS_RUN" /@root
grep -q '===VERIFY_OK===' "$LAST_LOG" || fail "non-default-root reverted-state verification failed"
assert_esp_unchanged
echo "pass: non-default root subvolume /@root plan/apply/status/revert"

echo "pass: authoritative phase-3 recovery QEMU acceptance succeeded"
