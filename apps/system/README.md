# catos-system

System backend for CatOS. Phase 1 is read-only environment + target
inspection, phase 2 is read-only storage discovery + safe RO target
mount, and phase 3 is the explicitly-authorized, transactional,
crash-resumable Btrfs root-snapshot recovery. The backend ships as a
single static musl binary installed at `/usr/lib/catos/catos-system`,
exposed through three multicall symlinks:

```
/usr/bin/catos-update   -> ../lib/catos/catos-system
/usr/bin/catos-recovery -> ../lib/catos/catos-system
/usr/bin/catos-doctor   -> ../lib/catos/catos-system
```

All three symlinks point to the same inode. There is exactly one binary
target. `argv[0]` is honoured only for the JSON `invocation` field and for
help text; it never gates a permission.

## Read-only vs. write scope

| Phase | Writes to the target device? |
|-------|------------------------------|
| Phase 1 — environment + target inspection | **Never.** Pure reads of the running system and the target root. |
| Phase 2 — storage discovery + safe target mount | **Never.** Mounts are read-only with filesystem-specific safety options (ext4 `noload`, xfs `norecovery`, btrfs `rescue=nologreplay`, ...) so journal replay and superblock updates are suppressed. Pre-existing mounts are never unmounted. |
| Phase 3 — Btrfs root-snapshot recovery | **Yes, only on the operator's explicit authorization.** `recovery apply`, `resume`, and `revert` mount the target's btrfs top-level read-write inside a private mount namespace, perform a single `renameat2(RENAME_EXCHANGE)` root swap, and persist transaction state after every state transition. |

Phase 3 is the only place in `catos-system` that writes to the target
device. The write path is bounded, transactional, and never touches the
ESP, the bootloader, `/boot`, initramfs images, or firmware entries.

## Scope (phase 1 + phase 2 + phase 3)

This is **phase 1 + phase 2 + phase 3**. Phases 1 and 2 are read-only
with respect to the target system. Phase 2 adds storage discovery and
safe read-only mounting of the target system inside a private mount
namespace; it never writes to the target device (no journal replay, no
superblock updates, no LUKS unlock, no LVM/mdraid changes, no fsck, no
btrfs rollback).

Phase 3 adds a durable, crash-resumable, explicitly-authorized Btrfs
root-snapshot recovery transaction. It mounts the target's btrfs
top-level (subvolid=5) read-write inside a private namespace, performs
a single `renameat2(RENAME_EXCHANGE)` root swap between the current
root subvolume and a fresh snapshot of the operator-selected source
snapshot, and persists transaction state on the btrfs top-level at
`/.catos-recovery/transactions/<id>/state.json` after every state
transition. The transaction can be resumed at any time after a crash
(SIGKILL, power loss) by running `recovery resume --transaction <id>`.

Phase 3 will NEVER:

- pacman updates
- bootloader repair (GRUB / Limine / UKI)
- LUKS unlock
- LVM / mdraid manipulation
- fsck
- delete the pre-recovery backup automatically (it lives at
  `/.catos-recovery/backups/<id>/root-before` and stays until the
  operator removes it or runs `recovery revert`)
- write to the ESP (the recovery root swap does not touch the ESP;
  recovery does not call any bootloader tool — boot reconciliation
  is the operator's responsibility)
- run as a long-lived daemon or TUI
- perform network operations

Phase 3 guarantees:

- Every persistent state transition is fsynced (file data + parent dir)
  before the next action runs.
- Crash injection is gated behind the `recovery_fault_injection` cargo
  feature; the production binary cannot be made to inject faults.
- A held `flock(LOCK_EX)` on `/.catos-recovery/locks/<fsid>.lock`
  prevents two concurrent transactions on the same filesystem.
- The pre-recovery root is preserved as a readonly subvolume at the
  backup path; it is never deleted by `apply`, `resume`, or `Completed`
  transitions.

## CLI

```
# Phase 1 — read-only environment + target inspection
catos-system environment  [--root PATH] [--json]
catos-system capabilities [--root PATH] [--json]
catos-system inspect      [--root PATH] [--json]

# Phase 2 — read-only storage discovery + safe RO target mount
catos-system storage scan                [--root PATH] [--json]
catos-system target plan                 [--root PATH] [--json]
    [--root-device /dev/...] [--root-subvolume PATH] [--esp-device /dev/...]
catos-system target mount                [--root PATH] [--json]
    [--root-device /dev/...] [--root-subvolume PATH] [--esp-device /dev/...]

# Phase 3 — durable, crash-resumable Btrfs root-snapshot recovery
catos-system recovery list              [--json]
    [--root-device /dev/...]
catos-system recovery inspect           [--json]
    [--root-device /dev/...] [--root-subvolume PATH]
    [--snapshot-subvolume PATH]
catos-system recovery plan              [--json]
    [--root-device /dev/...] [--root-subvolume PATH]
    [--snapshot-subvolume PATH]
catos-system recovery apply             [--json]
    --root-device /dev/... --root-subvolume PATH
    --snapshot-subvolume PATH
    --plan-id ID --confirm TOKEN --plan-file PATH
catos-system recovery status            [--json]
    --root-device /dev/... --transaction ID
catos-system recovery resume            [--json]
    --root-device /dev/... --root-subvolume PATH
    --snapshot-subvolume PATH --transaction ID
catos-system recovery revert            [--json]
    --root-device /dev/... --transaction ID --confirm TOKEN

catos-system --version
catos-system --help
```

The three symlinks accept the same subcommands and use the same probe
core. The selected subcommand controls which report sections are
rendered:

- `environment`: runtime facts only
- `capabilities`: capability results only
- `inspect`: runtime, capabilities, and target inspection
- `storage scan`: walks `/sys/class/block`, `/proc/self/mountinfo`, the udev
  database, and a fixed trusted `blkid` path. With `CAP_SYS_ADMIN`, unmounted
  candidates are briefly mounted in a private namespace for content-based
  root/ESP identification. Btrfs is mounted at `subvolid=5`, subvolumes are
  enumerated, and obvious snapshots are excluded from root candidates.
- `target plan`: reads the selected target's own fstab through confined
  `openat2` access and builds a `MountPlan`; **does not leave any mount**.
  For an unmounted LiveCD/initramfs target, `--root-device` performs a
  short-lived read-only probe to obtain that device's fstab. Optional
  `--root-subvolume` and `--esp-device` override ambiguous choices.
- `target mount`: performs a one-shot `mount -> inspect -> cleanup` flow in
  a private mount namespace (`unshare(CLONE_NEWNS)` plus
  `MS_REC|MS_PRIVATE`). The returned session is the truthful final state
  (`finished` or `cleanup_incomplete`), not a stale active snapshot.

```
catos-doctor inspect --json
catos-recovery environment --json
catos-update capabilities --json
catos-recovery storage scan --json
catos-recovery target plan --json
```

### Exit codes

Stable values, defined in `src/error.rs` and documented in `--help`:

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| 0    | success                                                    |
| 2    | argument error (unknown flag, missing value, etc.)         |
| 3    | `--root` invalid (does not exist, not a directory)         |
| 4    | permission denied reading a critical path                  |
| 5    | probe failed; could not produce a report                   |
| 6    | JSON serialisation failed                                  |

## JSON contract

Top-level shape (all keys are English, stable, and version-pinned):

```json
{
  "schemaVersion": 2,
  "programVersion": "0.1.0",
  "invocation": "catos-system",
  "targetRoot": "/",
  "runtime": {
    "is_initramfs":        { "status": "unknown", "evidence": [ ... ] },
    "is_chroot":           { "status": "unknown", "evidence": [ ... ] },
    "is_live_environment": { "status": "unknown", "evidence": [ ... ] },
    "is_snapshot_boot":    { "status": "unknown", "evidence": [ ... ] },
    "has_systemd":         { "status": "unknown", "evidence": [ ... ] },
    "root_is_read_only":   { "status": "unknown", "evidence": [ ... ] }
  },
  "capabilities": [ { "name": "read_proc", "status": "available", "evidence": [ ... ] }, ... ],
  "target": {
    "root": "/",
    "os_release": { "name": "...", "id": "...", "id_like": "...", "version": "...", "pretty_name": "...", "raw_fields": [ ["KEY","VALUE"], ... ] },
    "has_fstab": "present",
    "has_crypttab": "absent",
    "has_pacman_db": "present",
    "has_usr": "present",
    "has_boot": "present",
    "has_efi": "absent",
    "has_boot_efi": "absent",
    "is_catos_target": { "status": "unknown", "evidence": [ ... ] },
    "tool_paths": [ { "name": "pacman", "path": "/usr/bin/pacman", "status": "available", "evidence": [ ... ] }, ... ]
  },
  "warnings": [ { "code": "PROBE_WARNING", "message": "..." } ]
}
```

Stable invariants of the JSON contract:

1. `schemaVersion` is currently `2`. It will only change on a
   backward-incompatible report change.
2. `schemaVersion`, `programVersion`, `invocation`, `targetRoot`, and
   `warnings` are always present. `runtime`, `capabilities`, and `target` are
   emitted according to the selected subcommand.
3. Enum values are `snake_case` and stable:
   - `Detection.status`: `detected` | `not_detected` | `unknown`
   - `CapabilityStatus`: `available` | `unavailable` | `unknown`
   - `PrimaryRuntimeMode`: `running_system` | `chroot` | `live_environment`
     | `initramfs` | `unknown`
   - `CapabilityKind.name`: `read_target_root` | `read_proc` | `read_sysfs`
     | `read_block_sysfs` | `access_dev` | `shell_available`
     | `mount_operations_possible` | `write_efivars_possible`
     | `systemd_available` | `pacman_present_in_target`
     | `mkinitcpio_present_in_target` | `btrfs_tool_available`
     | `cryptsetup_available` | `lsblk_available`
     | `mount_tool_available`
4. `unknown` is never serialised as `false` or `null`. It is always the
   literal string `"unknown"`. Consumers MUST NOT treat it as a boolean.
5. Adding fields to nested objects is allowed and is considered
   backward-compatible. Consumers MUST ignore unknown fields.
6. JSON output never contains ANSI colour escapes, log lines, or progress
   text. Phase-1 argument/probe errors use stderr. Phase-2 commands in
   `--json` mode return a structured `{ "kind": "error", ... }` envelope
   on stdout, preserving mount errno, completed steps, cleanup status, and
   residual mounts.
7. `targetRoot` is the exact string the user supplied via `--root` (default
   `/`); it is not canonicalised, so a user who passes `/mnt/` sees
   `/mnt/` in the report.
8. Target-side presence and tool status are three-state. Permission errors,
   I/O errors, and unsafe path resolution are represented as `unknown`, not
   collapsed into `false` or `missing`.

Schema 2 intentionally replaces the initial internal schema 1 contract. It
introduces subcommand-specific sections, three-state target presence, and
three-state target tool results.

A formal JSON Schema file is intentionally **not** provided in phase 1. The
above is the contract. If the report grows enough that machine validation
becomes valuable, a schema file can be added without breaking this contract.

## Architecture

```
src/
  main.rs            binary entry; forwards to entry::run
  lib.rs             exposes API for unit + integration tests
  entry.rs           multicall argv[0] dispatch + top-level wiring
  cli.rs             hand-rolled arg parser + exit codes
  error.rs           Error + FsError + stable exit codes
  process.rs         fixed-path, bounded, timed external-tool runner
  system_root.rs     validated display/canonical target-root paths
  phase2.rs          phase-2 orchestrators: storage scan / target plan / target mount
  phase3.rs          phase-3 orchestrators: recovery list/inspect/plan/apply/status/resume/revert
  model/             pure data + serde; no I/O
    evidence.rs        Evidence: code/source/message/value
    runtime.rs         Detection, DetectionStatus, RuntimeFacts, PrimaryRuntimeMode
    capability.rs      Capability, CapabilityKind, CapabilityStatus
    inspection.rs      TargetInspection, OsRelease, ToolPath, Warning, InspectionReport
    storage.rs         phase 2: devices, mount observations, Btrfs subvolumes, candidates
    mount.rs           phase 2: MountError taxonomy, MountPlan, MountSession, CleanupReport
    recovery.rs        phase 3: RecoveryPlan, TransactionState, RecoveryErrorKind, DiskFacts
    fstab.rs           re-exports of parse::fstab types
  parse/             pure parsers; no I/O
    fstab.rs           /etc/fstab parser + malformed-line diagnostics
    mountinfo.rs       /proc/self/mountinfo parser (octal escapes, VFS vs superblock options)
    blkid.rs           blkid udev + human-format parser (ID_FS_*, ID_PART_ENTRY_*)
  probe/             reads the world via FilesystemProbe trait
    fs_probe.rs        filesystem abstraction + confined target-root access (openat2)
    runtime.rs         detect_runtime + six detectors (initramfs/chroot/live/snapshot/systemd/ro)
    target.rs          inspect_target + os-release parsing + tool probes
    capability.rs      detect_capabilities (15 phase-1 capabilities)
    block.rs           sysfs + mountinfo + udev DB + trusted blkid supplement
    candidate.rs       phase 2: evidence-driven root/ESP candidate identification
  mount/             state-changing layer (phase 2); only read-only mounts
    syscall.rs         raw FFI for mount/umount2/unshare + errno→MountErrorKind table
    namespace.rs       unshare(CLONE_NEWNS) + MS_REC|MS_PRIVATE on / + verify
    plan.rs            per-fstype RO option table + MountPlan builder
    probe.rs           short-lived root/ESP probes + Btrfs subvolume discovery
    session.rs         private namespace + ordered mounts + reverse-order rollback
  recovery/          phase-3 transaction layer; only place that writes to target btrfs
    state.rs           pure state machine: transition(), happy_path_successor(), reconcile_with_disk_facts()
    identity.rs        SubvolumePath validation, IdentityDrift, confirmation token verification
    plan.rs            PlanInputs, schema-v4 SHA-256 plan digest and confirmation binding
    confined.rs        openat2-confined records, Btrfs snapshot ioctl, dirfd root exchange
    lock.rs            non-blocking per-FSID flock
    store.rs           schema checks and durable confined state/plan persistence
    external.rs        trusted read-only btrfs-progs wrapper with bounded execution
    boot.rs            read-only BootConsistencyReport and external boot-resource gate
    engine.rs          begin/load/drive/revert, state persistence and fault injection
  output/            renders model
    human.rs           plain ASCII human output (phase 1)
    json.rs            serde_json wrapper (phase 1, single source of JSON contract)
    phase2.rs          phase 2: human + JSON for StorageReport / MountPlan / MountSession
    recovery.rs        phase 3: human + JSON for RecoveryPlan / TransactionRecord / RecoveryError
```

Layering rules:

- `model/*` is pure data + serde. No I/O, no side effects.
- `parse/*` is pure functions of bytes-in, model-out. No I/O.
- `probe/*` reads the world via `FilesystemProbe` and returns structured
  models. It never prints or mounts. Optional external metadata helpers
  are launched only through `process.rs`, with a fixed trusted path,
  minimal environment, timeout, and output limits.
- `mount/*` is the ONLY place that issues mount/umount/unshare syscalls.
  It receives a fully-built `MountPlan` from `mount::plan` and a
  pre-snapshotted pre-existing-mount set from `mount::session`. Probe mounts
  are short-lived and clean before returning; target mounts inspect before
  reverse-order cleanup.
- `output/*` consumes models. It never probes.
- `phase2.rs` orchestrates between `entry.rs` and the probe/mount layers.
- `phase3.rs` orchestrates between `entry.rs` and the recovery layer.
  It enters a private mount namespace, mounts the btrfs top-level
  read-write, and hands control to `recovery::engine::Engine`. Every
  persistent state transition is fsynced before the next action runs.
- `recovery/*` is the ONLY place that writes to the target btrfs
  filesystem. It uses `recovery::external` for trusted btrfs-progs
  invocations (subcommand allow-list, fixed paths, bounded execution)
  and a raw `renameat2(RENAME_EXCHANGE)` syscall for the root swap.
- Every detection carries an `Evidence` trail (code, source, message,
  optional value).
- Probes that cannot gather enough evidence MUST return `Unknown`, never
  `NotDetected` and never a guess.
- Real target-root reads use Linux `openat2(2)` with `RESOLVE_IN_ROOT` and
  `RESOLVE_NO_MAGICLINKS`. Absolute symlinks are interpreted inside the
  selected target root, and magic-link escapes are rejected. Kernels without
  `openat2` are handled fail-closed: target-root probes return `unknown`
  instead of falling back to a race-prone pathname check.

## Build

The binary is built via CMake, which delegates to Cargo:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
```

CMake captures `Cargo.toml`, `Cargo.lock`, and `src/**/*.rs` as dependencies
so an incremental CMake build does NOT unconditionally rerun `cargo build`.
Cargo's target dir lives inside the CMake build tree
(`build/apps/system/cargo-target/`), never in the source tree.

The default Rust target is `x86_64-unknown-linux-musl` so the binary is fully
static. To override locally (e.g. for fast iteration without musl std):

```
cmake -S . -B build -DCATOS_SYSTEM_TARGET=x86_64-unknown-linux-gnu ...
```

Releases MUST use the musl-static default. The CMakeLists verifies the
target's std is installed and gives a clear error otherwise.

### Release profile

`Cargo.toml` ships:

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
incremental = false
overflow-checks = true
```

`opt-level` was chosen empirically. On rustc 1.96.1 + musl:

| Setting        | Stripped size |
|----------------|---------------|
| `opt-level="s"` | 463416 B (~452 KiB) |
| `opt-level="z"` | 455224 B (~445 KiB) |

`"z"` wins by ~8 KiB so it is the default. The static-link verification
script reports the size on every run so regressions are visible.

### Static-link verification

`scripts/verify-static.sh` parses the produced ELF directly via `readelf`
(the human-readable `file` output can mislead on static-pie). It checks:

- no `PT_INTERP` segment
- no `NEEDED` entries in the dynamic section
- ELF magic bytes
- binary size (warns above 4 MiB; not a hard failure)

### Dependencies

Only `serde` + `serde_json`. No async runtime, no TLS, no D-Bus, no libalpm,
no CLI framework. CLI parsing is hand-rolled.

## Tests

The following surfaces are wired into CTest when `-DBUILD_TESTS=ON`:

| Test                              | What it guards against                                |
|-----------------------------------|-------------------------------------------------------|
| `catos-system-cargo-test`         | Rust unit + integration tests. Includes runtime/capability fixtures, target-root confinement, mount policy, fstab diagnostics, candidate evidence, Btrfs parsing, structured errors, CLI and multicall contracts, phase-3 recovery state machine, transaction durability, SHA-256 plan/token binding, confined path attacks, boot-consistency gating, and crash-resumable transaction flow. |
| `catos-system-cargo-clippy`       | All Rust targets and features remain warning-free at the declared MSRV contract. |
| `catos-system-static-check`       | The musl binary silently regressing to dynamic linking (would break initramfs and recovery use). |
| `catos-system-initramfs-smoke-bare` | The static binary refusing to start in a minimal Linux user space without systemd, dbus, network, or `/usr`. |
| `catos-system-initramfs-smoke-with-marker` | Runtime detection failing to identify a mkinitcpio-style initramfs containing `/etc/initrd-release`. |
| `catos-system-storage-qemu-smoke` | A real writable ext4 root, FAT ESP, and Btrfs `@`/snapshot image: discovery, explicit planning, mount-inspect-cleanup, snapshot exclusion, session cleanup, and byte-for-byte no-write verification. |
| `catos-system-recovery-qemu-smoke` | Authoritative real-Btrfs acceptance in QEMU. Exercises the happy path, all three fault windows, resume reconciliation, Completed revert including the reverse-swap crash window, non-default source identity, guest-side data/backup/readonly assertions, nested-layout refusal, external-ESP refusal, and byte-for-byte ESP no-write verification. Once QEMU starts, skipped assertions are hard failures. |

The two minimal initramfs tests are opt-in through
`-DCATOS_SYSTEM_INITRAMFS_SMOKE=ON`. The real storage test is enabled with
`-DCATOS_SYSTEM_STORAGE_SMOKE=ON`. The phase-3 recovery crash/resume
test is enabled with `-DCATOS_SYSTEM_RECOVERY_SMOKE=ON` and additionally
requires `mkfs.btrfs`, `mkfs.vfat`, `mtools` (`mmd`, `mcopy`), `cpio`,
`gzip`, `zstd`, and `modinfo`. All three smoke tests require
`qemu-system-x86_64`, a kernel image, and static `busybox`; they use KVM
when available, otherwise TCG, and skip with exit code 77 when
prerequisites are missing.

Run them:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
( cd build && ctest --output-on-failure )
```

To explicitly run all QEMU smoke tests:

```
cmake -S . -B build -DBUILD_TESTS=ON \
  -DCATOS_SYSTEM_INITRAMFS_SMOKE=ON \
  -DCATOS_SYSTEM_STORAGE_SMOKE=ON \
  -DCATOS_SYSTEM_RECOVERY_SMOKE=ON
( cd build && ctest -L qemu --output-on-failure )
```

Run the Rust tests directly (faster iteration, no CMake):

```
( cd apps/system && cargo test )
```

`cargo test` runs against the host target so test binaries can execute.
The musl release binary is verified separately by `verify-static.sh` and (if
enabled) the QEMU smoke test. The shipped binary is musl-static; tests are
not used as an excuse to weaken that.

## Static-link acceptance (current)

On this host (rustc 1.96.1, x86_64-unknown-linux-musl):

```
$ stat -c %s <binary>
1036992
$ file <binary>
... static-pie linked ... stripped
$ readelf -l <binary> | grep INTERP     # (empty)
$ readelf -d <binary> | grep NEEDED     # (empty)
$ bash scripts/verify-static.sh <binary>
ok: no PT_INTERP segment
ok: no NEEDED entries
ok: ELF magic bytes present
info: binary size 1036992 bytes (1012 KiB)
RESULT: OK (binary is fully static)
```

The phase-3 backend includes the recovery transaction layer, identity
drift detection, SHA-256-bound plan and confirmation records, confined
openat2 storage, durable transaction persistence, Btrfs ioctl snapshot
creation, the renameat2 root exchange, read-only boot consistency
reporting, and JSON + human renderers for all phase-3 outcomes. Static
size is checked by `verify-static.sh` against the 4 MiB warning
threshold; the exact binary size depends on the current toolchain.

## What is NOT implemented (deferred to later phases)

- LUKS unlock (`cryptsetup` integration)
- pacman-driven update workflow
- Bootloader repair of any kind (GRUB, Limine, UKI, sd-boot). Recovery
  swaps the root subvolume only; it does NOT call any bootloader tool
  and does NOT write to the ESP. A read-only `BootConsistencyReport`
  is sealed into schema-v4 plans and recomputed at apply time before
  the first persistent write. Separate `/boot`, separate boot
  subvolumes, external ESPs, and unknown boot topology are refused.
- Automatic deletion of recovery backups (`/.catos-recovery/backups/`
  content is preserved indefinitely until the operator runs
  `recovery revert` or removes it manually)
- A TUI / interactive UI
- A long-running daemon
- Network operations of any kind
