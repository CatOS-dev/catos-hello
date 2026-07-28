# catos-system

`catos-system` is the CatOS system-maintenance utility. It is designed for the
running system, LiveCD, initramfs, and recovery environments without requiring
a shell script framework or a graphical session.

The package installs one static binary:

```text
/usr/lib/catos/catos-system
```

and five role-specific symlinks:

```text
/usr/bin/catos-update   -> ../lib/catos/catos-system
/usr/bin/catos-recovery -> ../lib/catos/catos-system
/usr/bin/catos-doctor   -> ../lib/catos/catos-system
/usr/bin/catos-repair   -> ../lib/catos/catos-system
/usr/bin/catos-chroot   -> ../lib/catos/catos-system
```

All six command names share the same inode. `argv[0]` selects the independent
entry point; it does not grant permission. These are the two valid command
shapes:

```text
catos-repair mount --help
catos-system repair mount --help
```

Putting an entry-point name in the aggregate command position is invalid:

```text
catos-system catos-repair --help   # rejected
```

## User commands

Running `catos-system` without arguments from an interactive terminal opens a
numbered maintenance menu. Successful actions return to the main menu so an
operator can perform several maintenance tasks in one session. With redirected
stdin or stdout, no-argument menu entry points fail with exit code 2 instead of
printing a prompt and reporting a false success. Scripts must name the command
they intend to run. The same actions are available directly for scripts and
experienced users:

| Command | Purpose |
|---|---|
| `catos-system doctor` / `catos-doctor` | Check an installed CatOS system and explain detected problems. |
| `catos-system chroot` / `catos-chroot` | Discover an installed system, mount it safely, and open a maintenance shell. |
| `catos-system repair` / `catos-repair` | Repair a filesystem, fstab/mount layout, or boot setup. |
| `catos-system recovery` / `catos-recovery` | Inspect, apply, resume, or revert Btrfs snapshot recovery. |
| `catos-system update` / `catos-update` | Check for and apply package updates on the running system. |
| `catos-system advanced` | Low-level read-only inspection and target-mount tools. |

`catos-repair` and `catos-recovery` also open interactive submenus when run
without a command and attached to a terminal. Interactive repair and recovery
can select a detected CatOS installation instead of requiring the operator to
type a block-device path. Recovery lists detected snapshots and transactions,
interactive Apply loads the plan ID and confirmation token from the validated
plan file, and interactive Revert obtains its state-bound token from a fresh
status check.

Doctor, chroot, all Repair commands, and the write-capable Recovery commands
(`apply`, `resume`, and `revert`) request administrator privileges through an
absolute trusted `sudo`, `sudo-rs`, `doas`, or `run0` path before privileged
probing begins. Redirecting stdout does not disable password prompting when
stdin remains a terminal. In non-interactive use, an unprivileged invocation
fails immediately with exit code 4 rather than waiting for a password prompt or
probing the requested device first.

`catos-update` resolves `checkupdates`, `pacman`, and the elevation program only
from fixed trusted system directories. `checkupdates` exit code 2 means that no
updates are available; timeout, truncation, exit code 1, signals, or an
inconsistent empty successful result are reported as failures rather than as
"system is up to date". Update-list and confirmation-prompt write failures stop
the workflow with exit code 6 before package installation begins.

## Read/write boundary

Diagnosis, storage discovery, target planning, and read-only target inspection
do not modify the selected installation. State-changing operations require an
explicit repair, recovery, update, or chroot action:

```text
catos-repair fs
catos-repair mount
catos-repair boot
catos-recovery apply
catos-recovery resume
catos-recovery revert
catos-update
catos-chroot
```

`catos-repair fs` delegates to the official filesystem tools after target,
mount-state, topology, and shared-device-lock checks. Write-capable repair
commands have no short default deadline, and capped output is drained to EOF
so a verbose repair process is not terminated by `SIGPIPE`.

`catos-repair mount` uses the target's own fstab and os-release, binds the
operation to target identity and an fstab digest, writes through confined
dirfd operations, verifies the resulting mount layout, and restores the
original fstab plus newly-created empty objects when verification fails. It
never unmounts the running root or a pre-existing mount.

Snapshot recovery mounts the Btrfs top level read-write inside a private mount
namespace, validates the immutable plan and target identity, performs the root
exchange, and persists every transaction state. Filesystem repair, mount
repair, and recovery share a block-device lock so they cannot write the same
target concurrently.

## Snapshot-recovery guarantees

- Every persistent state transition is fsynced before the next operation.
- Fault injection is unavailable in the production binary.
- An exclusive filesystem lock prevents concurrent recovery transactions.
- The pre-recovery root is preserved as a read-only backup.
- `apply`, `resume`, and `revert` do not execute package management commands.
- Recovery never performs automatic boot repair.

## CLI

### Interactive entry

```text
catos-system
catos-repair
catos-recovery
```

These no-argument forms require both stdin and stdout to be terminals. Use the
explicit commands below for redirected or automated execution.

### Primary commands

```text
catos-system doctor
catos-system chroot
catos-system repair fs [DEVICE]
catos-system repair mount [--root-device /dev/...] [--root-subvolume /@]
catos-system repair boot  [--root-device /dev/...] [--root-subvolume /@]
catos-system recovery <list|inspect|plan|apply|status|resume|revert> [OPTIONS]
catos-system update [--check]
```

The role-specific aliases use the same command tail without the aggregate
role name:

```text
catos-doctor
catos-chroot
catos-repair mount --root-device /dev/nvme0n1p2
catos-recovery status --root-device /dev/nvme0n1p2 --transaction ID
catos-update --check
```

### Advanced read-only commands

These commands are retained for diagnostics and automation but do not dominate
the normal help screen:

```text
catos-system advanced inspect [--root PATH] [--json]
catos-system advanced environment [--root PATH] [--json]
catos-system advanced capabilities [--root PATH] [--json]
catos-system advanced storage scan [--json]
catos-system advanced target plan [OPTIONS]
catos-system advanced target mount [OPTIONS]
```

The legacy direct spellings remain compatible:

```text
catos-system inspect --json
catos-system --json inspect
catos-system storage scan --json
catos-system target plan --root-device /dev/nvme0n1p2 --json
```

Low-level inspection commands belong only to `catos-system`; forms such as
`catos-recovery environment` and `catos-chroot inspect` are rejected.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The requested command completed. For Doctor, this means a report was produced; health severity is reported separately. |
| 2 | The command, option, target selection, or requested operation was invalid. |
| 3 | A supplied target root was invalid. |
| 4 | Administrator privileges or access to a critical path were unavailable. |
| 5 | Diagnosis, repair, recovery, mount, shell entry, or cleanup could not complete. |
| 6 | Structured output could not be serialised or written. |

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
   text. Inspection argument/probe errors use stderr. Storage and target-mount
   commands in `--json` mode return a structured `{ "kind": "error", ... }` envelope
   on stdout, preserving mount errno, completed steps, cleanup status, and
   residual mounts.
7. `targetRoot` is the exact string the user supplied via `--root` (default
   `/`); it is not canonicalised, so a user who passes `/mnt/` sees
   `/mnt/` in the report.
8. Target-side presence and tool status are three-state. Permission errors,
   I/O errors, and unsafe path resolution are represented as `unknown`, not
   collapsed into `false` or `missing`.

Schema 2 introduced subcommand-specific sections, three-state target presence,
and three-state target tool results.

A formal JSON Schema file is intentionally **not** provided yet. The above is
the contract. If the report grows enough that machine validation
becomes valuable, a schema file can be added without breaking this contract.

## Architecture

The application layer is organised by user responsibility rather than by
implementation chronology:

```text
src/
  main.rs                 process entry; resolves argv[0]
  entry.rs                aggregate and role-specific command routing
  entry/menu.rs           line-oriented interactive menus
  entry/chroot.rs         privilege elevation and chroot application flow
  cli/                    low-level inspection parser and help
  selection_ui.rs         detected-target presentation and selection
  doctor/                 aggregated read-only diagnosis
  repair/                 filesystem, mount-layout, and boot repair wiring
  recovery/               snapshot recovery command orchestration
  system/                 storage scan and read-only target inspection
  update/                 package-update workflow
  output/                 human and JSON rendering
```

Reusable capabilities live in separate crates:

```text
crates/
  catos-target/           confined target reads, discovery, identity, fstab
  catos-mount/            mount planning, namespaces, sessions, verification
  catos-fs/               filesystem safety, command plans, repair verification
  catos-boot/             boot-provider detection, planning, execution, verification
  catos-snapshot/         durable Btrfs recovery state machine and storage
  catos-chroot/           chroot plans, assembly, shell preflight, cleanup
  catos-process/          trusted executable resolution and bounded processes
```

Layering rules:

- Capability crates do not parse the public command line or ask interactive
  questions.
- Target-side reads use confined Linux path resolution and fail closed on
  unsafe paths.
- External tools are resolved only from trusted system directories and are
  executed with explicit argv, bounded output, and controlled timeouts.
- Mounts are created inside private namespaces where required and are cleaned
  in reverse order. Pre-existing mounts are never unmounted.
- Repair and recovery hold shared device locks before persistent changes.
- Renderers consume structured models; they do not probe or mutate systems.
- Every uncertain detection remains `unknown` rather than being converted to
  a false assertion.

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

Runtime dependencies are limited to `serde`, `serde_json`, `sha2`,
`getrandom`, and `libc`. There is no async runtime, TLS stack, D-Bus client,
libalpm binding, or CLI framework; CLI parsing is hand-rolled.

## Tests

The following surfaces are wired into CTest when `-DBUILD_TESTS=ON`:

| Test                              | What it guards against                                |
|-----------------------------------|-------------------------------------------------------|
| `catos-system-cargo-test`         | Rust unit + integration tests. Includes runtime/capability fixtures, target-root confinement, mount policy, fstab diagnostics, candidate evidence, Btrfs parsing, structured errors, CLI and multicall contracts, snapshot-recovery state machine, transaction durability, SHA-256 plan/token binding, confined path attacks, boot-consistency gating, crash-resumable transaction flow, mount-repair fstab-editor preservation, subvolume-rebuild authorisation rules, path-safety refusals, and identity/drift detection. |
| `catos-system-cargo-clippy`       | Runs Clippy for the workspace targets configured by CMake. The application crate is also checked separately with warnings denied during CLI changes. |
| `catos-system-static-check`       | The musl binary silently regressing to dynamic linking (would break initramfs and recovery use). |
| `catos-system-initramfs-smoke-bare` | The static binary refusing to start in a minimal Linux user space without systemd, dbus, network, or `/usr`. |
| `catos-system-initramfs-smoke-with-marker` | Runtime detection failing to identify a mkinitcpio-style initramfs containing `/etc/initrd-release`. |
| `catos-system-storage-qemu-smoke` | A real writable ext4 root, FAT ESP, and Btrfs `@`/snapshot image: discovery, explicit planning, mount-inspect-cleanup, snapshot exclusion, session cleanup, and byte-for-byte no-write verification. |
| `catos-system-recovery-qemu-smoke` | Authoritative real-Btrfs acceptance in QEMU. Exercises the happy path, all three fault windows, resume reconciliation, Completed revert including the reverse-swap crash window, non-default source identity, guest-side data/backup/readonly assertions, nested-layout refusal, external-ESP refusal, and byte-for-byte ESP no-write verification. Once QEMU starts, skipped assertions are hard failures. |
| `catos-system-repair-qemu-smoke` | Real-filesystem repair acceptance in QEMU. It repairs deliberately damaged ext4 and FAT images, damages one metadata-DUP root-tree mirror and proves Btrfs escalates from the checksum diagnostic to `--repair` and a clean recheck, exercises normal XFS repair, and creates a real unclean XFS journal by killing a writer VM before proving `xfs_repair -L` reports `repaired_with_risk`. |
| `catos-system-mount-repair-qemu-smoke` | State-changing mount-repair acceptance in QEMU. It exercises all six `/boot`/ESP layouts, a Btrfs `@boot`, an independent ext4 `/boot`, a plain ext4 target, the currently-running ext4 root without unmounting it, complete fstab mount verification, and empty-subvolume rollback after an induced verification failure. |
| `catos-system-doctor-qemu-smoke` | Read-only Doctor acceptance in QEMU. Builds real CatOS btrfs target images (healthy, fs-corrupt, mount-break, ambiguous, doctor-fail), runs `catos-doctor` against each, asserts exit code 0 under the documented Doctor exit semantics for every unhealthy scenario, asserts non-zero exit only for doctor-fail, AND verifies byte-for-byte by `sha256` that no target image was written. Once QEMU starts, skipped assertions are hard failures. |

The two minimal initramfs tests are opt-in through
`-DCATOS_SYSTEM_INITRAMFS_SMOKE=ON`. The real storage test is enabled with
`-DCATOS_SYSTEM_STORAGE_SMOKE=ON`. The recovery crash/resume
test is enabled with `-DCATOS_SYSTEM_RECOVERY_SMOKE=ON` and additionally
requires `mkfs.btrfs`, `mkfs.vfat`, `mtools` (`mmd`, `mcopy`), `cpio`,
`gzip`, `zstd`, and `modinfo`. The filesystem-repair test is enabled with
`-DCATOS_SYSTEM_REPAIR_SMOKE=ON` and additionally requires `mkfs.ext4`,
`mkfs.vfat`, `mkfs.btrfs`, `e2fsck`, `fsck.fat`, `btrfs`,
`btrfs-map-logical`, and `debugfs`;
XFS acceptance is enabled when `mkfs.xfs` and `xfs_repair` are installed.
The six-layout state-changing test is enabled with
`-DCATOS_SYSTEM_MOUNT_REPAIR_SMOKE=ON` and additionally uses `sfdisk`,
`mkfs.ext4`, `mkfs.vfat`, `mtools`, and `mkfs.btrfs`. All smoke tests require
`qemu-system-x86_64`, a kernel image, and static `busybox`; they use KVM when
available, otherwise TCG, and skip with exit code 77 when prerequisites are
missing.

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
  -DCATOS_SYSTEM_RECOVERY_SMOKE=ON \
  -DCATOS_SYSTEM_REPAIR_SMOKE=ON \
  -DCATOS_SYSTEM_DOCTOR_SMOKE=ON
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

Snapshot recovery is implemented by `src/recovery/` and the
`catos-snapshot` crate. It includes the recovery transaction layer, identity
drift detection, SHA-256-bound plan and confirmation records, confined
openat2 storage, durable transaction persistence, Btrfs ioctl snapshot
creation, the renameat2 root exchange, read-only boot consistency
reporting, and JSON + human renderers for all snapshot-recovery outcomes. Static
size is checked by `verify-static.sh` against the 4 MiB warning
threshold; the exact binary size depends on the current toolchain.

## `catos-repair mount`

`catos-repair mount` repairs the target's `/etc/fstab`, CatOS standard Btrfs
subvolume layout, mount-point directories, independent `/boot`, and ESP mount
relationship. It supports offline Btrfs, ext2/3/4, XFS, and F2FS roots. A
uniquely identified currently-running CatOS root may repair its own fstab in a
private namespace; the running root is never unmounted.

```text
catos-repair mount [--json]
    [--root-device /dev/...] [--root-subvolume /@]
    [--esp-device /dev/...]
```

Running the command itself authorises repair. There are deliberately no
`inspect`, `plan`, `apply`, `status`, or `resume` public subcommands.

### CatOS standard Btrfs layout

```text
/            → /@
/home        → /@home
/root        → /@root
/srv         → /@srv
/var/cache   → /@cache
/var/tmp     → /@tmp
/var/log     → /@log
/.snapshots  → /@snapshots
```

Missing standard subvolumes are recreated only from confirmed CatOS identity
or fstab history. Existing filesystem objects are never overwritten. Data in
a populated ordinary mount-point directory is never migrated or deleted; the
result is reported as `data_conflict` and requires manual handling.

### Structure-preserving fstab editing

The editor works from the verbatim file rather than serialising a new template.
Comments, blank lines, unrelated mounts, swap entries, `noauto`, `nofail`, and
`x-systemd.*` options are retained. Root UUID and subvolume corrections are
combined in one replacement, and non-root standard entries are edited in
place. The original file is durably saved as
`/etc/fstab.catos-repair.backup` before replacement.

### Six `/boot` and ESP layouts

The target's own fstab, discovered block identities, FAT type, GPT ESP role,
and mounted EFI content are used to identify exactly one of:

1. ESP at `/boot/efi`;
2. ESP at `/efi`;
3. ESP directly at `/boot`;
4. independent ordinary `/boot` plus a nested ESP;
5. `/boot` as a Btrfs subvolume, optionally with a nested ESP;
6. `/boot` inside the root filesystem.

The repair preserves the existing layout; it never migrates providers or
invents a new ESP mount point. A separate ordinary `/boot` is not rewritten as
the ESP. For `/boot/efi`, the nested directory is created inside the external
`/boot` filesystem or `@boot`, not only in the underlying root directory.

### Transaction, verification, and rollback

The immutable plan binds to the target identity and SHA-256 of the original
fstab. Immediately before writing, the shared block-device lock is held and
the target fstab is re-read. Writes and directory/subvolume creation use
confined, no-symlink dirfd operations.

After replacement, the complete repaired fstab is mounted in a private
namespace. Verification includes the root, every standard local subvolume,
independent `/boot`, and the ESP. Plain/current roots reuse their existing
private root mount and verify additional resources without duplicate-mounting
the root.

On failure, the original fstab is restored and objects created by the current
transaction are rolled back in reverse order. Only proven-empty directories
and Btrfs subvolumes are removed. Non-empty or identity-uncertain objects are
left untouched and listed as rollback residuals. Session-created mounts are
cleaned in reverse order; pre-existing mounts are never unmounted.

### Deliberate exclusions

Mount repair does not run fsck, format or repartition devices, open LUKS,
assemble LVM/mdraid, migrate ordinary-directory data, rebuild Snapper config,
modify snapshot contents, install a bootloader, change Secure Boot state, or
run arbitrary target commands.

## `catos-repair boot`

`catos-repair boot` re-applies the target's currently-selected bootloader
provider recipe. It is a behaviour port of the Calamares `bootloadu` module to
the static Rust implementation; it does not invent a new bootloader architecture or a
parallel transaction framework.

```text
catos-repair boot [--json]
    [--root-device /dev/...] [--root-subvolume /@]
    [--esp-device /dev/...]
```

Running the command itself authorises re-application of the detected
provider's recipe. There are deliberately no `inspect`, `plan`, `apply`,
`status`, or `resume` public subcommands, and no per-provider subcommand
(`catos-repair boot grub` is rejected). The provider is selected from target
evidence, never from the live host's installed tools.

### Supported providers

| Provider | BIOS | UEFI x86_64 | UEFI aarch64 | Partition table |
|---|---|---|---|---|
| GRUB | x | x | x | any (GPT or MBR) |
| Limine | - | x | - | GPT only |
| systemd-boot | - | x | x | GPT only |
| UKI (FirmwareProvider method=uki) | - | x | x | GPT only |
| EFI Stub (FirmwareProvider method=efistub) | - | x | x | GPT only |

UKI and EFI Stub share a single `FirmwareProvider` implementation
parameterised by the `method = ...` field of
`/etc/catos/firmware-boot.conf`. They are NOT two parallel codebases.

### Provider detection

Detection is evidence-based and fail-closed. Authoritative signals are the
target's own bootloadu-managed configuration files:

- `/etc/default/grub.d/00-catos.cfg` (GRUB)
- `/etc/default/limine` (Limine)
- `/etc/kernel/install.conf.d/20-catos-bootloadu.conf` (systemd-boot)
- `/etc/catos/firmware-boot.conf` with `method = uki|efistub` (firmware family)

Corroborating signals (ESP layout, deployed artefacts, package presence) only
support an existing authoritative signal — they cannot establish one alone. A
leftover `EFI/CatOS/grubx64.efi` from a previous GRUB install is NOT evidence
that the current provider is GRUB if the target's `/etc` says it now uses
systemd-boot. Multiple authoritative sources surface as
`ambiguous_provider` rather than a guess.

### Target command executor

The boot-repair orchestrator is the only place that spawns target-side
binaries (`grub-install`, `mkinitcpio`, `bootctl`, `kernel-install`,
`catos-firmware-boot-update`, `catos-secureboot`, `efibootmgr`, etc.). It
replaces `libcalamares.utils.target_env_call` with a much narrower contract:

- **Fixed allow-list.** Only the binaries listed in
  `repair::boot_repair::target_exec::ALLOWED_BINARIES` may be invoked.
- **argv only.** Every argument is a separate string; there is no `sh -c`
  form, no shell expansion, no environment mutation surface.
- **Bounded output drain.** stdout/stderr are drained to EOF (verbose tools
  are not killed by SIGPIPE) but capped per stream; truncation is reported.
- **No mount cleanup.** The executor never unmounts anything; the shared target mount session owns all cleanup.

### Secure Boot

Repair **never auto-enables** Secure Boot just because the live host has it
on. The target's existing policy is the only authority:

- The target's `/etc/catos/secureboot` marker (or a signed artefact plus the
  `catos-secureboot` package) authorises re-applying the existing policy via
  `catos-secureboot enable --generate-enrollment-password --json`.
- EFI Stub is explicitly unsupported by the registry's `supportedProviders`
  list; repair refuses before invoking `catos-secureboot`.
- EFI variable writes, MOK enrollment, and signing operations are NOT
  atomic. Partial success surfaces as `partially_repaired` or
  `manual_intervention_required`, never as `repaired`.

### Outcome taxonomy

The boot-repair outcome model reuses the mount-repair shape where the
semantics match and adds boot-specific variants where they do not:

| Outcome | Meaning |
|---|---|
| `clean` | Bootloader already installed and verified; no command needed. |
| `repaired` | Provider recipe re-applied end to end; verify passed. |
| `partially_repaired` | Some steps completed but external side effects cannot be cleanly reverted. |
| `unsupported` | Target platform not supported by the detected provider. |
| `ambiguous_target` | Target could not be uniquely identified (shared with mount repair). |
| `ambiguous_provider` | Bootloader provider could not be uniquely identified. |
| `verification_failed` | Provider recipe ran but verification failed. |
| `cleanup_incomplete` | Boot files written but session cleanup did not finish. |
| `manual_intervention_required` | EFI NVRAM / MOK / signature failure requiring operator action. |

### Current verification status

| Layer | Status |
|---|---|
| Provider registry + platform matrix | Implemented; covered by contract tests |
| Kernel cmdline builder + conflict detection | Implemented; covered by contract tests |
| mkinitcpio config + kernel discovery | Implemented; covered by contract tests |
| Evidence-based provider detection | Implemented; covered by contract tests |
| Fixed-allow-list target command executor | Implemented; covered by contract tests |
| GRUB recipe (UEFI x86_64/aarch64 + BIOS) | Implemented; covered by contract tests |
| Limine recipe | Implemented; covered by contract tests |
| systemd-boot recipe | Implemented; covered by contract tests |
| UKI + EFI Stub recipe (FirmwareProvider) | Implemented; covered by contract tests |
| Secure Boot finalisation (target-policy preserving) | Implemented; covered by contract tests |
| Snapshot support per provider | Implemented at the mkinitcpio layer; per-provider snapshot tool invocation is wired through the provider trait |
| Real QEMU acceptance (full matrix) | **Not yet accepted.** `scripts/boot-repair-qemu-smoke.sh` is in place but currently performs target-image construction and detection-layer verification only. A complete boot-and-reboot acceptance requires OVMF Secure Boot certificates and the full provider toolchain in CI; it is tracked as environment-missing rather than reported as passing. |

### Deliberate exclusions

Boot repair does not migrate providers (GRUB → systemd-boot, etc.), auto-select
a provider based on the live host's installed tools, open LUKS, repartition
devices, run arbitrary target commands outside the fixed allow-list, or claim
atomic rollback for EFI NVRAM / MOK / signature operations.

## `catos-doctor`

`catos-doctor` is the read-only aggregated diagnosis entry point. It takes no
functional arguments and produces a single human-readable report that
summarises every diagnostic domain the maintenance capabilities cover:

```text
catos-doctor
```

### Public surface

* **No subcommands.** `catos-doctor inspect`, `catos-doctor preflight`,
  `catos-doctor repair`, `catos-doctor fs`, `catos-doctor mount`,
  `catos-doctor boot`, `catos-doctor recovery` are all rejected with exit
  code 2 (`ARG_ERROR`).
* **No target-selection flags.** `catos-doctor --root-device`,
  `catos-doctor --root-subvolume`, `catos-doctor --esp-device`,
  `catos-doctor --root` are rejected.
* **No `--json`.** Doctor's public surface is human-readable only. The
  internal `catos-system` binary keeps a stable JSON renderer for future
  GUI/front-end consumption; the public entry point intentionally does not
  expose it.
* `--help` / `--version` work as on every other entry point.
* With interactive stdin, Doctor requests administrator privileges through an
  absolute trusted `sudo`, `sudo-rs`, `doas`, or `run0` executable before
  creating a private mount namespace. Stdout may be redirected to a report
  file without disabling this prompt. A non-interactive unprivileged invocation
  fails before diagnosis and writes no empty report to stdout.
* The terminal report adapts its table to the current terminal width, up to 78
  columns. Each diagnostic domain occupies one summary row; findings and
  actions appear only when needed. Reports longer than the current terminal
  height use a built-in pager (`Enter` advances, `q` quits), so Doctor does not
  depend on `less`, a shell, or a desktop session. Action commands may wrap
  onto aligned continuation rows but are never truncated.
* The package installs one `catos-system` binary and five role-specific
  symlinks (`catos-update`, `catos-recovery`, `catos-doctor`, `catos-repair`,
  and `catos-chroot`). All six command names resolve to the same inode.

### Exit-code semantics

`overall_status` and the process exit code are independent:

| Exit code | Meaning |
|---|---|
| `0` | Doctor selected a target, completed the diagnosis, and cleaned up its resources. The target may still be degraded, unhealthy, critical, or partially unknown; severity remains in the report. |
| `4` | Administrator privileges were unavailable before diagnosis. |
| `5` | No unique target was selected, the private namespace or target session could not be established, or Doctor cleanup was incomplete. |
| other non-zero | Argument, serialisation, or output failure. |

Target health does not change a completed Doctor invocation into a process
failure. Filesystem corruption, a broken fstab, an interrupted recovery
transaction, a missing optional read-only tool, or an ambiguous boot provider
remain report findings and return 0 after a target was selected. By contrast,
missing/ambiguous target selection is an invocation failure because no target
was diagnosed.

### Diagnostic sections

The report aggregates seven sections, in canonical order:

1. **Environment** — runtime primary mode and running-root-is-Catos flag.
2. **Storage** — discovered root and ESP device paths.
3. **Filesystem** — read-only fsck result via the `check_only_for` family
   (`e2fsck -n`, `fsck.fat -n`, `fsck.f2fs --dry-run`, `xfs_repair -n`,
   `btrfs check --readonly`). Doctor NEVER invokes `-y`, `-a`, `--repair`,
   or `-L`.
4. **Mount layout** — fstab, root source/subvolume, CatOS standard
   subvolumes, ESP, and the six `/boot`/ESP layouts. Reuses the same
   pure `repair::mount_repair::diagnose` that `catos-repair mount` uses.
5. **Boot** — provider detection reusing
   `repair::boot_repair::detect::detect` (GRUB, Limine, systemd-boot,
   UKI, EFI Stub). Doctor never invokes the provider's `execute` or
   `verify` methods.
6. **Secure Boot** — consistency between firmware runtime state, the
   target's `/etc/catos/secureboot` policy marker, and the
   firmware-boot configuration. Doctor never enrolls, disables, or
   signs.
7. **Recovery** — read-only enumeration of in-flight Btrfs snapshot
   transactions. Uses `Engine::load` + `reconcile_status` (both
   read-only). Doctor never calls `Engine::drive`, `Engine::begin`,
   `Engine::load_for_write`, `Engine::load_for_revert`, or
   `store::persist_record`.

### Overall status

`healthy` | `degraded` | `unhealthy` | `critical` | `unknown`. The
aggregation is conservative: a single critical section promotes the
overall to critical; a single unhealthy section promotes it to
unhealthy; limitations alone degrade an otherwise-healthy report.

### Read-only boundary

Doctor never writes to the target. The only resources it may clean up
are mounts it created itself inside its private mount namespace
(`DoctorCleanup`). The QEMU acceptance test
(`scripts/doctor-qemu-smoke.sh`) verifies this by `sha256`-hashing
each target image before and after a `catos-doctor` run; any hash
mismatch is a hard failure.

### Issue codes

Stable uppercase symbolic codes are emitted for every issue
(`FS_CORRUPTION_DETECTED`, `FSTAB_ROOT_SOURCE_MISMATCH`,
`STANDARD_SUBVOLUME_MISSING`, `ESP_AMBIGUOUS`,
`BOOT_PROVIDER_AMBIGUOUS`, `BOOT_PROVIDER_CONFLICT`,
`SECURE_BOOT_STATE_INCOMPLETE`, `RECOVERY_TRANSACTION_INTERRUPTED`,
`RECOVERY_RECORD_DRIFT`, `RECOVERY_CLEANUP_RESIDUAL`,
`RECOVERY_BACKUP_PRESENT`, `TARGET_NOT_FOUND`, `TARGET_AMBIGUOUS`,
...). Recommendations carry their own stable codes
(`RUN_CATOS_REPAIR_FS`, `RUN_CATOS_REPAIR_MOUNT`,
`RUN_CATOS_REPAIR_BOOT`, `RUN_CATOS_RECOVERY_RESUME`,
`RUN_CATOS_RECOVERY_REVERT`, `BOOT_LIVE_ENVIRONMENT`,
`MANUAL_REVIEW`).

## What is not implemented yet

- AUR-helper, Flatpak, distribution-news, and desktop notification integration
  for `catos-update`.
- Automatic deletion of recovery backups; they remain available for revert or
  explicit operator removal.
- Complete boot-and-reboot QEMU acceptance for every provider/firmware
  combination. The full matrix needs OVMF Secure Boot certificates and the
  provider toolchain in CI.
- A graphical frontend and long-running maintenance daemon. The shipped
  interface is the command line plus its line-oriented interactive menus.

## Deliberate exclusions

- a bundled static pacman/libalpm replacement
- an independent repository database, package solver, keyring, or package
  repair runtime
- arbitrary or unconfined target command execution; Chroot and boot repair use
  fixed, audited workflows
- formatting, partition-table editing, automatic fsck, LVM, or mdraid repair
