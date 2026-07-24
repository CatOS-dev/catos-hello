# catos-system

Read-only system backend for CatOS. A single static musl binary installed at
`/usr/lib/catos/catos-system`, exposed through three multicall symlinks:

```
/usr/bin/catos-update   -> ../lib/catos/catos-system
/usr/bin/catos-recovery -> ../lib/catos/catos-system
/usr/bin/catos-doctor   -> ../lib/catos/catos-system
```

All three symlinks point to the same inode. There is exactly one binary
target. `argv[0]` is honoured only for the JSON `invocation` field and for
help text; it never gates a permission.

## Phase 1 scope

This is **phase 1** only. The program performs read-only probes and reports
structured results. It does **not**:

- discover block devices
- mount or unmount filesystems
- unlock LUKS devices
- detect or manipulate Btrfs subvolumes
- perform pacman updates
- create or roll back snapshots
- repair bootloaders (GRUB / Limine / UKI)
- modify the target root in any way
- run as a long-lived daemon
- expose a TUI

Even when invoked as root the program performs **only read operations**.

## CLI

```
catos-system environment [--root PATH] [--json]
catos-system capabilities [--root PATH] [--json]
catos-system inspect     [--root PATH] [--json]
catos-system --version
catos-system --help
```

The three symlinks accept the same subcommands and use the same probe core.
The selected subcommand controls which report sections are rendered:

- `environment`: runtime facts only
- `capabilities`: capability results only
- `inspect`: runtime, capabilities, and target inspection

```
catos-doctor inspect --json
catos-recovery environment --json
catos-update capabilities --json
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
     | `mkinitcpio_present_in_target` | `bootloadu_present_in_target`
     | `btrfs_tool_available` | `cryptsetup_available` | `lsblk_available`
     | `mount_tool_available`
4. `unknown` is never serialised as `false` or `null`. It is always the
   literal string `"unknown"`. Consumers MUST NOT treat it as a boolean.
5. Adding fields to nested objects is allowed and is considered
   backward-compatible. Consumers MUST ignore unknown fields.
6. JSON output never contains ANSI colour escapes, log lines, or progress
   text. Errors are written to stderr; stdout in `--json` mode is pure JSON.
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
  system_root.rs     validated display/canonical target-root paths
  model/             pure data + serde; no I/O
    evidence.rs        Evidence: code/source/message/value
    runtime.rs         Detection, DetectionStatus, RuntimeFacts, PrimaryRuntimeMode
    capability.rs      Capability, CapabilityKind, CapabilityStatus
    inspection.rs      TargetInspection, OsRelease, ToolPath, Warning, InspectionReport
  probe/             reads the world via FilesystemProbe trait
    fs_probe.rs        filesystem abstraction + confined target-root access
    runtime.rs         detect_runtime + six detectors (initramfs/chroot/live/snapshot/systemd/ro)
    target.rs          inspect_target + os-release parsing + tool probes
    capability.rs      detect_capabilities (16 phase-1 capabilities)
  output/            renders model
    human.rs           plain ASCII human output
    json.rs            serde_json wrapper (single source of JSON contract)
```

Layering rules:

- `probe/*` returns structured models. It never prints.
- `output/*` consumes models. It never probes.
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

Three surfaces, all wired into CTest when `-DBUILD_TESTS=ON`:

| Test                              | What it guards against                                |
|-----------------------------------|-------------------------------------------------------|
| `catos-system-cargo-test`         | Rust unit + integration (108 tests at this revision). Includes probe fixtures simulating initramfs, chroot, LiveCD, container, snapshot, capability and permission states; target-root path and symlink confinement; CLI exit codes; JSON purity; multicall single-inode invariant. |
| `catos-system-static-check`       | The musl binary silently regressing to dynamic linking (would break initramfs and recovery use). |
| `catos-system-initramfs-smoke-bare` | The static binary refusing to start in a minimal Linux user space without systemd, dbus, network, or `/usr`. |
| `catos-system-initramfs-smoke-with-marker` | Runtime detection failing to identify a mkinitcpio-style initramfs containing `/etc/initrd-release`. |

The two QEMU tests are opt-in through
`-DCATOS_SYSTEM_INITRAMFS_SMOKE=ON`. They require
`qemu-system-x86_64`, a kernel image, and static `busybox`; they use KVM when
available, otherwise TCG, and skip with exit code 77 when prerequisites are
missing.

Run them:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
( cd build && ctest --output-on-failure )
```

To explicitly run the opt-in initramfs/QEMU smoke:

```
cmake -S . -B build -DBUILD_TESTS=ON -DCATOS_SYSTEM_INITRAMFS_SMOKE=ON
( cd build && ctest -R initramfs --output-on-failure )
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
467512
$ file <binary>
... static-pie linked ... stripped
$ readelf -l <binary> | grep INTERP     # (empty)
$ readelf -d <binary> | grep NEEDED     # (empty)
```

## What is NOT implemented (deferred to later phases)

- Block device discovery (`lsblk` integration, sysfs walk)
- Filesystem mount/unmount
- LUKS unlock (`cryptsetup` integration)
- Btrfs subvolume enumeration and snapshot rollback
- pacman-driven update workflow
- Bootloader repair (GRUB, Limine, UKI regeneration via `mkinitcpio`,
  `bootloadu`)
- A transaction state machine with rollback semantics
- A TUI / interactive UI
- A long-running daemon
- Network operations of any kind
