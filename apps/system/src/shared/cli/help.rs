use crate::shared::error::exit_code;

pub fn help_text() -> String {
    format!(
        "\
catos-system {version} - CatOS mount and boot recovery backend

USAGE:
    catos-system <SUBCOMMAND> [OPTIONS]

FOUNDATION SUBCOMMANDS (read-only environment + target inspection):
    environment   Print detected runtime environment facts.
    capabilities  Print detected capabilities (read-only).
    inspect       Print combined runtime + capabilities + target inspection.

SAFE-MOUNT SUBCOMMANDS (read-only discovery + temporary target mount):
    storage scan  Walk sysfs + blkid + mountinfo; emit a StorageReport.
                  Pure read. No mounts, no writes.
    target plan   Read --root's /etc/fstab + discover devices; emit a
                  MountPlan WITHOUT executing any mount.
    target mount  Same as 'target plan' then execute the plan in a private
                  mount namespace (read-only mounts only).

SNAPSHOT-RECOVERY SUBCOMMANDS (transactional Btrfs root recovery):
    recovery list     List existing transactions on the configured root.
    recovery inspect  Read-only: show filesystem + current-root + snapshot
                      identity and the source-snapshot boot layout.
    recovery plan     Read-only: emit an immutable RecoveryPlan bound to a
                      plan id and confirmation token. Does NOT write.
    recovery apply    Execute the plan: mount the btrfs toplevel rw, run the
                      state machine, swap roots via renameat2(RENAME_EXCHANGE).
                      Does NOT touch the bootloader or the ESP. Requires
                      --plan-id and --confirm. Must run as root.
    recovery status   Read the transaction record, reconcile with disk facts,
                      emit a RecoveryStatusReport.
    recovery resume   Continue an in-flight transaction from its last
                      persisted state. Idempotent. Must run as root.
    recovery revert   Swap the roots back to the pre-recovery state.
                      Requires --confirm. Must run as root.

OPTIONS:
    --root PATH   Inspect a different target root (default: /).
                  PATH must be an absolute path to an existing directory.
    --root-device /dev/...
                  Explicit root block device for an unmounted target.
    --root-subvolume PATH
                  Explicit Btrfs root subvolume (requires --root-device).
    --esp-device /dev/...
                  Override the EFI System Partition for the target plan.
    --snapshot-subvolume PATH
                  Explicit source readonly snapshot (phase 3 inspect/plan).
    --plan-id <id>
                  Plan id (phase 3 apply).
    --confirm <token>
                  Confirmation token bound to the plan (phase 3 apply, revert).
    --transaction <id>
                  Transaction id (phase 3 status, resume, revert).
    --json        Emit a stable JSON report on stdout instead of human text.
    -h, --help    Show this help message and exit.
    -V, --version Print program version and exit.

EXIT CODES:
    {ok}   success
    {arg}   argument error
    {root} target root invalid (does not exist, not a directory, etc.)
    {perm} permission denied reading a critical path
    {probe} environment probe could not produce a report
    {ser}  JSON serialisation failed

NOTES:
    * Phases 1 and 2 are read-only with respect to the target device:
      environment/capabilities/inspection probes never mount, and
      'target mount' uses read-only filesystem-specific safety options
      (ext4 noload, xfs norecovery, btrfs rescue=nologreplay, ...) so
      journal replay and superblock updates are suppressed.
    * In the current implementation, recovery apply/resume/revert is the
      only target write path. The writes are bounded to the
      btrfs top-level, transactional, crash-resumable, and require
      --plan-id + --confirm (--transaction + --confirm for revert).
      Snapshot recovery never touches the ESP, the bootloader, /boot,
      initramfs images, or firmware entries.
    * 'target mount' enters a private mount namespace (CLONE_NEWNS) and
      flips / to MS_REC|MS_PRIVATE so its mounts do NOT propagate to
      the host. Pre-existing mounts are never unmounted.
    * Phase 2 mounts are read-only with filesystem-specific safety options
      (ext4 noload, xfs norecovery, btrfs rescue=nologreplay, etc.) so journal replay
      and superblock updates are suppressed.
    * Public entry points share this binary:
      catos-doctor  runs the diagnosis with no arguments;
      catos-recovery handles Btrfs snapshot recovery;
      catos-repair is the fs/mount/boot repair entry point;
      catos-update is retained as a separate entry point.
    * catos-doctor has no inspect or preflight subcommands.
",
        version = crate::PROGRAM_VERSION,
        ok = exit_code::SUCCESS,
        arg = exit_code::ARG_ERROR,
        root = exit_code::INVALID_ROOT,
        perm = exit_code::PERMISSION_DENIED,
        probe = exit_code::PROBE_FAILED,
        ser = exit_code::SERIALIZE_FAILED,
    )
}

pub fn version_text() -> String {
    format!("catos-system {}\n", crate::PROGRAM_VERSION)
}
