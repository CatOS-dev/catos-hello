//! Trusted btrfs-progs invocations.
//!
//! All external invocations go through [`crate::shared::process::run_trusted_tool`]:
//!
//! * Fixed trusted path resolution (no `PATH` lookup).
//! * Minimal environment.
//! * Parameter array (no shell, no `sh -c`).
//! * Bounded stdout/stderr.
//! * Timeout.
//! * Proper kill + wait.
//!
//! This read-only module adds Btrfs-specific parsing on top of those
//! guarantees. Mutation commands are exposed only by `snapshot::execute`.
//!
//! Subcommand allow-list:
//!
//! * `btrfs filesystem show <dev>`           — read FSID, label, device list.
//! * `btrfs subvolume show <path>`           — read subvolid, generation, readonly.
//! * `btrfs subvolume list -rg <path>`       — enumerate readonly subvolumes.
//! * `btrfs subvolume get-default <path>`    — read the default subvolid.
//!
//! Phase 3 NEVER runs:
//!
//! * `btrfs subvolume delete` — the original root is preserved as
//!   backup. Cleanup is the operator's responsibility.
//! * `btrfs balance` / `btrfs device add` / `btrfs device remove` /
//!   `btrfs scrub` — out of scope.
//! * `btrfs restore` / `btrfs check --repair` — too dangerous to run
//!   from a recovery tool without operator review.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::mount::diagnose::fstab::{self, FstabEntry, FstabEntryKind, FstabSource};
use crate::mount::execute::secure_dir::SESSION_ROOT_PARENT;
use crate::mount::plan::session::build_probe_plan;
use crate::mount::session::ReadOnlyMountSession;
use crate::shared::model::evidence::Evidence;
use crate::shared::process::{run_trusted_tool, ToolOutput};
use crate::snapshot::diagnose::identity::{
    canonical_block_identity, validate_mounted_filesystem, SubvolumePath,
};
use crate::snapshot::model::{
    BootConsistencyReport, BootLayout, BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity,
    CatosIdentity, FstabRootDefinition, SnapshotError, SnapshotErrorKind, SubvolumeFacts,
};
use crate::target::execute::confined;

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Filesystem identity
// ---------------------------------------------------------------------------

/// Read the btrfs filesystem identity for the block device that backs
/// `mounted_top_level`. The argument MUST be a path inside a mounted
/// btrfs filesystem (typically the toplevel mounted at `subvolid=5`).
///
/// We run `btrfs filesystem show <mountpoint>` and parse the FSID +
/// device list. `device_major_minor` is filled in by the caller from
/// `/sys/class/block/<name>/dev` since btrfs-progs does not emit the
/// `major:minor` form.
pub fn show_filesystem(mount_point: &Path) -> Result<BtrfsFilesystemIdentity, SnapshotError> {
    let mount_str = path_to_str(mount_point)?;
    let output = run("filesystem", &["show", mount_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fsid = None;
    let mut label: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        // The first line of `btrfs filesystem show` is:
        //   Label: 'catos-root'  uuid: <uuid>
        // or
        //   Label: none  uuid: <uuid>
        // Both fields can live on the same line; we scan the whole
        // line for each token rather than relying on a strict prefix.
        if let Some(rest) = trimmed.strip_prefix("Label: ") {
            let raw = rest.split_whitespace().next().unwrap_or("none");
            if raw != "none" {
                label = Some(raw.trim_matches('\'').to_string());
            }
        }
        if let Some(idx) = trimmed.find("uuid:") {
            let after = &trimmed[idx + "uuid:".len()..];
            let value = after.split_whitespace().next().unwrap_or("");
            if !value.is_empty() {
                fsid = Some(value.to_string());
            }
        }
    }
    let fsid = fsid.ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!(
                "btrfs filesystem show {} did not contain a uuid line; output:\n{}",
                mount_point.display(),
                text
            ),
        )
    })?;
    Ok(BtrfsFilesystemIdentity {
        fsid,
        device_major_minor: String::new(),
        label,
    })
}

/// Return every concrete device path reported for the mounted btrfs
/// filesystem. Phase 3 currently requires exactly one device so its
/// target identity can be represented by one stable major:minor pair.
pub fn filesystem_devices(mount_point: &Path) -> Result<Vec<String>, SnapshotError> {
    let mount_str = path_to_str(mount_point)?;
    let output = run("filesystem", &["show", mount_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("devid ") {
            continue;
        }
        let Some(index) = trimmed.find(" path ") else {
            continue;
        };
        let path = trimmed[index + " path ".len()..].trim();
        if !path.is_empty() && path != "missing" {
            devices.push(path.to_string());
        }
    }
    if devices.is_empty() {
        return Err(SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!(
                "btrfs filesystem show {} did not report any device path",
                mount_point.display()
            ),
        ));
    }
    devices.sort();
    devices.dedup();
    Ok(devices)
}

// ---------------------------------------------------------------------------
// Subvolume identity
// ---------------------------------------------------------------------------

/// Read the btrfs subvolume identity for `mounted_path`. The argument
/// MUST be a subvolume path inside a mounted btrfs filesystem.
pub fn show_subvolume(mounted_path: &Path) -> Result<BtrfsSubvolumeIdentity, SnapshotError> {
    let path_str = path_to_str(mounted_path)?;
    let output = run("subvolume", &["show", path_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut btrfs_relative_path: Option<String> = None;
    let mut subvolume_id: Option<u64> = None;
    let mut generation: Option<u64> = None;
    let mut read_only = false;
    let mut uuid: Option<String> = None;
    let mut parent_uuid: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        // The first non-empty line is the btrfs-relative path of the
        // subvolume (e.g. `@` or `@/.snapshots/1/snapshot`). btrfs-progs
        // emits it relative to the FS top-level, NOT including a
        // leading slash; we normalise to `/...` here so callers can
        // treat it as absolute-within-the-filesystem.
        if btrfs_relative_path.is_none() && !trimmed.is_empty() {
            let normalised = if trimmed.starts_with('/') {
                trimmed.to_string()
            } else {
                format!("/{trimmed}")
            };
            btrfs_relative_path = Some(normalised);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Subvolume ID:") {
            subvolume_id = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("Generation:") {
            generation = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("UUID:") {
            let v = rest.trim();
            if !v.is_empty() && !v.eq_ignore_ascii_case("none") {
                uuid = Some(v.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("Parent UUID:") {
            let v = rest.trim();
            if !v.is_empty() && !v.eq_ignore_ascii_case("none") {
                parent_uuid = Some(v.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("Flags:") {
            // `Flags: readonly` in modern btrfs-progs.
            if rest.contains("readonly") {
                read_only = true;
            }
        }
    }
    let subvolume_id = subvolume_id.ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!(
                "subvolume show did not contain a Subvolume ID line; output:\n{}",
                text
            ),
        )
    })?;
    let generation = generation.unwrap_or(0);
    let path = btrfs_relative_path.unwrap_or_else(|| path_str.to_string());
    // btrfs-progs did not always emit a UUID line. If it is present
    // we surface it via the evidence vector so callers (and tests)
    // can read it without changing the struct shape.
    let mut evidence = vec![Evidence::new(
        "BTRFS_SUBVOLUME_SHOW",
        "btrfs",
        "identity read from btrfs-progs",
    )];
    if let Some(ref u) = uuid {
        evidence.push(Evidence::new(
            "BTRFS_SUBVOLUME_UUID",
            "btrfs",
            format!("uuid={u}"),
        ));
    }
    if let Some(ref p) = parent_uuid {
        evidence.push(Evidence::new(
            "BTRFS_SUBVOLUME_PARENT_UUID",
            "btrfs",
            format!("parent_uuid={p}"),
        ));
    }
    Ok(BtrfsSubvolumeIdentity {
        path,
        subvolume_id,
        generation,
        uuid,
        parent_uuid,
        read_only,
        evidence,
    })
}

/// Read the btrfs subvolume identity for `mounted_path` and return it
/// as a [`SubvolumeFacts`] (richer than [`BtrfsSubvolumeIdentity`]).
/// Used by the engine when observing disk facts; the engine stores
/// the facts in the transaction record so resume / status can reason
/// about identity drift.
//
// Returns `Box<SnapshotError>`: the only caller is
// `engine::observe_disk_facts`, which immediately calls `.ok()` and
// discards the error. Boxing here keeps the result small and silences
// clippy's large-result lint without weakening structured error info
// (the boxed error is never inspected).
pub fn probe_subvolume_facts(mounted_path: &Path) -> Result<SubvolumeFacts, Box<SnapshotError>> {
    let identity = show_subvolume(mounted_path).map_err(Box::new)?;
    Ok(SubvolumeFacts {
        path: identity.path,
        subvolume_id: Some(identity.subvolume_id),
        generation: Some(identity.generation),
        uuid: identity.uuid,
        parent_uuid: identity.parent_uuid,
        read_only: Some(identity.read_only),
    })
}

/// Enumerate the readonly subvolumes of `mounted_top_level`. The
/// returned list is in the same shape `btrfs subvolume list -R` emits:
/// `<id> gen <g> top level <parent> path <relative>`.
pub fn list_readonly_subvolumes(
    mounted_top_level: &Path,
) -> Result<Vec<BtrfsSubvolumeIdentity>, SnapshotError> {
    let path_str = path_to_str(mounted_top_level)?;
    let output = run("subvolume", &["list", "-r", path_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Format: `ID 257 gen 10 top level 5 ogen 8 uuid ... path @/.snapshots/1/snapshot`
        let mut subvolume_id = None;
        let mut generation = None;
        let mut path = String::new();
        let mut tokens = trimmed.split_whitespace().peekable();
        while let Some(tok) = tokens.next() {
            match tok {
                "ID" => {
                    if let Some(next) = tokens.next() {
                        subvolume_id = next.parse().ok();
                    }
                }
                "gen" => {
                    if let Some(next) = tokens.next() {
                        generation = next.parse().ok();
                    }
                }
                "path" => {
                    path = tokens.collect::<Vec<_>>().join(" ");
                    break;
                }
                _ => {}
            }
        }
        let Some(subvolume_id) = subvolume_id else {
            continue;
        };
        let normalised = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        out.push(BtrfsSubvolumeIdentity {
            path: normalised,
            subvolume_id,
            generation: generation.unwrap_or(0),
            uuid: None,
            parent_uuid: None,
            read_only: true,
            evidence: vec![Evidence::new(
                "BTRFS_SUBVOLUME_LIST_RO",
                "btrfs",
                "readonly subvolume reported by btrfs-progs",
            )],
        });
    }
    Ok(out)
}

/// Enumerate every subvolume together with the identity fields emitted
/// by `btrfs subvolume list -u -q`. The readonly flag is not available
/// in this listing and is therefore left false; callers that select a
/// concrete source/root must refresh it with [`show_subvolume`].
pub fn list_subvolumes(
    mounted_top_level: &Path,
) -> Result<Vec<BtrfsSubvolumeIdentity>, SnapshotError> {
    let path_str = path_to_str(mounted_top_level)?;
    let output = run("subvolume", &["list", "-u", "-q", path_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut subvolume_id = None;
        let mut generation = None;
        let mut uuid = None;
        let mut parent_uuid = None;
        let mut path = None;
        let mut tokens = trimmed.split_whitespace();
        while let Some(token) = tokens.next() {
            match token {
                "ID" => subvolume_id = tokens.next().and_then(|value| value.parse().ok()),
                "gen" => generation = tokens.next().and_then(|value| value.parse().ok()),
                "uuid" => {
                    uuid = tokens.next().and_then(non_dash_value);
                }
                "parent_uuid" => {
                    parent_uuid = tokens.next().and_then(non_dash_value);
                }
                "path" => {
                    path = Some(tokens.collect::<Vec<_>>().join(" "));
                    break;
                }
                _ => {}
            }
        }
        let (Some(subvolume_id), Some(path)) = (subvolume_id, path) else {
            continue;
        };
        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        out.push(BtrfsSubvolumeIdentity {
            path,
            subvolume_id,
            generation: generation.unwrap_or(0),
            uuid,
            parent_uuid,
            read_only: false,
            evidence: vec![Evidence::new(
                "BTRFS_SUBVOLUME_LIST",
                "btrfs",
                "subvolume identity reported by btrfs-progs",
            )],
        });
    }
    Ok(out)
}

/// Return the configured default subvolume path. `/` denotes the btrfs
/// top-level (ID 5), which is not silently treated as a root candidate.
pub fn default_subvolume_path(mounted_top_level: &Path) -> Result<Option<String>, SnapshotError> {
    let path_str = path_to_str(mounted_top_level)?;
    let output = run("subvolume", &["get-default", path_str.as_str()])?;
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("FS_TREE") {
        return Ok(Some("/".into()));
    }
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let Some(path_index) = tokens.iter().position(|token| *token == "path") else {
        return Ok(None);
    };
    let raw = tokens[path_index + 1..].join(" ");
    if raw.is_empty() {
        return Ok(None);
    }
    Ok(Some(if raw.starts_with('/') {
        raw
    } else {
        format!("/{raw}")
    }))
}

fn non_dash_value(value: &str) -> Option<String> {
    if value == "-" || value.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn run(subcommand: &str, args: &[&str]) -> Result<ToolOutput, SnapshotError> {
    // Validate the subcommand against the strict allow-list so a code
    // bug cannot accidentally invoke, e.g., `btrfs subvolume delete`.
    match subcommand {
        "filesystem" | "subvolume" | "property" => {}
        other => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::BtrfsToolFailed,
                format!("refusing to invoke btrfs subcommand {other:?}; not in allow-list"),
            ));
        }
    }
    let mut full_args = vec![subcommand];
    full_args.extend_from_slice(args);
    let full_args_ref: Vec<&str> = full_args.to_vec();
    let output = run_trusted_tool(
        "btrfs",
        &full_args_ref,
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        MAX_OUTPUT_BYTES,
    )
    .map_err(|message| {
        let mut err = SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!("btrfs {} failed: {}", subcommand, message),
        );
        err.failed_step = Some(format!("btrfs-{}", subcommand));
        err
    })?;
    if !output.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(SnapshotError {
            kind: SnapshotErrorKind::BtrfsToolFailed,
            message: format!(
                "btrfs {} exited non-zero (rc={}): stdout={:?} stderr={:?}",
                subcommand,
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            )
            .into(),
            transaction_id: None,
            current_state: None,
            failed_step: Some(format!("btrfs-{}", subcommand)),
            errno: None,
            external_exit_code: output.status.code(),
            completed_steps: Box::default(),
            disk_facts: None,
            resume_possible: true,
            revert_possible: true,
            manual_intervention_required: false,
            record_persistence_error: None,
        });
    }
    Ok(output)
}

fn path_to_str(path: &Path) -> Result<String, SnapshotError> {
    path.to_str().map(|s| s.to_string()).ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!("path {} is not valid UTF-8", path.display()),
        )
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_filesystem_parses_uuid_and_label() {
        let body = b"Label: 'catos-root'  uuid: 3bdc66e2-f30b-4ef1-97f0-c687934e25e2\n\tTotal devices 1 FS bytes used 1234\n\tdevid    1 size 100G used 5G path /dev/vdc\n";
        let text = String::from_utf8_lossy(body);
        let mut fsid = None;
        let mut label: Option<String> = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Label: ") {
                let raw = rest.split_whitespace().next().unwrap_or("none");
                if raw != "none" {
                    label = Some(raw.trim_matches('\'').to_string());
                }
            }
            if let Some(idx) = trimmed.find("uuid:") {
                let after = &trimmed[idx + "uuid:".len()..];
                let value = after.split_whitespace().next().unwrap_or("");
                if !value.is_empty() {
                    fsid = Some(value.to_string());
                }
            }
        }
        assert_eq!(
            fsid.as_deref(),
            Some("3bdc66e2-f30b-4ef1-97f0-c687934e25e2")
        );
        assert_eq!(label.as_deref(), Some("catos-root"));
    }

    #[test]
    fn list_subvolumes_parses_realistic_output() {
        let body = b"ID 257 gen 12 top level 5 uuid ... path @\nID 258 gen 13 top level 5 uuid ... path @home\nID 300 gen 11 top level 257 uuid ... path @/.snapshots/1/snapshot\n";
        let text = String::from_utf8_lossy(body);
        let mut found = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut id = None;
            let mut gen = None;
            let mut path = String::new();
            let mut tokens = trimmed.split_whitespace().peekable();
            while let Some(tok) = tokens.next() {
                match tok {
                    "ID" => {
                        if let Some(next) = tokens.next() {
                            id = next.parse().ok();
                        }
                    }
                    "gen" => {
                        if let Some(next) = tokens.next() {
                            gen = next.parse().ok();
                        }
                    }
                    "path" => {
                        path = tokens.collect::<Vec<_>>().join(" ");
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(id) = id {
                found.push((id, gen.unwrap_or(0), path));
            }
        }
        assert_eq!(found[0], (257u64, 12u64, "@".to_string()));
        assert_eq!(found[1], (258u64, 13u64, "@home".to_string()));
        assert_eq!(
            found[2],
            (300u64, 11u64, "@/.snapshots/1/snapshot".to_string())
        );
    }

    #[test]
    fn run_rejects_off_list_subcommand() {
        // The allow-list keeps a code bug from invoking `btrfs
        // subvolume delete` accidentally.
        let err = run("balance", &[]).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::BtrfsToolFailed);
        assert!(err.message.contains("balance"));
    }
}

// ---------------------------------------------------------------------------
// Read-only target snapshot diagnosis
// ---------------------------------------------------------------------------

pub struct TargetProbe {
    pub canonical_device: PathBuf,
    pub filesystem: BtrfsFilesystemIdentity,
    pub current_root: BtrfsSubvolumeIdentity,
    pub snapshot: BtrfsSubvolumeIdentity,
    pub boot_layout: BootLayout,
    pub boot_consistency: BootConsistencyReport,
    pub catos_identity: Option<CatosIdentity>,
    pub fstab_root_definition: FstabRootDefinition,
}

pub fn probe_target_readonly(
    device: &Path,
    root_subvolume: Option<&str>,
    snapshot_subvolume: Option<&str>,
) -> Result<TargetProbe, SnapshotError> {
    let snapshot_btrfs_path = snapshot_subvolume
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "--snapshot-subvolume is required; no snapshot path is inferred",
            )
        })?;
    SubvolumePath::parse(snapshot_btrfs_path)?;
    let (canonical_device, _) = canonical_block_identity(device)?;

    let session_root =
        PathBuf::from(SESSION_ROOT_PARENT).join(format!("recovery-ro-{}", std::process::id()));
    let source = canonical_device.to_str().ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| SnapshotError::new(SnapshotErrorKind::SyscallFailed, error.to_string()))?;
    let id = format!("recovery-ro-{}", std::process::id());
    let mut session = ReadOnlyMountSession::new(id, &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        let mut recovery_error = SnapshotError::new(
            SnapshotErrorKind::SyscallFailed,
            format!("cannot mount target read-only: {error}"),
        );
        recovery_error.failed_step = Some("probe-mount".into());
        recovery_error
    })?;

    let result = (|| {
        let top_level = &mounted.target_root;
        let target = validate_mounted_filesystem(top_level, &canonical_device)?;
        let filesystem = target.filesystem;

        let all_subvolumes = list_subvolumes(top_level)?;
        let default_subvolume = default_subvolume_path(top_level)?;
        let (root_candidates, self_describing_fstab) =
            discover_root_candidates(top_level, &all_subvolumes)?;
        let candidates_for_selection = if root_subvolume.is_some() {
            all_subvolumes.as_slice()
        } else {
            root_candidates.as_slice()
        };
        let selected_root = select_root_subvolume(
            root_subvolume,
            self_describing_fstab.as_ref(),
            default_subvolume.as_deref(),
            candidates_for_selection,
        )?;

        let mut current_root =
            show_subvolume(&top_level.join(selected_root.trim_start_matches('/')))?;
        current_root.path = selected_root.clone();
        if current_root.read_only {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                format!("selected root subvolume {selected_root} is readonly"),
            ));
        }

        let mut snapshot_identity =
            show_subvolume(&top_level.join(snapshot_btrfs_path.trim_start_matches('/')))?;
        snapshot_identity.path = snapshot_btrfs_path.to_string();
        let fstab_root_definition =
            read_fstab_root(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                SnapshotError::new(
                    SnapshotErrorKind::AmbiguousTarget,
                    format!(
                        "source snapshot {snapshot_btrfs_path} has no parseable /etc/fstab root entry"
                    ),
                )
            })?;

        let snapshot_root = top_level.join(snapshot_btrfs_path.trim_start_matches('/'));
        let snapshot_fstab =
            read_fstab_entries(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                SnapshotError::new(
                    SnapshotErrorKind::BootConsistencyUnknown,
                    format!("source snapshot {snapshot_btrfs_path} has no /etc/fstab"),
                )
            })?;
        let boot_layout =
            crate::snapshot::diagnose::boot::detect_layout(&snapshot_root, &snapshot_fstab);
        let boot_consistency =
            crate::snapshot::diagnose::boot::evaluate_readonly_consistency(&boot_layout);
        let catos_identity = read_catos_identity(top_level, snapshot_btrfs_path);

        Ok(TargetProbe {
            canonical_device: canonical_device.clone(),
            filesystem,
            current_root,
            snapshot: snapshot_identity,
            boot_layout,
            boot_consistency,
            catos_identity,
            fstab_root_definition,
        })
    })();

    let cleanup = session.cleanup();
    if !cleanup.all_clean {
        return Err(SnapshotError::new(
            SnapshotErrorKind::CleanupIncomplete,
            format!(
                "read-only target probe left residual mounts: {:?}; directory cleanup: {:?}",
                cleanup.residual, cleanup.directory_cleanup_error
            ),
        ));
    }
    result
}

fn read_catos_identity(top_level: &Path, subvolume: &str) -> Option<CatosIdentity> {
    let body = confined::read_rooted_file(top_level, &rooted_join(subvolume, "/etc/os-release"))
        .or_else(|_| {
            confined::read_rooted_file(top_level, &rooted_join(subvolume, "/usr/lib/os-release"))
        })
        .ok()?;
    let body = String::from_utf8(body).ok()?;
    let mut out = CatosIdentity::default();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches('"');
        match key {
            "NAME" => out.name = Some(value.into()),
            "ID" => out.id = Some(value.into()),
            "VERSION_ID" => out.version = Some(value.into()),
            "PRETTY_NAME" => out.pretty_name = Some(value.into()),
            _ => {}
        }
    }
    Some(out)
}

pub fn read_fstab_root(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<FstabRootDefinition>, SnapshotError> {
    let path = rooted_join(subvolume, "/etc/fstab");
    let Some(entries) = read_fstab_entries(top_level, subvolume)? else {
        return Ok(None);
    };
    let roots: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.kind == FstabEntryKind::Root)
        .collect();
    match roots.len() {
        0 => Ok(None),
        1 => {
            let root = &roots[0];
            Ok(Some(FstabRootDefinition {
                source: fstab_source_string(&root.source),
                fstype: root.fstype.clone(),
                options: root.options.clone(),
            }))
        }
        count => Err(SnapshotError::new(
            SnapshotErrorKind::AmbiguousTarget,
            format!("{path} contains {count} root entries"),
        )),
    }
}

fn read_fstab_entries(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<Vec<FstabEntry>>, SnapshotError> {
    let path = rooted_join(subvolume, "/etc/fstab");
    let bytes = match confined::read_rooted_file(top_level, &path) {
        Ok(bytes) => bytes,
        Err(crate::shared::error::FsError::NotFound) => return Ok(None),
        Err(error) => return Err(crate::snapshot::model::fs_to_snapshot(error)),
    };
    let body = String::from_utf8(bytes).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::AmbiguousTarget,
            format!("{path} is not valid UTF-8: {error}"),
        )
    })?;
    let (entries, diagnostics) = fstab::parse_all_with_diagnostics(&body);
    if !diagnostics.is_empty() {
        return Err(SnapshotError::new(
            SnapshotErrorKind::AmbiguousTarget,
            format!("{path} contains malformed fstab lines: {diagnostics:?}"),
        ));
    }
    Ok(Some(entries))
}

fn fstab_source_string(source: &FstabSource) -> String {
    match source {
        FstabSource::Uuid(value) => format!("UUID={value}"),
        FstabSource::PartUuid(value) => format!("PARTUUID={value}"),
        FstabSource::Label(value) => format!("LABEL={value}"),
        FstabSource::PartLabel(value) => format!("PARTLABEL={value}"),
        FstabSource::Path(value) | FstabSource::Pseudo(value) => value.clone(),
    }
}

// ---------------------------------------------------------------------------
// Root candidate selection
// ---------------------------------------------------------------------------

pub fn discover_root_candidates(
    top_level: &Path,
    subvolumes: &[BtrfsSubvolumeIdentity],
) -> Result<(Vec<BtrfsSubvolumeIdentity>, Option<FstabRootDefinition>), SnapshotError> {
    let mut candidates = Vec::new();
    let mut self_describing = Vec::new();
    for candidate in subvolumes {
        if candidate.path == "/.catos-recovery" || candidate.path.starts_with("/.catos-recovery/") {
            continue;
        }
        let fstab = read_fstab_root(top_level, &candidate.path)?;
        let has_os_release = rooted_file_exists(top_level, &candidate.path, "/etc/os-release")
            || rooted_file_exists(top_level, &candidate.path, "/usr/lib/os-release");
        if fstab.is_none() && !has_os_release {
            continue;
        }
        let mut identity = show_subvolume(&top_level.join(candidate.path.trim_start_matches('/')))?;
        identity.path = candidate.path.clone();
        if identity.read_only {
            continue;
        }
        if let Some(definition) = fstab {
            if root_definition_matches_candidate(&definition, &identity) {
                self_describing.push(definition);
            }
        }
        candidates.push(identity);
    }
    let fstab = match self_describing.len() {
        0 => None,
        1 => self_describing.pop(),
        count => {
            return Err(SnapshotError::new(
                SnapshotErrorKind::AmbiguousTarget,
                format!("{count} writable subvolumes self-identify as the root in fstab"),
            ));
        }
    };
    Ok((candidates, fstab))
}

fn root_definition_matches_candidate(
    definition: &FstabRootDefinition,
    candidate: &BtrfsSubvolumeIdentity,
) -> bool {
    let path = definition
        .options
        .iter()
        .find_map(|option| option.strip_prefix("subvol="))
        .map(|value| {
            if value.starts_with('/') {
                value.to_string()
            } else {
                format!("/{value}")
            }
        });
    let id = definition
        .options
        .iter()
        .find_map(|option| option.strip_prefix("subvolid="))
        .and_then(|value| value.parse::<u64>().ok());
    path.as_deref()
        .map_or(true, |value| value == candidate.path)
        && id.map_or(true, |value| value == candidate.subvolume_id)
        && (path.is_some() || id.is_some())
}

pub fn rooted_file_exists(top_level: &Path, subvolume: &str, suffix: &str) -> bool {
    let path = rooted_join(subvolume, suffix);
    confined::read_rooted_file(top_level, &path).is_ok()
}

pub fn rooted_join(subvolume: &str, suffix: &str) -> String {
    format!(
        "{}/{}",
        subvolume.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

pub fn select_root_subvolume(
    explicit: Option<&str>,
    fstab: Option<&FstabRootDefinition>,
    default_subvolume: Option<&str>,
    high_confidence_candidates: &[BtrfsSubvolumeIdentity],
) -> Result<String, SnapshotError> {
    let normalise = |raw: &str| -> Result<String, SnapshotError> {
        let path = if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };
        SubvolumePath::parse(&path)?;
        Ok(path)
    };
    let candidate_by_path = |path: &str| {
        high_confidence_candidates
            .iter()
            .find(|candidate| candidate.path == path)
    };

    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        let path = normalise(explicit)?;
        if candidate_by_path(&path).is_none() {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                format!("explicit root subvolume {path} does not exist on the target"),
            ));
        }
        return Ok(path);
    }

    if let Some(fstab) = fstab {
        let by_path = fstab
            .options
            .iter()
            .find_map(|option| option.strip_prefix("subvol="))
            .map(normalise)
            .transpose()?;
        let by_id = fstab
            .options
            .iter()
            .find_map(|option| option.strip_prefix("subvolid="))
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    SnapshotError::new(
                        SnapshotErrorKind::AmbiguousTarget,
                        format!("invalid root subvolid in fstab: {value:?}"),
                    )
                })
            })
            .transpose()?
            .map(|id| {
                high_confidence_candidates
                    .iter()
                    .find(|candidate| candidate.subvolume_id == id)
                    .map(|candidate| candidate.path.clone())
                    .ok_or_else(|| {
                        SnapshotError::new(
                            SnapshotErrorKind::TargetChanged,
                            format!("fstab root subvolid={id} does not exist on the target"),
                        )
                    })
            })
            .transpose()?;

        if let (Some(path), Some(id_path)) = (&by_path, &by_id) {
            if path != id_path {
                return Err(SnapshotError::new(
                    SnapshotErrorKind::AmbiguousTarget,
                    format!("fstab root subvol={path} conflicts with subvolid path {id_path}"),
                ));
            }
        }
        if let Some(path) = by_path.or(by_id) {
            if candidate_by_path(&path).is_none() {
                return Err(SnapshotError::new(
                    SnapshotErrorKind::TargetChanged,
                    format!("fstab root subvolume {path} does not exist on the target"),
                ));
            }
            return Ok(path);
        }
    }

    if let Some(default_subvolume) = default_subvolume.filter(|value| *value != "/") {
        let path = normalise(default_subvolume)?;
        if candidate_by_path(&path).is_some() {
            return Ok(path);
        }
    }

    if high_confidence_candidates.len() == 1 {
        return Ok(high_confidence_candidates[0].path.clone());
    }
    Err(SnapshotError::new(
        SnapshotErrorKind::AmbiguousTarget,
        format!(
            "could not select a unique root subvolume ({} high-confidence candidates)",
            high_confidence_candidates.len()
        ),
    ))
}

#[cfg(test)]
mod root_selection_tests {
    use super::*;
    use crate::snapshot::model::{BtrfsSubvolumeIdentity, FstabRootDefinition};

    #[test]
    fn explicit_root_subvolume_wins_over_fstab_and_default() {
        let fstab = FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        };
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        assert_eq!(
            select_root_subvolume(Some("/@root"), Some(&fstab), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
    }

    #[test]
    fn fstab_subvol_and_subvolid_select_non_default_root() {
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        let by_path = FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["rw".into(), "subvol=@root".into()],
        };
        assert_eq!(
            select_root_subvolume(None, Some(&by_path), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
        let by_id = FstabRootDefinition {
            source: "UUID=root".into(),
            fstype: "btrfs".into(),
            options: vec!["subvolid=300".into()],
        };
        assert_eq!(
            select_root_subvolume(None, Some(&by_id), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
    }

    #[test]
    fn missing_or_ambiguous_root_selection_never_invents_at() {
        let error = select_root_subvolume(None, None, None, &[]).unwrap_err();
        assert_eq!(error.kind.code(), "ambiguous_target");
        let candidates = vec![candidate("/@", 256), candidate("/@root", 300)];
        let error = select_root_subvolume(None, None, None, &candidates).unwrap_err();
        assert_eq!(error.kind.code(), "ambiguous_target");
    }

    fn candidate(path: &str, subvolume_id: u64) -> BtrfsSubvolumeIdentity {
        BtrfsSubvolumeIdentity {
            path: path.into(),
            subvolume_id,
            generation: 1,
            uuid: Some(format!("uuid-{subvolume_id}")),
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        }
    }
}
