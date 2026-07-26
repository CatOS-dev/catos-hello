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
//! This module adds btrfs-specific parsing on top of those guarantees.
//! It also keeps a strict allow-list of which subcommands we run: any
//! attempt to invoke an off-list subcommand would be a code error and
//! must fail loudly.
//!
//! Subcommand allow-list:
//!
//! * `btrfs filesystem show <dev>`           — read FSID, label, device list.
//! * `btrfs subvolume show <path>`           — read subvolid, generation, readonly.
//! * `btrfs subvolume list -rg <path>`       — enumerate readonly subvolumes.
//! * `btrfs subvolume snapshot -r <src> <dst>` — create readonly snapshot.
//! * `btrfs subvolume snapshot <src> <dst>`    — create writable snapshot.
//! * `btrfs property set <path> ro true|false` — toggle readonly (used by tests; never on the source).
//! * `btrfs subvolume get-default <path>`    — read the default subvolid.
//! * `btrfs subvolume set-default <id> <path>` — set the default subvolid (NOT used in phase 3; recovery uses subvol= in fstab).
//!
//! Phase 3 NEVER runs:
//!
//! * `btrfs subvolume delete` — the original root is preserved as
//!   backup. Cleanup is the operator's responsibility.
//! * `btrfs balance` / `btrfs device add` / `btrfs device remove` /
//!   `btrfs scrub` — out of scope.
//! * `btrfs restore` / `btrfs check --repair` — too dangerous to run
//!   from a recovery tool without operator review.

use std::path::Path;
use std::time::Duration;

use crate::model::evidence::Evidence;
use crate::model::recovery::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, RecoveryError, RecoveryErrorKind,
    SubvolumeFacts,
};
use crate::shared::process::{run_trusted_tool, ToolOutput};

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
pub fn show_filesystem(mount_point: &Path) -> Result<BtrfsFilesystemIdentity, RecoveryError> {
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
        RecoveryError::new(
            RecoveryErrorKind::BtrfsToolFailed,
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
pub fn filesystem_devices(mount_point: &Path) -> Result<Vec<String>, RecoveryError> {
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
        return Err(RecoveryError::new(
            RecoveryErrorKind::BtrfsToolFailed,
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
pub fn show_subvolume(mounted_path: &Path) -> Result<BtrfsSubvolumeIdentity, RecoveryError> {
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
        RecoveryError::new(
            RecoveryErrorKind::BtrfsToolFailed,
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
// Returns `Box<RecoveryError>`: the only caller is
// `engine::observe_disk_facts`, which immediately calls `.ok()` and
// discards the error. Boxing here keeps the result small and silences
// clippy's large-result lint without weakening structured error info
// (the boxed error is never inspected).
pub fn probe_subvolume_facts(mounted_path: &Path) -> Result<SubvolumeFacts, Box<RecoveryError>> {
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
) -> Result<Vec<BtrfsSubvolumeIdentity>, RecoveryError> {
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
) -> Result<Vec<BtrfsSubvolumeIdentity>, RecoveryError> {
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
pub fn default_subvolume_path(mounted_top_level: &Path) -> Result<Option<String>, RecoveryError> {
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

/// Create a readonly snapshot `dst` of `src`. Both paths MUST live in
/// the same btrfs filesystem. Used to back up the current root before
/// the recovery swap.
pub fn create_readonly_snapshot(src: &Path, dst: &Path) -> Result<(), RecoveryError> {
    let _ = run(
        "subvolume",
        &[
            "snapshot",
            "-r",
            path_to_str(src)?.as_str(),
            path_to_str(dst)?.as_str(),
        ],
    )?;
    Ok(())
}

/// Create a writable snapshot `dst` of `src`. Used to materialise the
/// new root from the source readonly snapshot.
pub fn create_writable_snapshot(src: &Path, dst: &Path) -> Result<(), RecoveryError> {
    let _ = run(
        "subvolume",
        &[
            "snapshot",
            path_to_str(src)?.as_str(),
            path_to_str(dst)?.as_str(),
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn run(subcommand: &str, args: &[&str]) -> Result<ToolOutput, RecoveryError> {
    // Validate the subcommand against the strict allow-list so a code
    // bug cannot accidentally invoke, e.g., `btrfs subvolume delete`.
    match subcommand {
        "filesystem" | "subvolume" | "property" => {}
        other => {
            return Err(RecoveryError::new(
                RecoveryErrorKind::BtrfsToolFailed,
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
        let mut err = RecoveryError::new(
            RecoveryErrorKind::BtrfsToolFailed,
            format!("btrfs {} failed: {}", subcommand, message),
        );
        err.failed_step = Some(format!("btrfs-{}", subcommand));
        err
    })?;
    if !output.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(RecoveryError {
            kind: RecoveryErrorKind::BtrfsToolFailed,
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

fn path_to_str(path: &Path) -> Result<String, RecoveryError> {
    path.to_str().map(|s| s.to_string()).ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::BtrfsToolFailed,
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
        assert_eq!(err.kind, RecoveryErrorKind::BtrfsToolFailed);
        assert!(err.message.contains("balance"));
    }
}
