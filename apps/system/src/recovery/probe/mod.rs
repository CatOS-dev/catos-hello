//! Probe infrastructure for recovery: read-only transaction probing,
//! target candidate discovery, fstab/root selection, and cleanup
//! summarisation.

pub(super) mod target;

use std::path::{Path, PathBuf};

use crate::shared::model::recovery::{
    BtrfsSubvolumeIdentity, CleanupSummary, DiskFacts, FstabRootDefinition, RecoveryError,
    RecoveryErrorKind, TransactionRecord,
};
use crate::shared::model::mount::CleanupReport;
use crate::shared::mount::plan::build_probe_plan;
use crate::shared::mount::secure_dir::SESSION_ROOT_PARENT;
use crate::shared::mount::session::Session;
use crate::shared::snapshot_engine::confined;
use crate::shared::snapshot_engine::engine::{Engine, EngineOptions};
use crate::shared::snapshot_engine::external as btrfs;
use crate::shared::snapshot_engine::identity::{
    canonical_block_identity, ensure_supported_snapshot_layout, ensure_target_is_not_running_root,
    SubvolumePath, validate_mounted_filesystem,
};

pub(super) use target::probe_target_readonly;

pub(super) struct ExistingTransactionProbe {
    pub(super) canonical_device: PathBuf,
    pub(super) filesystem: crate::shared::model::recovery::BtrfsFilesystemIdentity,
    pub(super) record: TransactionRecord,
    pub(super) disk_facts: DiskFacts,
    pub(super) cleanup: CleanupSummary,
}

pub(super) fn probe_existing_transaction_readonly(
    device: &Path,
    explicit_root: Option<&str>,
    transaction_id: &str,
    protect_running_root: bool,
) -> Result<ExistingTransactionProbe, RecoveryError> {
    let (canonical_device, _) = canonical_block_identity(device)?;
    let session_root = PathBuf::from(SESSION_ROOT_PARENT).join(format!(
        "recovery-existing-{}-{}",
        std::process::id(),
        transaction_id
    ));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let mut session = Session::new(format!("recovery-existing-{transaction_id}"), &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount existing recovery transaction read-only: {error}"),
        )
    })?;

    let result = (|| {
        let target = validate_mounted_filesystem(&mounted.target_root, &canonical_device)?;
        let mut engine = Engine::load(
            EngineOptions {
                top_level_mount: mounted.target_root.clone(),
                device_path: canonical_device.clone(),
                validated_filesystem: target.filesystem.clone(),
            },
            transaction_id,
        )?;
        super::ensure_cli_root_matches_plan(explicit_root, &engine.record().plan.current_root.path)?;
        ensure_supported_snapshot_layout(
            &engine.record().plan.current_root.path,
            &engine.record().plan.source_snapshot.path,
        )?;

        if protect_running_root {
            let root_path = engine.record().plan.current_root.path.clone();
            let mut active_root = btrfs::show_subvolume(
                &mounted.target_root.join(root_path.trim_start_matches('/')),
            )?;
            active_root.path = root_path;
            ensure_target_is_not_running_root(&target.filesystem, &active_root)?;
        }

        let disk_facts = engine.reconcile_status();
        let record = engine.record().clone();
        Ok((target.filesystem, record, disk_facts))
    })();

    let cleanup = cleanup_summary(session.cleanup());
    if !cleanup.all_clean {
        let primary = result
            .as_ref()
            .err()
            .map(|error: &RecoveryError| format!("; primary probe error: {error}"))
            .unwrap_or_default();
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "existing transaction probe left residual mounts: {:?}{primary}",
                cleanup.residual
            ),
        ));
    }
    let (filesystem, record, disk_facts) = result?;
    Ok(ExistingTransactionProbe {
        canonical_device,
        filesystem,
        record,
        disk_facts,
        cleanup,
    })
}

pub(super) fn cleanup_summary(report: CleanupReport) -> CleanupSummary {
    let mut residual = report
        .residual
        .iter()
        .map(|entry| {
            format!(
                "{}: {} ({})",
                entry.resource.target.display(),
                entry.reason,
                entry.error_code
            )
        })
        .collect::<Vec<_>>();
    if let Some(error) = report.directory_cleanup_error {
        residual.push(format!("session directory cleanup: {error}"));
    }
    CleanupSummary {
        unmounted: report
            .unmounted
            .iter()
            .map(|entry| entry.target.display().to_string())
            .collect(),
        residual,
        all_clean: report.all_clean,
    }
}

pub(super) fn discover_root_candidates(
    top_level: &Path,
    subvolumes: &[BtrfsSubvolumeIdentity],
) -> Result<
    (
        Vec<BtrfsSubvolumeIdentity>,
        Option<FstabRootDefinition>,
    ),
    RecoveryError,
> {
    let mut candidates = Vec::new();
    let mut self_describing = Vec::new();
    for candidate in subvolumes {
        if candidate.path == "/.catos-recovery" || candidate.path.starts_with("/.catos-recovery/") {
            continue;
        }
        let fstab = target::read_fstab_root(top_level, &candidate.path)?;
        let has_os_release = rooted_file_exists(top_level, &candidate.path, "/etc/os-release")
            || rooted_file_exists(top_level, &candidate.path, "/usr/lib/os-release");
        if fstab.is_none() && !has_os_release {
            continue;
        }
        let mut identity =
            btrfs::show_subvolume(&top_level.join(candidate.path.trim_start_matches('/')))?;
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
            return Err(RecoveryError::new(
                RecoveryErrorKind::AmbiguousTarget,
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

pub(super) fn rooted_file_exists(top_level: &Path, subvolume: &str, suffix: &str) -> bool {
    let path = rooted_join(subvolume, suffix);
    confined::read_rooted_file(top_level, &path).is_ok()
}

pub(super) fn rooted_join(subvolume: &str, suffix: &str) -> String {
    format!(
        "{}/{}",
        subvolume.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

pub(super) fn select_root_subvolume(
    explicit: Option<&str>,
    fstab: Option<&FstabRootDefinition>,
    default_subvolume: Option<&str>,
    high_confidence_candidates: &[BtrfsSubvolumeIdentity],
) -> Result<String, RecoveryError> {
    let normalise = |raw: &str| -> Result<String, RecoveryError> {
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
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
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
                    RecoveryError::new(
                        RecoveryErrorKind::AmbiguousTarget,
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
                        RecoveryError::new(
                            RecoveryErrorKind::TargetChanged,
                            format!("fstab root subvolid={id} does not exist on the target"),
                        )
                    })
            })
            .transpose()?;

        if let (Some(path), Some(id_path)) = (&by_path, &by_id) {
            if path != id_path {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::AmbiguousTarget,
                    format!("fstab root subvol={path} conflicts with subvolid path {id_path}"),
                ));
            }
        }
        if let Some(path) = by_path.or(by_id) {
            if candidate_by_path(&path).is_none() {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::TargetChanged,
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
    Err(RecoveryError::new(
        RecoveryErrorKind::AmbiguousTarget,
        format!(
            "could not select a unique root subvolume ({} high-confidence candidates)",
            high_confidence_candidates.len()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::recovery::{BtrfsSubvolumeIdentity, FstabRootDefinition};

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
            source: "UUID=root".into(), fstype: "btrfs".into(),
            options: vec!["rw".into(), "subvol=@root".into()],
        };
        assert_eq!(
            select_root_subvolume(None, Some(&by_path), Some("/@"), &candidates).unwrap(),
            "/@root"
        );
        let by_id = FstabRootDefinition {
            source: "UUID=root".into(), fstype: "btrfs".into(),
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
            path: path.into(), subvolume_id, generation: 1,
            uuid: Some(format!("uuid-{subvolume_id}")), parent_uuid: None,
            read_only: false, evidence: vec![],
        }
    }
}
