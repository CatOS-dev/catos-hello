//! Read-only target probing: mount the btrfs top-level read-only and
//! discover filesystem identity, root subvolume, snapshot identity,
//! boot layout, and CatOS identity.

use std::path::{Path, PathBuf};

use crate::shared::model::recovery::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, BootLayout, BootConsistencyReport,
    CatosIdentity, FstabRootDefinition, RecoveryError, RecoveryErrorKind,
};
use crate::mount::plan::session::build_probe_plan;
use crate::mount::session::ReadOnlyMountSession;
use crate::mount::diagnose::fstab::{self, FstabEntry, FstabEntryKind, FstabSource};
use crate::target::execute::confined;
use crate::shared::snapshot_engine::external as btrfs;
use crate::shared::snapshot_engine::identity::{
    canonical_block_identity, SubvolumePath,
    validate_mounted_filesystem,
};
use super::{discover_root_candidates, select_root_subvolume};

pub(crate) struct TargetProbe {
    pub(crate) canonical_device: PathBuf,
    pub(crate) filesystem: BtrfsFilesystemIdentity,
    pub(crate) current_root: BtrfsSubvolumeIdentity,
    pub(crate) snapshot: BtrfsSubvolumeIdentity,
    pub(crate) boot_layout: BootLayout,
    pub(crate) boot_consistency: BootConsistencyReport,
    pub(crate) catos_identity: Option<CatosIdentity>,
    pub(crate) fstab_root_definition: FstabRootDefinition,
}

pub(crate) fn probe_target_readonly(
    device: &Path,
    root_subvolume: Option<&str>,
    snapshot_subvolume: Option<&str>,
) -> Result<TargetProbe, RecoveryError> {
    let snapshot_btrfs_path = snapshot_subvolume
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                "--snapshot-subvolume is required; no snapshot path is inferred",
            )
        })?;
    SubvolumePath::parse(snapshot_btrfs_path)?;
    let (canonical_device, _) = canonical_block_identity(device)?;

    let session_root =
        PathBuf::from(crate::mount::execute::secure_dir::SESSION_ROOT_PARENT)
            .join(format!("recovery-ro-{}", std::process::id()));
    let source = canonical_device.to_str().ok_or_else(|| {
        RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("device {} is not valid UTF-8", canonical_device.display()),
        )
    })?;
    let mount_plan = build_probe_plan(session_root, source, "btrfs", Some("subvolid=5"))
        .map_err(|error| RecoveryError::new(RecoveryErrorKind::SyscallFailed, error.to_string()))?;
    let id = format!("recovery-ro-{}", std::process::id());
    let mut session = ReadOnlyMountSession::new(id, &mount_plan);
    let mounted = session.run(&mount_plan).map_err(|error| {
        let mut recovery_error = RecoveryError::new(
            RecoveryErrorKind::SyscallFailed,
            format!("cannot mount target read-only: {error}"),
        );
        recovery_error.failed_step = Some("probe-mount".into());
        recovery_error
    })?;

    let result = (|| {
        let top_level = &mounted.target_root;
        let target = validate_mounted_filesystem(top_level, &canonical_device)?;
        let filesystem = target.filesystem;

        let all_subvolumes = btrfs::list_subvolumes(top_level)?;
        let default_subvolume = btrfs::default_subvolume_path(top_level)?;
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
            btrfs::show_subvolume(&top_level.join(selected_root.trim_start_matches('/')))?;
        current_root.path = selected_root.clone();
        if current_root.read_only {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                format!("selected root subvolume {selected_root} is readonly"),
            ));
        }

        let mut snapshot_identity =
            btrfs::show_subvolume(&top_level.join(snapshot_btrfs_path.trim_start_matches('/')))?;
        snapshot_identity.path = snapshot_btrfs_path.to_string();
        let fstab_root_definition =
            read_fstab_root(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                RecoveryError::new(
                    RecoveryErrorKind::AmbiguousTarget,
                    format!(
                        "source snapshot {snapshot_btrfs_path} has no parseable /etc/fstab root entry"
                    ),
                )
            })?;

        let snapshot_root = top_level.join(snapshot_btrfs_path.trim_start_matches('/'));
        let snapshot_fstab =
            read_fstab_entries(top_level, snapshot_btrfs_path)?.ok_or_else(|| {
                RecoveryError::new(
                    RecoveryErrorKind::BootConsistencyUnknown,
                    format!("source snapshot {snapshot_btrfs_path} has no /etc/fstab"),
                )
            })?;
        let boot_layout = crate::shared::snapshot_engine::boot::detect_layout(&snapshot_root, &snapshot_fstab);
        let boot_consistency = crate::shared::snapshot_engine::boot::evaluate_readonly_consistency(&boot_layout);
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
        return Err(RecoveryError::new(
            RecoveryErrorKind::CleanupIncomplete,
            format!(
                "read-only target probe left residual mounts: {:?}; directory cleanup: {:?}",
                cleanup.residual, cleanup.directory_cleanup_error
            ),
        ));
    }
    result
}

fn read_catos_identity(
    top_level: &Path,
    subvolume: &str,
) -> Option<CatosIdentity> {
    let body = confined::read_rooted_file(top_level, &super::rooted_join(subvolume, "/etc/os-release"))
        .or_else(|_| {
            confined::read_rooted_file(top_level, &super::rooted_join(subvolume, "/usr/lib/os-release"))
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

pub(super) fn read_fstab_root(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<FstabRootDefinition>, RecoveryError> {
    let path = super::rooted_join(subvolume, "/etc/fstab");
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
        count => Err(RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
            format!("{path} contains {count} root entries"),
        )),
    }
}

fn read_fstab_entries(
    top_level: &Path,
    subvolume: &str,
) -> Result<Option<Vec<FstabEntry>>, RecoveryError> {
    let path = super::rooted_join(subvolume, "/etc/fstab");
    let bytes = match confined::read_rooted_file(top_level, &path) {
        Ok(bytes) => bytes,
        Err(crate::shared::error::FsError::NotFound) => return Ok(None),
        Err(error) => return Err(crate::shared::snapshot_engine::confined::fs_to_recovery(error)),
    };
    let body = String::from_utf8(bytes).map_err(|error| {
        RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
            format!("{path} is not valid UTF-8: {error}"),
        )
    })?;
    let (entries, diagnostics) = fstab::parse_all_with_diagnostics(&body);
    if !diagnostics.is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::AmbiguousTarget,
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
