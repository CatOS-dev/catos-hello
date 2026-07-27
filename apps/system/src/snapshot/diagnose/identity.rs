//! Identity helpers: subvolume path validation, confirmation token
//! binding, plan staleness checks. Mostly pure; the only I/O is
//! reading `/proc/self/mountinfo` for current-root detection.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use crate::mount::diagnose::mountinfo;
use crate::snapshot::diagnose::enumerate as btrfs;
use crate::snapshot::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, RecoveryPlan, SnapshotError, SnapshotErrorKind,
};

pub const RECOVERY_ID_HEX_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFilesystemIdentity {
    pub canonical_device: PathBuf,
    pub filesystem: BtrfsFilesystemIdentity,
}

/// Resolve a user-supplied device path to a concrete block device and
/// return its kernel major:minor identity.
pub fn canonical_block_identity(device: &Path) -> Result<(PathBuf, String), SnapshotError> {
    let canonical = std::fs::canonicalize(device).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!(
                "cannot canonicalize target device {}: {error}",
                device.display()
            ),
        )
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!("cannot stat target device {}: {error}", canonical.display()),
        )
    })?;
    if !metadata.file_type().is_block_device() {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!("target {} is not a block device", canonical.display()),
        ));
    }
    let device_number = metadata.rdev() as libc::dev_t;
    Ok((
        canonical,
        format!(
            "{}:{}",
            libc::major(device_number),
            libc::minor(device_number)
        ),
    ))
}

/// Validate that a mounted Btrfs top-level belongs to the exact single
/// block device selected by the operator. Multi-device filesystems are
/// rejected because the current plan schema pins one major:minor.
pub fn validate_mounted_filesystem(
    top_level: &Path,
    requested_device: &Path,
) -> Result<TargetFilesystemIdentity, SnapshotError> {
    let (canonical_device, major_minor) = canonical_block_identity(requested_device)?;
    let mut filesystem = btrfs::show_filesystem(top_level)?;
    let filesystem_devices = btrfs::filesystem_devices(top_level)?;
    if filesystem_devices.len() != 1 {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedMultiDeviceBtrfs,
            format!(
                "phase 3 supports exactly one btrfs device; target reports {}: {:?}",
                filesystem_devices.len(),
                filesystem_devices
            ),
        ));
    }
    let reported_device = std::fs::canonicalize(&filesystem_devices[0]).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!(
                "cannot canonicalize btrfs-reported device {}: {error}",
                filesystem_devices[0]
            ),
        )
    })?;
    if reported_device != canonical_device {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            format!(
                "selected device {} differs from btrfs filesystem device {}",
                canonical_device.display(),
                reported_device.display()
            ),
        ));
    }
    filesystem.device_major_minor = major_minor;
    Ok(TargetFilesystemIdentity {
        canonical_device,
        filesystem,
    })
}

/// Validate the only identifier grammar accepted by privileged
/// recovery storage: `tx-` followed by exactly 32 lowercase ASCII
/// hexadecimal digits. This same function is used for CLI values,
/// deserialised plans/records, lock names, and transaction paths.
pub fn validate_recovery_id(id: &str) -> Result<(), SnapshotError> {
    let Some(hex) = id.strip_prefix("tx-") else {
        return Err(SnapshotError::new(
            SnapshotErrorKind::InvalidRecoveryId,
            "recovery id must start with tx-",
        ));
    };
    if hex.len() != RECOVERY_ID_HEX_LEN
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::new(
            SnapshotErrorKind::InvalidRecoveryId,
            format!(
                "recovery id must be tx- followed by exactly {RECOVERY_ID_HEX_LEN} lowercase hexadecimal digits"
            ),
        ));
    }
    Ok(())
}

/// Phase 3 currently switches roots with an atomic name exchange. A
/// source snapshot nested below the active root would move together
/// with that root and invalidate its sealed path during the operation.
pub fn ensure_supported_snapshot_layout(
    current_root: &str,
    source_snapshot: &str,
) -> Result<(), SnapshotError> {
    let root = current_root.trim_end_matches('/');
    let descendant_prefix = format!("{root}/");
    if source_snapshot == current_root || source_snapshot.starts_with(&descendant_prefix) {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedNestedSnapshotLayout,
            format!(
                "source snapshot {source_snapshot} is nested below active root {current_root}; exchanging the root would move its declared path"
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Subvolume path safety
// ---------------------------------------------------------------------------

/// A validated absolute subvolume path relative to the btrfs top-level.
///
/// Rules:
/// * Must start with `/`.
/// * Must not contain `..`, `.`, or prefix components.
/// * Must not contain NUL.
/// * Must be a single subvolume path (e.g. `/@`, `/@home`,
///   `/@/.snapshots/123/snapshot`). The top-level `/` is also valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubvolumePath(String);

impl SubvolumePath {
    pub fn parse(input: &str) -> Result<Self, SnapshotError> {
        if input.is_empty() || !input.starts_with('/') {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "subvolume path must be absolute (start with /)",
            ));
        }
        if input.contains('\0') {
            return Err(SnapshotError::new(
                SnapshotErrorKind::TargetChanged,
                "subvolume path contains NUL",
            ));
        }
        // Reject any path component that is not Normal. We allow a
        // leading RootDir (which is implicit in the absolute form) and
        // a trailing empty component (which Path collapses) but nothing
        // else.
        for component in Path::new(input).components() {
            match component {
                Component::Normal(_) | Component::RootDir => {}
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(SnapshotError::new(
                        SnapshotErrorKind::TargetChanged,
                        format!("subvolume path {input:?} contains an unsafe component"),
                    ));
                }
            }
        }
        // Collapse trailing slashes. The path "/" stays as "/".
        let trimmed = input.trim_end_matches('/');
        let normalised = if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        };
        Ok(SubvolumePath(normalised))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reject a subvolume path that would escape or collide with the
/// recovery directory layout. The recovery dir owns
/// `/.catos-recovery/...`; no source or target may live there.
pub fn is_protected_recovery_path(path: &str) -> bool {
    let normalised = path.trim_end_matches('/');
    normalised == "/.catos-recovery" || normalised.starts_with("/.catos-recovery/")
}

/// Join a subvolume path with a relative tail, lexically. Used to build
/// staging paths under a controlled directory. Rejects any tail that
/// would escape the prefix.
pub fn safe_join(prefix: &Path, tail: &str) -> Result<PathBuf, SnapshotError> {
    let mut out = prefix.to_path_buf();
    for component in Path::new(tail).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(SnapshotError::new(
                    SnapshotErrorKind::TargetChanged,
                    format!("path {tail:?} would escape the controlled prefix"),
                ));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Current-root detection
// ---------------------------------------------------------------------------

/// Refuse a target that is the currently running root. The decision is
/// fail-closed when the running system is Btrfs and the target shares
/// its FSID but UUID/subvolid/path cannot distinguish them reliably.
pub fn ensure_target_is_not_running_root(
    target_filesystem: &BtrfsFilesystemIdentity,
    target_root: &BtrfsSubvolumeIdentity,
) -> Result<(), SnapshotError> {
    let body = std::fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::RunningRootProtectionIndeterminate,
            format!("cannot read /proc/self/mountinfo: {error}"),
        )
    })?;
    let running_mount = mountinfo::parse_all(&body)
        .into_iter()
        .find(|entry| entry.mount_point == Path::new("/"))
        .ok_or_else(|| {
            SnapshotError::new(
                SnapshotErrorKind::RunningRootProtectionIndeterminate,
                "cannot locate the running / mount in mountinfo",
            )
        })?;
    if running_mount.fstype != "btrfs" {
        return Ok(());
    }

    let running_filesystem = btrfs::show_filesystem(Path::new("/")).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::RunningRootProtectionIndeterminate,
            format!("cannot determine running-root btrfs FSID: {error}"),
        )
    })?;
    if running_filesystem.fsid != target_filesystem.fsid {
        return Ok(());
    }

    let mut running_root = btrfs::show_subvolume(Path::new("/")).map_err(|error| {
        SnapshotError::new(
            SnapshotErrorKind::RunningRootProtectionIndeterminate,
            format!("cannot determine running-root btrfs subvolume identity: {error}"),
        )
    })?;
    running_root.path = if running_mount.root.starts_with('/') {
        running_mount.root.clone()
    } else {
        format!("/{}", running_mount.root)
    };

    let uuid_match = match (&target_root.uuid, &running_root.uuid) {
        (Some(target), Some(running)) => Some(target == running),
        _ => None,
    };
    let subvolid_match = target_root.subvolume_id == running_root.subvolume_id;
    let path_match = target_root.path == running_root.path;
    if uuid_match == Some(true) || subvolid_match || path_match {
        return Err(SnapshotError::new(
            SnapshotErrorKind::CurrentRootRefused,
            format!(
                "target FSID {} subvolid {} UUID {:?} path {} is the running root",
                target_filesystem.fsid,
                target_root.subvolume_id,
                target_root.uuid,
                target_root.path
            ),
        ));
    }
    if uuid_match == Some(false)
        && target_root.subvolume_id != running_root.subvolume_id
        && target_root.path != running_root.path
    {
        return Ok(());
    }
    Err(SnapshotError::new(
        SnapshotErrorKind::RunningRootProtectionIndeterminate,
        format!(
            "target and running root share FSID {}, but their complete identities could not be distinguished safely",
            target_filesystem.fsid
        ),
    ))
}

/// Snapshot of the running root identity. Used by the engine to refuse
/// recovering the root we are running on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningRoot {
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
    pub major_minor: Option<String>,
    /// btrfs `subvol=` / `subvolid=` mount options, when applicable.
    pub subvol: Option<String>,
    pub subvolid: Option<u64>,
}

/// Read `/proc/self/mountinfo` and return the entry for `/` if any.
pub fn detect_running_root() -> Option<RunningRoot> {
    let body = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mounts = mountinfo::parse_all(&body);
    let root = mounts
        .iter()
        .find(|m| m.mount_point == Path::new("/"))?
        .clone();

    let subvol = superblock_option_in_vec(&root.super_options, "subvol");
    let subvolid = superblock_option_in_vec(&root.super_options, "subvolid")
        .and_then(|value| value.parse::<u64>().ok());

    Some(RunningRoot {
        mount_point: root.mount_point,
        fstype: root.fstype,
        source: root.source,
        major_minor: Some(root.major_minor.clone()),
        subvol,
        subvolid,
    })
}

fn superblock_option_in_vec(options: &[String], key: &str) -> Option<String> {
    let needle = format!("{key}=");
    for raw in options {
        let trimmed = raw.trim();
        if let Some(value) = trimmed.strip_prefix(&needle) {
            return Some(value.to_string());
        }
    }
    None
}

/// Decide whether a planned recovery target IS the currently running
/// root. The check is multi-axis: a single matching field is not
/// enough, but matching on (major:minor, subvolid) or (major:minor,
/// subvol path) is conclusive.
pub fn target_is_running_root(
    plan: &RecoveryPlan,
    observed_major_minor: &str,
    observed_subvolid: u64,
    running: Option<&RunningRoot>,
) -> bool {
    let Some(running) = running else {
        return false;
    };
    let Some(running_mm) = &running.major_minor else {
        return false;
    };
    if running_mm != observed_major_minor {
        return false;
    }
    // Major:minor agrees; now the subvolume must also agree.
    if let Some(running_subvolid) = running.subvolid {
        return running_subvolid == observed_subvolid;
    }
    // No subvolid at the running root; fall back to subvol path match.
    if let (Some(running_subvol), planned_path) = (&running.subvol, &plan.current_root.path) {
        let normalised_running = if running_subvol.starts_with('/') {
            running_subvol.clone()
        } else {
            format!("/{running_subvol}")
        };
        return normalised_running == *planned_path;
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::model::BootLayout;
    use crate::snapshot::diagnose::consistency::*;
    use crate::snapshot::model::{
        CatosIdentity, FstabRootDefinition, RECOVERY_PLAN_SCHEMA_VERSION,
    };
    use crate::snapshot::plan::{build_confirmation_token, effective_plan_digest};
    use crate::snapshot::verify::*;

    const PLAN_ID: &str = "tx-00000000000000000000000000000001";
    const OTHER_PLAN_ID: &str = "tx-00000000000000000000000000000002";

    fn sample_plan() -> RecoveryPlan {
        let mut plan = RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: PLAN_ID.into(),
            generated_at_unix: 100,
            generated_on_host: None,
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid-1".into(),
                device_major_minor: "259:2".into(),
                label: None,
            },
            current_root: BtrfsSubvolumeIdentity {
                path: "/@".into(),
                subvolume_id: 256,
                generation: 100,
                uuid: Some("old-root-uuid".into()),
                parent_uuid: None,
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@snapshots/1".into(),
                subvolume_id: 300,
                generation: 80,
                uuid: Some("source-snapshot-uuid".into()),
                parent_uuid: Some("older-root-uuid".into()),
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: Some(CatosIdentity::default()),
            boot_layout: BootLayout::default(),
            boot_consistency: crate::boot::diagnose::layout::evaluate_readonly_consistency(
                &BootLayout::default(),
            ),
            backup_root_path: format!("/.catos-recovery/backups/{PLAN_ID}/root-before"),
            staging_root_path: format!("/.catos-recovery/staging/{PLAN_ID}/new-root"),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec![],
            refusal_conditions: vec![],
            risks_and_warnings: vec![],
            nonce: "00".repeat(32),
            plan_digest: String::new(),
            confirmation_token: String::new(),
            evidence: vec![],
        };
        plan.plan_digest = effective_plan_digest(&plan).unwrap();
        plan.confirmation_token =
            build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);
        plan
    }

    #[test]
    fn subvolume_path_rejects_relative() {
        assert!(SubvolumePath::parse("@").is_err());
        assert!(SubvolumePath::parse("").is_err());
    }

    #[test]
    fn subvolume_path_rejects_parent_components() {
        assert!(SubvolumePath::parse("/@/../host").is_err());
        assert!(SubvolumePath::parse("/../@").is_err());
    }

    #[test]
    fn subvolume_path_rejects_nul() {
        assert!(SubvolumePath::parse("/@\0/evil").is_err());
    }

    #[test]
    fn subvolume_path_accepts_top_level() {
        let p = SubvolumePath::parse("/").unwrap();
        assert_eq!(p.as_str(), "/");
    }

    #[test]
    fn subvolume_path_accepts_snapshot_path() {
        let p = SubvolumePath::parse("/@/.snapshots/123/snapshot").unwrap();
        assert_eq!(p.as_str(), "/@/.snapshots/123/snapshot");
    }

    #[test]
    fn protected_recovery_path_detection() {
        assert!(is_protected_recovery_path("/.catos-recovery"));
        assert!(is_protected_recovery_path("/.catos-recovery/transactions"));
        assert!(is_protected_recovery_path("/.catos-recovery/transactions/"));
        assert!(!is_protected_recovery_path("/@"));
        assert!(!is_protected_recovery_path("/@home"));
    }

    #[test]
    fn safe_join_rejects_escape() {
        let prefix = Path::new("/tmp/prefix");
        assert_eq!(
            safe_join(prefix, "a/b").unwrap(),
            PathBuf::from("/tmp/prefix/a/b")
        );
        assert!(safe_join(prefix, "../escape").is_err());
        assert!(safe_join(prefix, "a/../../escape").is_err());
    }

    #[test]
    fn drift_detects_fsid_change() {
        let plan = sample_plan();
        let mut fs = plan.filesystem.clone();
        fs.fsid = "different".into();
        let drift = drift_between(&plan, &fs, &plan.current_root, &plan.source_snapshot);
        assert!(drift.fsid_changed.is_some());
        assert!(drift.into_error().is_some());
    }

    #[test]
    fn drift_detects_generation_change() {
        let plan = sample_plan();
        let mut root = plan.current_root.clone();
        root.generation = 200;
        let drift = drift_between(&plan, &plan.filesystem, &root, &plan.source_snapshot);
        assert!(drift.current_root_generation_changed.is_some());
    }

    #[test]
    fn drift_detects_current_root_uuid_change() {
        let plan = sample_plan();
        let mut root = plan.current_root.clone();
        root.uuid = Some("replacement-root-uuid".into());
        let drift = drift_between(&plan, &plan.filesystem, &root, &plan.source_snapshot);
        assert!(drift.current_root_uuid_changed.is_some());
        assert!(drift.into_error().is_some());
    }

    #[test]
    fn drift_detects_source_snapshot_identity_change() {
        let plan = sample_plan();
        let mut snapshot = plan.source_snapshot.clone();
        snapshot.uuid = Some("different-snapshot-uuid".into());
        snapshot.parent_uuid = Some("different-parent-uuid".into());
        let drift = drift_between(&plan, &plan.filesystem, &plan.current_root, &snapshot);
        assert!(drift.source_snapshot_uuid_changed.is_some());
        assert!(drift.source_snapshot_parent_uuid_changed.is_some());
        assert!(drift.into_error().is_some());
    }

    #[test]
    fn drift_detects_snapshot_readonly_change() {
        let plan = sample_plan();
        let mut snapshot = plan.source_snapshot.clone();
        snapshot.read_only = false;
        let drift = drift_between(&plan, &plan.filesystem, &plan.current_root, &snapshot);
        assert!(drift.source_snapshot_readonly_changed.is_some());
    }

    #[test]
    fn drift_is_clean_when_identities_match() {
        let plan = sample_plan();
        let drift = drift_between(
            &plan,
            &plan.filesystem,
            &plan.current_root,
            &plan.source_snapshot,
        );
        assert!(drift.is_clean());
        assert!(drift.into_error().is_none());
    }

    #[test]
    fn confirmation_token_rejects_wrong_plan_id() {
        let plan = sample_plan();
        assert!(verify_confirmation_token(&plan, PLAN_ID, &plan.confirmation_token).is_ok());
        assert!(verify_confirmation_token(&plan, OTHER_PLAN_ID, &plan.confirmation_token).is_err());
        assert!(verify_confirmation_token(&plan, PLAN_ID, "tok-other").is_err());
    }

    #[test]
    fn validate_plan_shape_rejects_unsupported_schema() {
        let mut plan = sample_plan();
        plan.schema_version = 99;
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::UnsupportedPlanSchema);
    }

    #[test]
    fn validate_plan_shape_rejects_non_readonly_snapshot() {
        let mut plan = sample_plan();
        plan.source_snapshot.read_only = false;
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::SnapshotNotReadonly);
    }

    #[test]
    fn validate_plan_shape_rejects_identical_paths() {
        let mut plan = sample_plan();
        plan.source_snapshot.path = plan.current_root.path.clone();
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::TargetChanged);
    }

    #[test]
    fn validate_plan_shape_rejects_forged_boot_consistency() {
        let mut plan = sample_plan();
        plan.boot_consistency.status = crate::boot::model::BootConsistencyStatus::Consistent;
        plan.boot_consistency.root_switch_covers_all_boot_resources = true;
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::BootConsistencyInconsistent);
    }

    #[test]
    fn target_is_running_root_requires_major_minor_match() {
        let plan = sample_plan();
        let running = RunningRoot {
            mount_point: PathBuf::from("/"),
            fstype: "btrfs".into(),
            source: "/dev/nvme0n1p2".into(),
            major_minor: Some("259:2".into()),
            subvol: None,
            subvolid: Some(256),
        };
        assert!(target_is_running_root(&plan, "259:2", 256, Some(&running)));
        assert!(!target_is_running_root(&plan, "259:3", 256, Some(&running)));
        assert!(!target_is_running_root(&plan, "259:2", 999, Some(&running)));
    }

    #[test]
    fn target_is_running_root_falls_back_to_subvol_path() {
        let plan = sample_plan();
        let running = RunningRoot {
            mount_point: PathBuf::from("/"),
            fstype: "btrfs".into(),
            source: "/dev/nvme0n1p2".into(),
            major_minor: Some("259:2".into()),
            subvol: Some("/@".into()),
            subvolid: None,
        };
        assert!(target_is_running_root(&plan, "259:2", 999, Some(&running)));
    }

    #[test]
    fn target_is_running_root_returns_false_when_no_running_root() {
        let plan = sample_plan();
        assert!(!target_is_running_root(&plan, "259:2", 256, None));
    }

    #[test]
    fn superblock_option_parses_subvol() {
        let options: Vec<String> = [
            "rw",
            "relatime",
            "compress=zstd:3",
            "subvol=/@",
            "space_cache=v2",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            superblock_option_in_vec(&options, "subvol").as_deref(),
            Some("/@")
        );
        assert_eq!(superblock_option_in_vec(&options, "subvolid"), None);
        assert_eq!(
            superblock_option_in_vec(&options, "compress").as_deref(),
            Some("zstd:3")
        );
    }
}
