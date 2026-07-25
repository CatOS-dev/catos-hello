//! Identity helpers: subvolume path validation, confirmation token
//! binding, plan staleness checks. Mostly pure; the only I/O is
//! reading `/proc/self/mountinfo` for current-root detection.

use std::path::{Component, Path, PathBuf};

use crate::model::recovery::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, RecoveryError, RecoveryErrorKind,
    RecoveryPlan, RECOVERY_PLAN_SCHEMA_VERSION,
};
use crate::parse::mountinfo;

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
    pub fn parse(input: &str) -> Result<Self, RecoveryError> {
        if input.is_empty() || !input.starts_with('/') {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
                "subvolume path must be absolute (start with /)",
            ));
        }
        if input.contains('\0') {
            return Err(RecoveryError::new(
                RecoveryErrorKind::TargetChanged,
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
                    return Err(RecoveryError::new(
                        RecoveryErrorKind::TargetChanged,
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
pub fn safe_join(prefix: &Path, tail: &str) -> Result<PathBuf, RecoveryError> {
    let mut out = prefix.to_path_buf();
    for component in Path::new(tail).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(RecoveryError::new(
                    RecoveryErrorKind::TargetChanged,
                    format!("path {tail:?} would escape the controlled prefix"),
                ));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Plan staleness
// ---------------------------------------------------------------------------

/// Identity drift observed between a [`RecoveryPlan`] and a fresh
/// observation of the filesystem. Each field is `None` when there is no
/// drift for that axis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityDrift {
    pub fsid_changed: Option<(String, String)>,
    pub device_major_minor_changed: Option<(String, String)>,
    pub current_root_subvolid_changed: Option<(u64, u64)>,
    pub current_root_generation_changed: Option<(u64, u64)>,
    pub current_root_path_changed: Option<(String, String)>,
    pub source_snapshot_subvolid_changed: Option<(u64, u64)>,
    pub source_snapshot_generation_changed: Option<(u64, u64)>,
    pub source_snapshot_readonly_changed: Option<(bool, bool)>,
}

impl IdentityDrift {
    pub fn is_clean(&self) -> bool {
        self.fsid_changed.is_none()
            && self.device_major_minor_changed.is_none()
            && self.current_root_subvolid_changed.is_none()
            && self.current_root_generation_changed.is_none()
            && self.current_root_path_changed.is_none()
            && self.source_snapshot_subvolid_changed.is_none()
            && self.source_snapshot_generation_changed.is_none()
            && self.source_snapshot_readonly_changed.is_none()
    }

    pub fn into_error(self) -> Option<RecoveryError> {
        if self.is_clean() {
            return None;
        }
        let mut messages = Vec::new();
        if let Some((a, b)) = self.fsid_changed {
            messages.push(format!("fsid changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.device_major_minor_changed {
            messages.push(format!("device major:minor changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.current_root_subvolid_changed {
            messages.push(format!("current root subvolid changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.current_root_generation_changed {
            messages.push(format!("current root generation changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.current_root_path_changed {
            messages.push(format!("current root path changed: {a:?} -> {b:?}"));
        }
        if let Some((a, b)) = self.source_snapshot_subvolid_changed {
            messages.push(format!("source snapshot subvolid changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.source_snapshot_generation_changed {
            messages.push(format!("source snapshot generation changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.source_snapshot_readonly_changed {
            messages.push(format!("source snapshot readonly changed: {a} -> {b}"));
        }
        Some(
            RecoveryError::new(
                RecoveryErrorKind::StalePlan,
                format!(
                    "plan is stale; identity drift detected: {}",
                    messages.join("; ")
                ),
            )
            .with_resume_possible(false),
        )
    }
}

impl RecoveryError {
    pub fn with_resume_possible(mut self, possible: bool) -> Self {
        self.resume_possible = possible;
        self
    }
}

/// Compare the plan's pinned identities with a fresh observation.
pub fn drift_between(
    plan: &RecoveryPlan,
    filesystem: &BtrfsFilesystemIdentity,
    current_root: &BtrfsSubvolumeIdentity,
    source_snapshot: &BtrfsSubvolumeIdentity,
) -> IdentityDrift {
    let mut drift = IdentityDrift::default();
    if plan.filesystem.fsid != filesystem.fsid {
        drift.fsid_changed = Some((plan.filesystem.fsid.clone(), filesystem.fsid.clone()));
    }
    if plan.filesystem.device_major_minor != filesystem.device_major_minor {
        drift.device_major_minor_changed = Some((
            plan.filesystem.device_major_minor.clone(),
            filesystem.device_major_minor.clone(),
        ));
    }
    if plan.current_root.subvolume_id != current_root.subvolume_id {
        drift.current_root_subvolid_changed =
            Some((plan.current_root.subvolume_id, current_root.subvolume_id));
    }
    if plan.current_root.generation != current_root.generation {
        drift.current_root_generation_changed =
            Some((plan.current_root.generation, current_root.generation));
    }
    if plan.current_root.path != current_root.path {
        drift.current_root_path_changed =
            Some((plan.current_root.path.clone(), current_root.path.clone()));
    }
    if plan.source_snapshot.subvolume_id != source_snapshot.subvolume_id {
        drift.source_snapshot_subvolid_changed = Some((
            plan.source_snapshot.subvolume_id,
            source_snapshot.subvolume_id,
        ));
    }
    if plan.source_snapshot.generation != source_snapshot.generation {
        drift.source_snapshot_generation_changed =
            Some((plan.source_snapshot.generation, source_snapshot.generation));
    }
    if plan.source_snapshot.read_only != source_snapshot.read_only {
        drift.source_snapshot_readonly_changed =
            Some((plan.source_snapshot.read_only, source_snapshot.read_only));
    }
    drift
}

// ---------------------------------------------------------------------------
// Confirmation token
// ---------------------------------------------------------------------------

/// Verify that a confirmation token presented to `apply` matches the
/// plan's expected token AND is bound to the same plan id and identity
/// fields. A token cannot be replayed against a different plan.
///
/// The token format we accept is the bare opaque string emitted by
/// `recovery plan`. We do not implement cryptography here (the binary
/// has no OpenSSL by design); the binding is enforced structurally:
/// the caller MUST supply both `--plan-id` and `--confirm <token>`,
/// and we check the pair against the plan file on disk.
pub fn verify_confirmation_token(
    plan: &RecoveryPlan,
    presented_plan_id: &str,
    presented_token: &str,
) -> Result<(), RecoveryError> {
    if presented_plan_id != plan.plan_id {
        return Err(RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "presented plan id does not match the plan record on disk",
        ));
    }
    if presented_token != plan.confirmation_token {
        return Err(RecoveryError::new(
            RecoveryErrorKind::ConfirmationTokenMismatch,
            "presented confirmation token does not match the plan record on disk",
        ));
    }
    Ok(())
}

/// Validate that a deserialised plan has a supported schema version
/// and that its identity fields are internally consistent (paths parse,
/// subvolumes are different, snapshot is readonly).
pub fn validate_plan_shape(plan: &RecoveryPlan) -> Result<(), RecoveryError> {
    if plan.schema_version != RECOVERY_PLAN_SCHEMA_VERSION {
        return Err(RecoveryError::new(
            RecoveryErrorKind::UnsupportedPlanSchema,
            format!(
                "plan schema version {} is not supported (expected {})",
                plan.schema_version, RECOVERY_PLAN_SCHEMA_VERSION
            ),
        ));
    }
    SubvolumePath::parse(&plan.current_root.path)?;
    SubvolumePath::parse(&plan.source_snapshot.path)?;
    if plan.current_root.path == plan.source_snapshot.path {
        return Err(RecoveryError::new(
            RecoveryErrorKind::TargetChanged,
            "current root and source snapshot paths are identical",
        ));
    }
    if !plan.source_snapshot.read_only {
        return Err(RecoveryError::new(
            RecoveryErrorKind::SnapshotNotReadonly,
            "source snapshot is not readonly in the plan record",
        ));
    }
    if plan.confirmation_token.is_empty() || plan.plan_id.is_empty() {
        return Err(RecoveryError::new(
            RecoveryErrorKind::StateRecordCorrupt,
            "plan record is missing plan_id or confirmation_token",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Current-root detection
// ---------------------------------------------------------------------------

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
    use crate::model::recovery::{
        BootFinalizationDecision, BootLayout, CatosIdentity, FstabRootDefinition,
    };

    fn sample_plan() -> RecoveryPlan {
        RecoveryPlan {
            schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
            plan_id: "p-1".into(),
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
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@/.snapshots/1/snapshot".into(),
                subvolume_id: 300,
                generation: 80,
                read_only: true,
                evidence: vec![],
            },
            target_catos_identity: Some(CatosIdentity::default()),
            boot_layout: BootLayout::default(),
            finalization: BootFinalizationDecision::NotRequired,
            backup_root_path: "/.catos-recovery/backups/tx/root-before".into(),
            staging_root_path: "/.catos-recovery/staging/tx/new-root".into(),
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            predicted_steps: vec![],
            refusal_conditions: vec![],
            risks_and_warnings: vec![],
            confirmation_token: "tok-1".into(),
            evidence: vec![],
        }
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
        assert!(verify_confirmation_token(&plan, "p-1", "tok-1").is_ok());
        assert!(verify_confirmation_token(&plan, "p-other", "tok-1").is_err());
        assert!(verify_confirmation_token(&plan, "p-1", "tok-other").is_err());
    }

    #[test]
    fn validate_plan_shape_rejects_unsupported_schema() {
        let mut plan = sample_plan();
        plan.schema_version = 99;
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::UnsupportedPlanSchema);
    }

    #[test]
    fn validate_plan_shape_rejects_non_readonly_snapshot() {
        let mut plan = sample_plan();
        plan.source_snapshot.read_only = false;
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::SnapshotNotReadonly);
    }

    #[test]
    fn validate_plan_shape_rejects_identical_paths() {
        let mut plan = sample_plan();
        plan.source_snapshot.path = plan.current_root.path.clone();
        let err = validate_plan_shape(&plan).unwrap_err();
        assert_eq!(err.kind, RecoveryErrorKind::TargetChanged);
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
