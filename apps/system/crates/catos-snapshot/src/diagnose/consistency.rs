//! Pure identity-drift analysis for snapshot plans.

use crate::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, RecoveryPlan, SnapshotError, SnapshotErrorKind,
};

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
    pub current_root_uuid_changed: Option<(Option<String>, Option<String>)>,
    pub current_root_parent_uuid_changed: Option<(Option<String>, Option<String>)>,
    pub source_snapshot_subvolid_changed: Option<(u64, u64)>,
    pub source_snapshot_generation_changed: Option<(u64, u64)>,
    pub source_snapshot_uuid_changed: Option<(Option<String>, Option<String>)>,
    pub source_snapshot_parent_uuid_changed: Option<(Option<String>, Option<String>)>,
    pub source_snapshot_readonly_changed: Option<(bool, bool)>,
}

impl IdentityDrift {
    pub fn is_clean(&self) -> bool {
        self.fsid_changed.is_none()
            && self.device_major_minor_changed.is_none()
            && self.current_root_subvolid_changed.is_none()
            && self.current_root_generation_changed.is_none()
            && self.current_root_path_changed.is_none()
            && self.current_root_uuid_changed.is_none()
            && self.current_root_parent_uuid_changed.is_none()
            && self.source_snapshot_subvolid_changed.is_none()
            && self.source_snapshot_generation_changed.is_none()
            && self.source_snapshot_uuid_changed.is_none()
            && self.source_snapshot_parent_uuid_changed.is_none()
            && self.source_snapshot_readonly_changed.is_none()
    }

    pub fn into_error(self) -> Option<SnapshotError> {
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
        if let Some((a, b)) = self.current_root_uuid_changed {
            messages.push(format!("current root uuid changed: {a:?} -> {b:?}"));
        }
        if let Some((a, b)) = self.current_root_parent_uuid_changed {
            messages.push(format!("current root parent uuid changed: {a:?} -> {b:?}"));
        }
        if let Some((a, b)) = self.source_snapshot_subvolid_changed {
            messages.push(format!("source snapshot subvolid changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.source_snapshot_generation_changed {
            messages.push(format!("source snapshot generation changed: {a} -> {b}"));
        }
        if let Some((a, b)) = self.source_snapshot_uuid_changed {
            messages.push(format!("source snapshot uuid changed: {a:?} -> {b:?}"));
        }
        if let Some((a, b)) = self.source_snapshot_parent_uuid_changed {
            messages.push(format!(
                "source snapshot parent uuid changed: {a:?} -> {b:?}"
            ));
        }
        if let Some((a, b)) = self.source_snapshot_readonly_changed {
            messages.push(format!("source snapshot readonly changed: {a} -> {b}"));
        }
        Some(
            SnapshotError::new(
                SnapshotErrorKind::StalePlan,
                format!(
                    "plan is stale; identity drift detected: {}",
                    messages.join("; ")
                ),
            )
            .with_resume_possible(false),
        )
    }
}

impl SnapshotError {
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
    if plan.current_root.uuid != current_root.uuid {
        drift.current_root_uuid_changed =
            Some((plan.current_root.uuid.clone(), current_root.uuid.clone()));
    }
    if plan.current_root.parent_uuid != current_root.parent_uuid {
        drift.current_root_parent_uuid_changed = Some((
            plan.current_root.parent_uuid.clone(),
            current_root.parent_uuid.clone(),
        ));
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
    if plan.source_snapshot.uuid != source_snapshot.uuid {
        drift.source_snapshot_uuid_changed = Some((
            plan.source_snapshot.uuid.clone(),
            source_snapshot.uuid.clone(),
        ));
    }
    if plan.source_snapshot.parent_uuid != source_snapshot.parent_uuid {
        drift.source_snapshot_parent_uuid_changed = Some((
            plan.source_snapshot.parent_uuid.clone(),
            source_snapshot.parent_uuid.clone(),
        ));
    }
    if plan.source_snapshot.read_only != source_snapshot.read_only {
        drift.source_snapshot_readonly_changed =
            Some((plan.source_snapshot.read_only, source_snapshot.read_only));
    }
    drift
}
