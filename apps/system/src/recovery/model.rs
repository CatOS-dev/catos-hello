//! Recovery application reports and recommendations.

use crate::boot::model::{BootConsistencyReport, BootLayout};
use crate::snapshot::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CatosIdentity, CleanupSummary, DiskFacts,
    RecoveryPlan, TransactionRecord, TransactionState,
};
use crate::target::model::Warning;
use serde::{Deserialize, Serialize};

/// Output envelope for `recovery list` — the readonly listing of
/// snapshots and transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RecoveryListReport {
    /// Canonical block-device path that was mounted for this listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_device: Option<String>,
    /// FSID observed from the mounted target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_filesystem_fsid: Option<String>,
    /// Explicit cleanup result for the short-lived read-only mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_cleanup: Option<CleanupSummary>,
    /// Filesystem identities observed (one per probed btrfs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystems: Vec<BtrfsFilesystemIdentity>,
    /// Subvolumes that look like readonly snapshots eligible as a
    /// recovery source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly_snapshots: Vec<BtrfsSubvolumeIdentity>,
    /// Persisted plans that have not started a transaction yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plans: Vec<RecoveryPlanSummary>,
    /// Transactions known to exist on this machine (across all
    /// filesystems), with their current state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transactions: Vec<TransactionSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlanSummary {
    pub plan_id: String,
    pub generated_at_unix: u64,
    pub source_snapshot_path: String,
    pub confirmation_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlanReport {
    #[serde(flatten)]
    pub plan: RecoveryPlan,
    pub plan_path: String,
    pub mount_cleanup: CleanupSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionSummary {
    pub transaction_id: String,
    pub state: TransactionState,
    pub plan_id: String,
    pub created_at_unix: u64,
    pub last_updated_unix: u64,
    pub source_snapshot_path: String,
}

/// Output envelope for `recovery inspect`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryInspectReport {
    pub filesystem: BtrfsFilesystemIdentity,
    pub current_root: BtrfsSubvolumeIdentity,
    pub source_snapshot: BtrfsSubvolumeIdentity,
    pub boot_layout: BootLayout,
    pub boot_consistency: BootConsistencyReport,
    pub target_catos_identity: Option<CatosIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

/// Output envelope for `recovery status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryStatusReport {
    pub transaction_id: String,
    /// State after reconciling the persisted record with current disk
    /// facts. Consumers MUST use this, not `record.state`.
    pub reconciled_state: TransactionState,
    pub record: TransactionRecord,
    pub disk_facts: DiskFacts,
    /// Operator-facing recommendation. Stable enum so the recovery UI
    /// can route without parsing free text.
    pub recommendation: RecoveryRecommendation,
    /// Cleanup result for the short-lived read-only status mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_cleanup: Option<CleanupSummary>,
    /// State-bound confirmation required by `recovery revert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_confirmation_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

/// What the engine recommends the operator do next.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRecommendation {
    /// Transaction is complete; no action needed.
    #[default]
    None,
    /// Transaction is in progress; safe to call `resume`.
    Resume,
    /// Transaction failed but `resume` is safe.
    ResumeAfterFailure,
    /// Transaction failed and `revert` is the safer path.
    Revert,
    /// Manual intervention required; neither `resume` nor `revert` is
    /// safe without operator review.
    ManualIntervention,
}
