//! Immutable snapshot recovery plan model.

use super::identity::{BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity};
use super::metadata::{BootConsistencyReport, BootLayout, CatosIdentity, FstabRootDefinition};
use crate::shared::model::evidence::Evidence;
use serde::{Deserialize, Serialize};

/// Recovery plan schema version. Bumped only on backward-incompatible
/// changes to [`RecoveryPlan`].
///
/// v3 adds a kernel-generated nonce and SHA-256 digest of the
/// canonical effective plan. Older plans are rejected rather than
/// treated as if their limited confirmation token covered every
/// execution field. v2 dropped the erroneous boot finalization
/// coupling. A v1/v2 plan is rejected as
/// `UnsupportedPlanSchema` rather than silently loading with
/// removed fields ignored.
pub const RECOVERY_PLAN_SCHEMA_VERSION: u32 = 4;

/// An immutable recovery plan. Produced by `recovery plan`; consumed
/// (with re-verification) by `recovery apply`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlan {
    /// [`RECOVERY_PLAN_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Opaque plan id (UUID-like). Bound into the confirmation token.
    pub plan_id: String,
    /// Wall-clock seconds since UNIX epoch when the plan was produced.
    pub generated_at_unix: u64,
    /// Hostname / kernel version at plan time (for human context only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_on_host: Option<String>,

    /// Identity of the target btrfs filesystem.
    pub filesystem: BtrfsFilesystemIdentity,
    /// Identity of the current root subvolume (the one to be replaced).
    pub current_root: BtrfsSubvolumeIdentity,
    /// Identity of the source readonly snapshot (the recovery target).
    pub source_snapshot: BtrfsSubvolumeIdentity,

    /// CatOS identity of the snapshot (os-release name/id/version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_catos_identity: Option<CatosIdentity>,

    /// Boot layout of the source snapshot.
    pub boot_layout: BootLayout,
    /// Read-only boot consistency decision sealed into the plan.
    pub boot_consistency: BootConsistencyReport,

    /// Where the pre-recovery backup of the current root will live.
    /// Always under the btrfs top-level.
    pub backup_root_path: String,
    /// Where the new writable root will be staged before the swap.
    /// Always under the btrfs top-level.
    pub staging_root_path: String,

    /// The fstab root definition observed inside the source snapshot.
    /// This is what the recovered root will use after the swap.
    pub fstab_root_definition: FstabRootDefinition,

    /// Predicted ordered execution steps. The engine must complete them
    /// in this order; resume continues from the last persisted step.
    pub predicted_steps: Vec<String>,
    /// Conditions under which the plan refuses to apply (re-checked at
    /// apply time).
    pub refusal_conditions: Vec<String>,
    /// Risks and warnings the operator should be aware of before
    /// confirming.
    pub risks_and_warnings: Vec<String>,

    /// 256-bit kernel-generated nonce encoded as lowercase hex.
    /// Generation fails closed if the kernel random source fails.
    pub nonce: String,
    /// SHA-256 digest of the canonical effective plan. This excludes
    /// presentation-only fields and the confirmation token itself,
    /// but covers every field that can change execution or refusal.
    pub plan_digest: String,

    /// Operator-facing confirmation token. The plan is invalid without
    /// a matching token at apply time; the token is bound to `plan_id`
    /// and to the plan identity fields so it cannot be replayed against
    /// a different plan.
    pub confirmation_token: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}
