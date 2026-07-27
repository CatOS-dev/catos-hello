//! Read-only validation of sealed snapshot plans and confirmation tokens.

use crate::snapshot::diagnose::identity::{
    ensure_supported_snapshot_layout, validate_recovery_id, SubvolumePath,
};
use crate::snapshot::model::{
    RecoveryPlan, SnapshotError, SnapshotErrorKind, RECOVERY_PLAN_SCHEMA_VERSION,
};

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
) -> Result<(), SnapshotError> {
    validate_recovery_id(presented_plan_id)?;
    if presented_plan_id != plan.plan_id {
        return Err(SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "presented plan id does not match the plan record on disk",
        ));
    }
    let observed_digest = crate::snapshot::plan::effective_plan_digest(plan)?;
    if observed_digest != plan.plan_digest {
        return Err(SnapshotError::new(
            SnapshotErrorKind::PlanDigestMismatch,
            format!(
                "effective plan digest changed: expected {}, observed {}",
                plan.plan_digest, observed_digest
            ),
        ));
    }
    let expected_token = crate::snapshot::plan::build_confirmation_token(
        &plan.plan_id,
        &plan.plan_digest,
        &plan.nonce,
    );
    if plan.confirmation_token != expected_token || presented_token != expected_token {
        return Err(SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "confirmation token is not bound to the current effective plan",
        ));
    }
    Ok(())
}

/// Validate that a deserialised plan has a supported schema version
/// and that its identity fields are internally consistent (paths parse,
/// subvolumes are different, snapshot is readonly).
pub fn validate_plan_shape(plan: &RecoveryPlan) -> Result<(), SnapshotError> {
    if plan.schema_version != RECOVERY_PLAN_SCHEMA_VERSION {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedPlanSchema,
            format!(
                "plan schema version {} is not supported (expected {})",
                plan.schema_version, RECOVERY_PLAN_SCHEMA_VERSION
            ),
        ));
    }
    validate_recovery_id(&plan.plan_id)?;
    SubvolumePath::parse(&plan.current_root.path)?;
    SubvolumePath::parse(&plan.source_snapshot.path)?;
    if plan.current_root.path == plan.source_snapshot.path {
        return Err(SnapshotError::new(
            SnapshotErrorKind::TargetChanged,
            "current root and source snapshot paths are identical",
        ));
    }
    if !plan.source_snapshot.read_only {
        return Err(SnapshotError::new(
            SnapshotErrorKind::SnapshotNotReadonly,
            "source snapshot is not readonly in the plan record",
        ));
    }
    ensure_supported_snapshot_layout(&plan.current_root.path, &plan.source_snapshot.path)?;
    let expected_backup = format!(
        "{}/{}/root-before",
        crate::snapshot::model::TransactionPaths::backups_dir(),
        plan.plan_id
    );
    let expected_staging = format!(
        "{}/{}/new-root",
        crate::snapshot::model::TransactionPaths::staging_dir(),
        plan.plan_id
    );
    if plan.backup_root_path != expected_backup || plan.staging_root_path != expected_staging {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsafeRecoveryPath,
            "plan backup/staging paths do not match the canonical transaction layout",
        ));
    }
    let expected_boot_consistency =
        crate::snapshot::diagnose::boot::evaluate_readonly_consistency(&plan.boot_layout);
    if plan.boot_consistency != expected_boot_consistency {
        return Err(SnapshotError::new(
            SnapshotErrorKind::BootConsistencyInconsistent,
            format!(
                "sealed boot consistency report does not match boot layout: expected {:?}, observed {:?}",
                expected_boot_consistency.status, plan.boot_consistency.status
            ),
        ));
    }
    if plan.confirmation_token.is_empty()
        || plan.nonce.len() != 64
        || !plan
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || plan.plan_digest.len() != 64
        || !plan
            .plan_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::new(
            SnapshotErrorKind::StateRecordCorrupt,
            "plan record is missing a valid nonce, digest, or confirmation token",
        ));
    }
    let observed_digest = crate::snapshot::plan::effective_plan_digest(plan)?;
    if observed_digest != plan.plan_digest {
        return Err(SnapshotError::new(
            SnapshotErrorKind::PlanDigestMismatch,
            "effective plan fields do not match the persisted digest",
        ));
    }
    let expected_token = crate::snapshot::plan::build_confirmation_token(
        &plan.plan_id,
        &plan.plan_digest,
        &plan.nonce,
    );
    if plan.confirmation_token != expected_token {
        return Err(SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "persisted confirmation token is not bound to the effective plan",
        ));
    }
    Ok(())
}
