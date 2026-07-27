//! Read-only validation of sealed snapshot plans and confirmation tokens.

use crate::diagnose::identity::{
    ensure_supported_snapshot_layout, validate_recovery_id, SubvolumePath,
};
use crate::model::{RecoveryPlan, SnapshotError, SnapshotErrorKind, RECOVERY_PLAN_SCHEMA_VERSION};
use catos_boot::model::{BootConsistencyReport, BootConsistencyStatus};

/// Map the Boot capability's read-only topology assessment into Snapshot
/// recovery policy. Boot describes the target; Snapshot decides whether a
/// root-only exchange is safe to perform.
pub fn require_boot_consistency(report: &BootConsistencyReport) -> Result<(), SnapshotError> {
    match report.status {
        BootConsistencyStatus::Consistent
            if report.checked_read_only && report.root_switch_covers_all_boot_resources =>
        {
            Ok(())
        }
        BootConsistencyStatus::Inconsistent => Err(SnapshotError::new(
            SnapshotErrorKind::BootConsistencyInconsistent,
            format!(
                "boot resources are inconsistent: {}",
                report.reasons.join("; ")
            ),
        )),
        BootConsistencyStatus::Unsupported => Err(SnapshotError::new(
            SnapshotErrorKind::UnsupportedExternalBootLayout,
            format!(
                "external boot resources are not supported by root-only recovery: {}",
                report.reasons.join("; ")
            ),
        )),
        BootConsistencyStatus::Unknown | BootConsistencyStatus::Consistent => {
            Err(SnapshotError::new(
                SnapshotErrorKind::BootConsistencyUnknown,
                format!(
                    "boot consistency was not established safely: {}",
                    report.reasons.join("; ")
                ),
            ))
        }
    }
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
) -> Result<(), SnapshotError> {
    validate_recovery_id(presented_plan_id)?;
    if presented_plan_id != plan.plan_id {
        return Err(SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "presented plan id does not match the plan record on disk",
        ));
    }
    let observed_digest = crate::plan::effective_plan_digest(plan)?;
    if observed_digest != plan.plan_digest {
        return Err(SnapshotError::new(
            SnapshotErrorKind::PlanDigestMismatch,
            format!(
                "effective plan digest changed: expected {}, observed {}",
                plan.plan_digest, observed_digest
            ),
        ));
    }
    let expected_token =
        crate::plan::build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);
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
        crate::model::TransactionPaths::backups_dir(),
        plan.plan_id
    );
    let expected_staging = format!(
        "{}/{}/new-root",
        crate::model::TransactionPaths::staging_dir(),
        plan.plan_id
    );
    if plan.backup_root_path != expected_backup || plan.staging_root_path != expected_staging {
        return Err(SnapshotError::new(
            SnapshotErrorKind::UnsafeRecoveryPath,
            "plan backup/staging paths do not match the canonical transaction layout",
        ));
    }
    let expected_boot_consistency =
        catos_boot::diagnose::layout::evaluate_readonly_consistency(&plan.boot_layout);
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
    let observed_digest = crate::plan::effective_plan_digest(plan)?;
    if observed_digest != plan.plan_digest {
        return Err(SnapshotError::new(
            SnapshotErrorKind::PlanDigestMismatch,
            "effective plan fields do not match the persisted digest",
        ));
    }
    let expected_token =
        crate::plan::build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);
    if plan.confirmation_token != expected_token {
        return Err(SnapshotError::new(
            SnapshotErrorKind::ConfirmationTokenMismatch,
            "persisted confirmation token is not bound to the effective plan",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catos_boot::diagnose::layout::evaluate_readonly_consistency;
    use catos_boot::model::BootLayout;

    #[test]
    fn root_contained_boot_resources_authorize_snapshot_recovery() {
        let report = evaluate_readonly_consistency(&BootLayout {
            boot_inside_root: true,
            kernel_versions: vec!["6.12.1-catos".into()],
            has_initramfs: true,
            ..BootLayout::default()
        });

        require_boot_consistency(&report).unwrap();
    }

    #[test]
    fn external_boot_resources_map_to_snapshot_policy_error() {
        let report = evaluate_readonly_consistency(&BootLayout {
            boot_separate_filesystem: true,
            ..BootLayout::default()
        });

        let error = require_boot_consistency(&report).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::UnsupportedExternalBootLayout);
    }

    #[test]
    fn unknown_boot_topology_fails_closed_for_snapshot_recovery() {
        let report = evaluate_readonly_consistency(&BootLayout::default());

        let error = require_boot_consistency(&report).unwrap_err();
        assert_eq!(error.kind, SnapshotErrorKind::BootConsistencyUnknown);
    }
}
