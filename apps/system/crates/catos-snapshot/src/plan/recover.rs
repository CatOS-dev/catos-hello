//! Canonical snapshot-plan digest and apply confirmation binding.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CatosIdentity, FstabRootDefinition,
    RecoveryPlan, SnapshotError,
};
use catos_boot::model::{BootConsistencyReport, BootLayout};

#[derive(Serialize)]
struct CanonicalEffectivePlan<'a> {
    schema_version: u32,
    plan_id: &'a str,
    filesystem: &'a BtrfsFilesystemIdentity,
    current_root: &'a BtrfsSubvolumeIdentity,
    source_snapshot: &'a BtrfsSubvolumeIdentity,
    target_catos_identity: &'a Option<CatosIdentity>,
    boot_layout: &'a BootLayout,
    boot_consistency: &'a BootConsistencyReport,
    backup_root_path: &'a str,
    staging_root_path: &'a str,
    fstab_root_definition: &'a FstabRootDefinition,
    predicted_steps: &'a [String],
    refusal_conditions: &'a [String],
    risks_and_warnings: &'a [String],
}

/// Hash the canonical execution-relevant plan. The persisted digest,
/// nonce, confirmation token, timestamps, host label, and evidence are
/// deliberately excluded so re-serialising JSON with a different field
/// order cannot alter the effective plan while preserving an old digest.
pub fn effective_plan_digest(plan: &RecoveryPlan) -> Result<String, SnapshotError> {
    let canonical = CanonicalEffectivePlan {
        schema_version: plan.schema_version,
        plan_id: &plan.plan_id,
        filesystem: &plan.filesystem,
        current_root: &plan.current_root,
        source_snapshot: &plan.source_snapshot,
        target_catos_identity: &plan.target_catos_identity,
        boot_layout: &plan.boot_layout,
        boot_consistency: &plan.boot_consistency,
        backup_root_path: &plan.backup_root_path,
        staging_root_path: &plan.staging_root_path,
        fstab_root_definition: &plan.fstab_root_definition,
        predicted_steps: &plan.predicted_steps,
        refusal_conditions: &plan.refusal_conditions,
        risks_and_warnings: &plan.risks_and_warnings,
    };
    let bytes = serde_json::to_vec(&canonical).map_err(|error| {
        SnapshotError::new(
            crate::model::SnapshotErrorKind::StateRecordCorrupt,
            format!("cannot serialise canonical recovery plan: {error}"),
        )
    })?;
    Ok(hex_encode(&Sha256::digest(bytes)))
}

/// Build the confirmation token from the immutable plan digest and
/// kernel-generated nonce. The token format is
/// `v2:<plan_id>:<sha256>`.
pub fn build_confirmation_token(plan_id: &str, plan_digest: &str, nonce: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"catos-recovery-confirmation-v2\0");
    digest.update(plan_id.as_bytes());
    digest.update(b"\0");
    digest.update(plan_digest.as_bytes());
    digest.update(b"\0");
    digest.update(nonce.as_bytes());
    format!("v2:{plan_id}:{}", hex_encode(&digest.finalize()))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, FstabRootDefinition, SnapshotErrorKind,
    };
    use crate::plan::create::{build_plan, PlanInputs};
    use crate::plan::rollback::{
        build_revert_confirmation_token, verify_revert_confirmation_token,
    };

    const PLAN_ID: &str = "tx-00000000000000000000000000000001";
    const OTHER_PLAN_ID: &str = "tx-00000000000000000000000000000002";

    fn inputs(read_only: bool) -> PlanInputs {
        PlanInputs {
            filesystem: BtrfsFilesystemIdentity {
                fsid: "fsid".into(),
                device_major_minor: "259:2".into(),
                label: None,
            },
            current_root: BtrfsSubvolumeIdentity {
                path: "/@".into(),
                subvolume_id: 256,
                generation: 100,
                uuid: None,
                parent_uuid: None,
                read_only: false,
                evidence: vec![],
            },
            source_snapshot: BtrfsSubvolumeIdentity {
                path: "/@snapshots/1".into(),
                subvolume_id: 300,
                generation: 80,
                uuid: None,
                parent_uuid: None,
                read_only,
                evidence: vec![],
            },
            boot_layout: BootLayout {
                boot_inside_root: true,
                boot_separate_filesystem: false,
                boot_separate_subvolume: false,
                esp_mount_point: None,
                esp_device: None,
                uki_paths: vec![],
                kernel_versions: vec![],
                has_initramfs: false,
            },
            catos_identity: None,
            fstab_root_definition: FstabRootDefinition {
                source: "/dev/nvme0n1p2".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
            },
            plan_id: PLAN_ID.into(),
            generated_at_unix: 1,
            generated_on_host: None,
            confirmation_token_entropy: vec![0u8; 32],
        }
    }

    #[test]
    fn build_plan_produces_stable_paths() {
        let plan = build_plan(inputs(true)).unwrap();
        assert_eq!(
            plan.backup_root_path,
            "/.catos-recovery/backups/tx-00000000000000000000000000000001/root-before"
        );
        assert_eq!(
            plan.staging_root_path,
            "/.catos-recovery/staging/tx-00000000000000000000000000000001/new-root"
        );
    }

    #[test]
    fn build_plan_rejects_non_readonly_snapshot() {
        let err = build_plan(inputs(false)).unwrap_err();
        assert_eq!(err.kind, SnapshotErrorKind::SnapshotNotReadonly);
    }

    #[test]
    fn build_plan_rejects_insufficient_entropy() {
        let mut i = inputs(true);
        i.confirmation_token_entropy = vec![0u8; 4];
        assert!(build_plan(i).is_err());
    }

    #[test]
    fn build_plan_rejects_empty_plan_id() {
        let mut i = inputs(true);
        i.plan_id = "".into();
        assert!(build_plan(i).is_err());
    }

    #[test]
    fn build_plan_rejects_path_and_unicode_plan_ids() {
        for invalid in [
            "../../outside",
            "/tmp/outside",
            "a/b",
            "tx-0123456789abcdef0123456789abcdeF",
            "tx-0123456789abcdef0123456789abcde\n",
            "tx-0123456789abcdef0123456789abcde０",
        ] {
            let mut i = inputs(true);
            i.plan_id = invalid.into();
            assert!(
                build_plan(i).is_err(),
                "invalid plan id was accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn confirmation_token_is_deterministic_for_same_inputs() {
        let t1 = build_confirmation_token(PLAN_ID, "ab", "cd");
        let t2 = build_confirmation_token(PLAN_ID, "ab", "cd");
        assert_eq!(t1, t2);
    }

    #[test]
    fn confirmation_token_differs_when_any_input_changes() {
        let base = build_confirmation_token(PLAN_ID, "digest-a", "nonce-a");
        assert_ne!(
            base,
            build_confirmation_token(OTHER_PLAN_ID, "digest-a", "nonce-a")
        );
        assert_ne!(
            base,
            build_confirmation_token(PLAN_ID, "digest-b", "nonce-a")
        );
        assert_ne!(
            base,
            build_confirmation_token(PLAN_ID, "digest-a", "nonce-b")
        );
    }

    #[test]
    fn confirmation_token_starts_with_v2_prefix() {
        let t = build_confirmation_token(PLAN_ID, "digest", "nonce");
        assert!(t.starts_with(&format!("v2:{PLAN_ID}:")));
    }

    #[test]
    fn revert_confirmation_token_binds_transaction_plan_fsid_state_and_nonce() {
        let base =
            build_revert_confirmation_token(PLAN_ID, "digest-a", "fsid-a", "completed", "nonce-a");
        assert_ne!(
            base,
            build_revert_confirmation_token(
                OTHER_PLAN_ID,
                "digest-a",
                "fsid-a",
                "completed",
                "nonce-a",
            )
        );
        assert_ne!(
            base,
            build_revert_confirmation_token(PLAN_ID, "digest-b", "fsid-a", "completed", "nonce-a",)
        );
        assert_ne!(
            base,
            build_revert_confirmation_token(PLAN_ID, "digest-a", "fsid-b", "completed", "nonce-a",)
        );
        assert_ne!(
            base,
            build_revert_confirmation_token(PLAN_ID, "digest-a", "fsid-a", "reverting", "nonce-a",)
        );
        assert_ne!(
            base,
            build_revert_confirmation_token(PLAN_ID, "digest-a", "fsid-a", "completed", "nonce-b",)
        );
        assert!(base.starts_with(&format!("revert-v1:{PLAN_ID}:")));
    }

    #[test]
    fn revert_confirmation_rejects_arbitrary_nonempty_and_stale_state_tokens() {
        let token =
            build_revert_confirmation_token(PLAN_ID, "digest-a", "fsid-a", "completed", "nonce-a");
        assert!(verify_revert_confirmation_token(
            PLAN_ID,
            "digest-a",
            "fsid-a",
            "completed",
            "nonce-a",
            &token,
        )
        .is_ok());
        assert!(verify_revert_confirmation_token(
            PLAN_ID,
            "digest-a",
            "fsid-a",
            "completed",
            "nonce-a",
            "anything",
        )
        .is_err());
        assert!(verify_revert_confirmation_token(
            PLAN_ID,
            "digest-a",
            "fsid-a",
            "reverting",
            "nonce-a",
            &token,
        )
        .is_err());
    }

    #[test]
    fn effective_plan_digest_changes_for_each_execution_field() {
        let plan = build_plan(inputs(true)).unwrap();
        let original = plan.plan_digest.clone();

        let mut changed = plan.clone();
        changed.filesystem.fsid.push('x');
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);

        let mut changed = plan.clone();
        changed.current_root.path = "/@root".into();
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);

        let mut changed = plan.clone();
        changed.source_snapshot.subvolume_id += 1;
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);

        let mut changed = plan.clone();
        changed
            .fstab_root_definition
            .options
            .push("subvol=/evil".into());
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);

        let mut changed = plan.clone();
        changed.boot_layout.boot_inside_root = false;
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);

        let mut changed = plan.clone();
        changed.backup_root_path = "/@".into();
        assert_ne!(effective_plan_digest(&changed).unwrap(), original);
    }

    #[test]
    fn predicted_steps_do_not_include_boot_finalization() {
        // Recovery MUST NOT call any bootloader tool. The predicted
        // step list is part of the JSON contract; pinning it here
        // guards against re-introducing a finalize_boot step.
        let plan = build_plan(inputs(true)).unwrap();
        assert!(!plan
            .predicted_steps
            .iter()
            .any(|s| s.contains("finalize") || s.contains("bootloader")));
        assert!(plan.predicted_steps.contains(&"verify_final".to_string()));
    }
}
