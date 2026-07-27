//! The privileged write path: `execute_mount_repair` takes a verified
//! [`MountRepairPlan`] and applies fstab edits, creates subvolumes and
//! directories, and mounts the ESP inside the target session.

#![allow(clippy::too_many_arguments)]

use std::path::{Path, PathBuf};

use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::{
    AppliedAction, FstabTransaction, MountRepairCleanup, MountRepairOutcome, MountRepairPlan,
    MountRepairReport, MountVerification, TargetIdentity,
};
use crate::shared::model::storage::BlockDevice;
use crate::shared::snapshot_engine::confined;
use crate::repair::path_safety::{validate_directory_creation, PathObservation};

use super::rollback::{
    ensure_nested_esp_mountpoint, failure_after_created_resources,
    rollback_created_resources,
};
use super::select::target_rooted_path;
use super::verify::verify_written_target;
use super::{apply_in_memory, build_plan, digest_of, MountRepairInputs};

pub(super) fn execute_mount_repair(
    inputs: &MountRepairInputs,
    top: &Path,
    authorised: bool,
    devices: &[BlockDevice],
) -> MountRepairReport {
    let plan = build_plan(inputs);
    if !authorised {
        return MountRepairReport {
            target: Some(inputs.target.clone()),
            plan: Some(plan),
            final_outcome: MountRepairOutcome::PartiallyRepaired,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new(
                "AUTHORIZATION_REQUIRED",
                "repair::mount",
                "mount repair requires explicit CLI authorization",
            )],
            ..Default::default()
        };
    }
    if !plan.unresolved_conflicts.is_empty() {
        return MountRepairReport::refused(
            MountRepairOutcome::ConflictingFstab,
            &plan.unresolved_conflicts.join("; "),
        );
    }
    if plan.fstab_edits.is_empty() && plan.subvolumes.is_empty() && plan.directories.is_empty() {
        let mut report = MountRepairReport::clean(inputs.target.clone());
        report.plan = Some(plan);
        return report;
    }
    let rewritten = match apply_in_memory(&inputs.fstab_text, &plan) {
        Ok(text) => text,
        Err(outcome) => {
            return MountRepairReport::refused(outcome, "fstab edits could not be applied safely");
        }
    };
    let current =
        match confined::read_rooted_file(top, &target_rooted_path(&inputs.target, "/etc/fstab"))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(text) => text,
            None => {
                return MountRepairReport::refused(
                    MountRepairOutcome::FstabChanged,
                    "cannot safely re-read target fstab",
                );
            }
        };
    if digest_of(&current) != plan.fstab_digest {
        return MountRepairReport::refused(
            MountRepairOutcome::FstabChanged,
            "target fstab changed after planning",
        );
    }

    let mut actions = Vec::new();
    let mut created_subvolumes = Vec::new();
    let mut created_directories = Vec::new();
    let mut nested_esp_directory_created = false;

    for subvolume in &plan.subvolumes {
        if let Err(error) = confined::create_btrfs_subvolume(top, &subvolume.subvol) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::SubvolumeConflict,
                "SUBVOLUME_CREATE_FAILED",
                format!("cannot create {}: {}", subvolume.subvol, error.message),
                None,
                None,
            );
        }
        created_subvolumes.push(subvolume.subvol.clone());
        actions.push(AppliedAction::SubvolumeCreated {
            subvol: subvolume.subvol.clone(),
        });
    }

    for directory in &plan.directories {
        let path = Path::new(&directory.mount_point);
        let observation = inputs
            .mount_point_observations
            .get(&directory.mount_point)
            .copied()
            .unwrap_or_default();
        let policy_observation = PathObservation {
            is_symlink: observation.is_symlink,
            is_directory: observation.is_directory,
            is_regular_file: observation.is_other_object,
            is_other: false,
        };
        if let Err(error) = validate_directory_creation(path, &policy_observation) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "UNSAFE_MOUNTPOINT",
                format!("{}: {error:?}", directory.mount_point),
                None,
                None,
            );
        }
        let target_path = target_rooted_path(&inputs.target, &directory.mount_point);
        if let Err(error) = confined::create_rooted_directory(top, &target_path) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "MOUNTPOINT_CREATE_FAILED",
                format!("{}: {}", directory.mount_point, error.message),
                None,
                None,
            );
        }
        created_directories.push(directory.mount_point.clone());
        actions.push(AppliedAction::DirectoryCreated {
            mount_point: directory.mount_point.clone(),
        });
    }

    match ensure_nested_esp_mountpoint(top, &inputs.target, devices) {
        Ok(Some(mount_point)) => {
            nested_esp_directory_created = true;
            actions.push(AppliedAction::DirectoryCreated { mount_point });
        }
        Ok(None) => {}
        Err(reason) => {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                actions,
                &created_subvolumes,
                &created_directories,
                nested_esp_directory_created,
                MountRepairOutcome::UnsafePath,
                "NESTED_ESP_MOUNTPOINT_FAILED",
                reason,
                None,
                None,
            );
        }
    }

    let backup_path = target_rooted_path(&inputs.target, "/etc/fstab.catos-repair.backup");
    if let Err(error) =
        confined::atomic_write_rooted(top, &backup_path, inputs.fstab_text.as_bytes(), 0o600)
    {
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            MountRepairOutcome::RollbackFailed,
            "FSTAB_BACKUP_FAILED",
            error.message.to_string(),
            None,
            None,
        );
    }

    let fstab_path = target_rooted_path(&inputs.target, "/etc/fstab");
    if let Err(error) = confined::atomic_write_rooted(top, &fstab_path, rewritten.as_bytes(), 0o644)
    {
        let rollback_succeeded =
            confined::atomic_write_rooted(top, &fstab_path, inputs.fstab_text.as_bytes(), 0o644)
                .is_ok();
        let transaction = FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: false,
            parent_fsynced: false,
            rollback_attempted: true,
            rollback_succeeded,
        };
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            if rollback_succeeded {
                MountRepairOutcome::VerificationFailed
            } else {
                MountRepairOutcome::RollbackFailed
            },
            "FSTAB_WRITE_FAILED",
            error.message.to_string(),
            Some(transaction),
            None,
        );
    }
    actions.extend(
        plan.fstab_edits
            .iter()
            .cloned()
            .map(|edit| AppliedAction::FstabEdited { edit }),
    );

    let verification = verify_written_target(devices, &inputs.target, &rewritten, top);
    if !verification.mounted {
        let rollback_succeeded =
            confined::atomic_write_rooted(top, &fstab_path, inputs.fstab_text.as_bytes(), 0o644)
                .is_ok();
        let transaction = FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: true,
            parent_fsynced: true,
            rollback_attempted: true,
            rollback_succeeded,
        };
        return failure_after_created_resources(
            inputs,
            plan.clone(),
            top,
            devices,
            actions,
            &created_subvolumes,
            &created_directories,
            nested_esp_directory_created,
            if rollback_succeeded {
                MountRepairOutcome::VerificationFailed
            } else {
                MountRepairOutcome::RollbackFailed
            },
            "VERIFICATION_ROLLBACK",
            "verification failed; original fstab restoration was attempted".into(),
            Some(transaction),
            Some(verification),
        );
    }

    let data_conflict = plan.subvolumes.iter().any(|subvolume| {
        inputs
            .mount_point_observations
            .get(&subvolume.mount_point)
            .and_then(|observation| observation.entry_count)
            .is_some_and(|count| count > 0)
    });
    MountRepairReport {
        target: Some(inputs.target.clone()),
        plan: Some(plan),
        fstab_transaction: Some(FstabTransaction {
            original_path: PathBuf::from("/etc/fstab"),
            backup_path: Some(PathBuf::from("/etc/fstab.catos-repair.backup")),
            temp_path: None,
            atomic_replace_succeeded: true,
            parent_fsynced: true,
            rollback_attempted: false,
            rollback_succeeded: false,
        }),
        actions,
        verification: Some(verification),
        cleanup: MountRepairCleanup::default(),
        final_outcome: if data_conflict {
            MountRepairOutcome::DataConflict
        } else {
            MountRepairOutcome::Repaired
        },
        requires_human_action: data_conflict,
        fully_complete: !data_conflict,
        evidence: vec![Evidence::new(
            "FSTAB_WRITTEN",
            "repair::mount",
            "target fstab replaced atomically after target-local validation",
        )],
        warnings: Vec::new(),
    }
}
