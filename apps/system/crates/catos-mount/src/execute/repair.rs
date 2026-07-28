//! Pure-mount apply: take a verified [`MountRepairPlan`] and apply the
//! fstab edit (atomic write), create the planned directories, and
//! establish the nested ESP mountpoint. btrfs subvolume creation is
//! injected by the caller via the `create_subvolume` hook so this
//! module never depends on the snapshot engine.
//!
//! The caller (repair orchestration) supplies the btrfs create hook;
//! everything else here is confined directory/mount/fstab work that
//! belongs to the mount capability.

use std::path::{Path, PathBuf};

use crate::diagnose::target::target_rooted_path;
use crate::execute::rollback::{ensure_nested_esp_mountpoint, rollback_mount_resources};
use crate::model::{
    AppliedAction, FstabTransaction, MountRepairCleanup, MountRepairOutcome, MountRepairPlan,
    MountRepairReport, MountVerification,
};
use crate::plan::repair::{apply_in_memory, digest_of, MountRepairInputs};
use crate::verify::verify_written_target;
use catos_target::execute::confined;
use catos_target::Evidence;

struct FstabSnapshot {
    text: String,
    mode: u32,
}

fn read_fstab_snapshot(top: &Path, rooted_path: &str) -> Result<FstabSnapshot, String> {
    let (bytes, mode) = confined::read_rooted_file_with_mode(top, rooted_path)
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8(bytes)
        .map_err(|error| format!("target fstab is not UTF-8: {error}"))?;
    Ok(FstabSnapshot { text, mode })
}

fn write_fstab_snapshot(
    top: &Path,
    rooted_path: &str,
    contents: &[u8],
    mode: u32,
) -> Result<(), catos_target::FsError> {
    confined::atomic_write_rooted(top, rooted_path, contents, mode)
}

/// Execute a verified plan against the mounted target root `top`.
///
/// `create_subvolume` is invoked for each planned subvolume; the
/// orchestration layer implements it with `create_btrfs_subvolume`
/// via the snapshot engine. Returning `Err(message)` from the hook
/// aborts the apply and triggers rollback exactly as a native
/// failure would.
pub fn execute_mount_repair(
    inputs: &MountRepairInputs,
    top: &Path,
    authorised: bool,
    devices: &[catos_target::model::BlockDevice],
    mut create_subvolume: impl FnMut(&Path, &str) -> Result<(), String>,
) -> MountRepairReport {
    let plan = crate::plan::repair::build_plan(inputs);
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
    let fstab_path = target_rooted_path(&inputs.target, "/etc/fstab");
    let fstab_snapshot = match read_fstab_snapshot(top, &fstab_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return MountRepairReport::refused(
                MountRepairOutcome::FstabChanged,
                &format!("cannot safely re-read target fstab: {error}"),
            );
        }
    };
    if digest_of(&fstab_snapshot.text) != plan.fstab_digest {
        return MountRepairReport::refused(
            MountRepairOutcome::FstabChanged,
            "target fstab changed after planning",
        );
    }

    let mut created = CreatedResources::default();

    for subvolume in &plan.subvolumes {
        if let Err(message) = create_subvolume(top, &subvolume.subvol) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                created,
                RepairFailure {
                    requested_outcome: MountRepairOutcome::SubvolumeConflict,
                    evidence_code: "SUBVOLUME_CREATE_FAILED",
                    message: format!("cannot create {}: {}", subvolume.subvol, message),
                    fstab_transaction: None,
                    verification: None,
                },
            );
        }
        created.subvolumes.push(subvolume.subvol.clone());
        created.actions.push(AppliedAction::SubvolumeCreated {
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
        let policy_observation = crate::plan::repair::PathObservation {
            is_symlink: observation.is_symlink,
            is_directory: observation.is_directory,
            is_regular_file: observation.is_other_object,
            is_other: false,
        };
        if let Err(error) =
            crate::plan::repair::validate_directory_creation(path, &policy_observation)
        {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                created,
                RepairFailure {
                    requested_outcome: MountRepairOutcome::UnsafePath,
                    evidence_code: "UNSAFE_MOUNTPOINT",
                    message: format!("{}: {error:?}", directory.mount_point),
                    fstab_transaction: None,
                    verification: None,
                },
            );
        }
        let target_path = target_rooted_path(&inputs.target, &directory.mount_point);
        if let Err(error) = confined::create_rooted_directory(top, &target_path) {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                created,
                RepairFailure {
                    requested_outcome: MountRepairOutcome::UnsafePath,
                    evidence_code: "MOUNTPOINT_CREATE_FAILED",
                    message: format!("{}: {error}", directory.mount_point),
                    fstab_transaction: None,
                    verification: None,
                },
            );
        }
        created.directories.push(directory.mount_point.clone());
        created.actions.push(AppliedAction::DirectoryCreated {
            mount_point: directory.mount_point.clone(),
        });
    }

    match ensure_nested_esp_mountpoint(top, &inputs.target, devices) {
        Ok(Some(mount_point)) => {
            created.nested_esp_directory_created = true;
            created
                .actions
                .push(AppliedAction::DirectoryCreated { mount_point });
        }
        Ok(None) => {}
        Err(reason) => {
            return failure_after_created_resources(
                inputs,
                plan.clone(),
                top,
                devices,
                created,
                RepairFailure {
                    requested_outcome: MountRepairOutcome::UnsafePath,
                    evidence_code: "NESTED_ESP_MOUNTPOINT_FAILED",
                    message: reason,
                    fstab_transaction: None,
                    verification: None,
                },
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
            created,
            RepairFailure {
                requested_outcome: MountRepairOutcome::RollbackFailed,
                evidence_code: "FSTAB_BACKUP_FAILED",
                message: error.to_string(),
                fstab_transaction: None,
                verification: None,
            },
        );
    }

    if let Err(error) = write_fstab_snapshot(
        top,
        &fstab_path,
        rewritten.as_bytes(),
        fstab_snapshot.mode,
    )
    {
        let rollback_succeeded =
            write_fstab_snapshot(
                top,
                &fstab_path,
                inputs.fstab_text.as_bytes(),
                fstab_snapshot.mode,
            )
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
            created,
            RepairFailure {
                requested_outcome: if rollback_succeeded {
                    MountRepairOutcome::VerificationFailed
                } else {
                    MountRepairOutcome::RollbackFailed
                },
                evidence_code: "FSTAB_WRITE_FAILED",
                message: error.to_string(),
                fstab_transaction: Some(transaction),
                verification: None,
            },
        );
    }
    created.actions.extend(
        plan.fstab_edits
            .iter()
            .cloned()
            .map(|edit| AppliedAction::FstabEdited { edit }),
    );

    let verification = verify_written_target(devices, &inputs.target, &rewritten, top);
    if !verification.mounted {
        let rollback_succeeded =
            write_fstab_snapshot(
                top,
                &fstab_path,
                inputs.fstab_text.as_bytes(),
                fstab_snapshot.mode,
            )
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
            created,
            RepairFailure {
                requested_outcome: if rollback_succeeded {
                    MountRepairOutcome::VerificationFailed
                } else {
                    MountRepairOutcome::RollbackFailed
                },
                evidence_code: "VERIFICATION_ROLLBACK",
                message: "verification failed; original fstab restoration was attempted".into(),
                fstab_transaction: Some(transaction),
                verification: Some(verification),
            },
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
        actions: created.actions,
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

/// Roll back every created resource after a mid-apply failure, then
/// assemble the failure report. The pure-mount side (directories +
/// nested ESP) is undone here; the pending btrfs subvolume rollbacks
/// are returned to the caller for snapshot-engine-driven deletion.
#[derive(Default)]
struct CreatedResources {
    actions: Vec<AppliedAction>,
    subvolumes: Vec<String>,
    directories: Vec<String>,
    nested_esp_directory_created: bool,
}

struct RepairFailure {
    requested_outcome: MountRepairOutcome,
    evidence_code: &'static str,
    message: String,
    fstab_transaction: Option<FstabTransaction>,
    verification: Option<MountVerification>,
}

fn failure_after_created_resources(
    inputs: &MountRepairInputs,
    plan: MountRepairPlan,
    top: &Path,
    devices: &[catos_target::model::BlockDevice],
    mut created: CreatedResources,
    failure: RepairFailure,
) -> MountRepairReport {
    let (mount_residuals, pending_subvolumes) = rollback_mount_resources(
        top,
        &inputs.target,
        devices,
        &created.subvolumes,
        &created.directories,
        created.nested_esp_directory_created,
        &mut created.actions,
    );
    // The btrfs subvolume rollbacks are the caller's responsibility.
    // Pending work is not itself a rollback failure: the orchestration
    // layer still has to drive the snapshot-engine deletion. Only real
    // pure-mount residuals force RollbackFailed at this stage.
    let final_outcome = if mount_residuals.is_empty() {
        failure.requested_outcome
    } else {
        MountRepairOutcome::RollbackFailed
    };
    let mut evidence = vec![Evidence::new(
        failure.evidence_code,
        "repair::mount",
        failure.message,
    )];
    for residual in &mount_residuals {
        evidence.push(Evidence::new(
            "ROLLBACK_RESIDUAL",
            "repair::mount",
            residual.clone(),
        ));
    }
    for pending in &pending_subvolumes {
        evidence.push(Evidence::new(
            "ROLLBACK_RESIDUAL",
            "repair::mount",
            format!("{}: pending btrfs subvolume rollback", pending.subvol),
        ));
    }
    MountRepairReport {
        target: Some(inputs.target.clone()),
        plan: Some(plan),
        fstab_transaction: failure.fstab_transaction,
        actions: created.actions,
        verification: failure.verification,
        cleanup: MountRepairCleanup::default(),
        final_outcome,
        requires_human_action: true,
        fully_complete: false,
        evidence,
        warnings: Vec::new(),
    }
}

// Apply_in_memory wrapper for callers that need the in-memory
// pre-check without the full apply path.
#[allow(dead_code)]
fn _apply_in_memory_anchor() {
    let _: fn(&str, &MountRepairPlan) -> Result<String, MountRepairOutcome> = apply_in_memory;
    let _: fn(&str) -> crate::model::FstabDigest = digest_of;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "catos-mount-fstab-mode-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("etc")).unwrap();
            Self(root)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn fstab_replacement_and_restore_preserve_original_mode() {
        let root = TempRoot::new();
        let path = root.0.join("etc/fstab");
        fs::write(&path, b"before\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let snapshot = read_fstab_snapshot(&root.0, "/etc/fstab").unwrap();
        assert_eq!(snapshot.text, "before\n");
        assert_eq!(snapshot.mode, 0o600);

        write_fstab_snapshot(&root.0, "/etc/fstab", b"after\n", snapshot.mode).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);

        write_fstab_snapshot(
            &root.0,
            "/etc/fstab",
            snapshot.text.as_bytes(),
            snapshot.mode,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "before\n");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    }
}
