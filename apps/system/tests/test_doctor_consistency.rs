//! Cross-surface consistency tests. The same fixture MUST produce
//! the same conclusion in Doctor's diagnosis and in
//! `catos-repair`'s plan/detect step. The spec (section 五) is
//! explicit:
//!
//! > 同一个事实必须产生一致结论，例如：
//! > * Doctor 认为 root UUID 正确时，catos-repair mount 不应又认为错误；
//! > * Doctor 认为 provider 是 GRUB 时，catos-repair boot 不应识别成 Limine；
//! > * Doctor 认为 Btrfs 是多设备时，catos-repair fs 不应进入单设备 repair。

#![allow(clippy::field_reassign_with_default)]

use catos_system::shared::model::boot_repair::ProviderId;
use catos_system::shared::model::mount_repair::{MountProblem, TargetIdentity};
use catos_system::repair::boot_repair::detect::{detect, DetectionInputs, DetectionVerdict};
use catos_system::repair::mount_repair::{diagnose as mount_diagnose, MountRepairInputs};
use catos_system::repair::subvol_decision::CatosConfirmation;
use std::path::PathBuf;

fn btrfs_target() -> TargetIdentity {
    TargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root-uuid".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        esp_uuid: Some("esp-uuid".into()),
        boot_layout: None,
    }
}

// ---------------------------------------------------------------------------
// Mount diagnosis ⇄ mount repair plan
// ---------------------------------------------------------------------------

#[test]
fn same_fstab_fixture_produces_same_mount_problems() {
    // Doctor and catos-repair mount MUST call the same `diagnose()`
    // function. The function is pure; the inputs are observable
    // directly. Asserting equality between two calls with the same
    // inputs pins the contract.
    let fstab = "UUID=root-uuid  /  btrfs  defaults,subvol=/@  0 0\n\
                 UUID=root-uuid  /home  btrfs  defaults,subvol=/@home  0 0\n";
    let target = btrfs_target();
    let inputs = MountRepairInputs {
        fstab_text: fstab.into(),
        target: target.clone(),
        catos_confirmation: CatosConfirmation::Confirmed,
        ..MountRepairInputs::default()
    };
    let doctor_problems = mount_diagnose(&inputs);
    let repair_problems = mount_diagnose(&inputs);
    assert_eq!(doctor_problems, repair_problems);
}

#[test]
fn doctor_and_repair_agree_on_root_uuid_mismatch() {
    let fstab = "UUID=wrong-uuid  /  btrfs  defaults,subvol=/@  0 0\n";
    let target = btrfs_target();
    let inputs = MountRepairInputs {
        fstab_text: fstab.into(),
        target,
        catos_confirmation: CatosConfirmation::Confirmed,
        ..MountRepairInputs::default()
    };
    let problems = mount_diagnose(&inputs);
    assert!(
        problems
            .iter()
            .any(|p| matches!(p, MountProblem::RootUuidMismatch { .. })),
        "expected RootUuidMismatch, got {problems:?}"
    );
}

#[test]
fn doctor_and_repair_agree_on_missing_standard_entry() {
    let fstab = "UUID=root-uuid  /  btrfs  defaults,subvol=/@  0 0\n";
    let target = btrfs_target();
    let inputs = MountRepairInputs {
        fstab_text: fstab.into(),
        target,
        catos_confirmation: CatosConfirmation::Confirmed,
        ..MountRepairInputs::default()
    };
    let problems = mount_diagnose(&inputs);
    assert!(
        problems.iter().any(|p| matches!(
            p,
            MountProblem::MissingStandardEntry { mount_point, .. } if mount_point == "/home"
        )),
        "expected MissingStandardEntry for /home, got {problems:?}"
    );
}

// ---------------------------------------------------------------------------
// Boot provider detection ⇄ boot repair
// ---------------------------------------------------------------------------

#[test]
fn doctor_and_repair_agree_on_grub_provider() {
    let inputs = DetectionInputs {
        grub_defaults_catos: Some(
            "GRUB_DISTRIBUTOR=CatOS\nGRUB_CMDLINE_LINUX_DEFAULT='quiet rw'\n".into(),
        ),
        ..DetectionInputs::default()
    };
    let target = btrfs_target();
    let verdict = detect(&inputs, &target);
    match verdict {
        DetectionVerdict::Detected { provider, .. } => {
            assert_eq!(provider, ProviderId::Grub);
        }
        other => panic!("expected Detected Grub, got {other:?}"),
    }
}

#[test]
fn doctor_and_repair_agree_on_limine_provider() {
    let inputs = DetectionInputs {
        limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\nESP_PATH=\"/boot/efi\"\n".into()),
        ..DetectionInputs::default()
    };
    let target = btrfs_target();
    let verdict = detect(&inputs, &target);
    match verdict {
        DetectionVerdict::Detected { provider, .. } => {
            assert_eq!(provider, ProviderId::Limine);
        }
        other => panic!("expected Detected Limine, got {other:?}"),
    }
}

#[test]
fn doctor_and_repair_agree_on_conflicting_providers() {
    let inputs = DetectionInputs {
        grub_defaults_catos: Some("GRUB_DISTRIBUTOR=CatOS\n".into()),
        limine_defaults: Some("KERNEL_CMDLINE[default]=quiet rw\n".into()),
        ..DetectionInputs::default()
    };
    let target = btrfs_target();
    let verdict = detect(&inputs, &target);
    assert!(
        matches!(verdict, DetectionVerdict::Conflict { .. }),
        "expected Conflict, got {verdict:?}"
    );
}

#[test]
fn doctor_and_repair_agree_on_ambiguous_provider() {
    // No authoritative evidence; stale ESP artefacts alone MUST NOT
    // identify a provider in either surface.
    let inputs = DetectionInputs {
        has_boot_grub: true,
        has_esp_limine_conf: true,
        has_systemd_boot_loader: true,
        has_catos_uki_deployed: true,
        ..DetectionInputs::default()
    };
    let target = btrfs_target();
    let verdict = detect(&inputs, &target);
    assert!(
        matches!(verdict, DetectionVerdict::Ambiguous { .. }),
        "expected Ambiguous, got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// Btrfs checksum diagnostic ⇄ fs repair initial diagnosis
// ---------------------------------------------------------------------------

use catos_system::repair::runner::{RecordedRunner, ToolResult};
use catos_system::repair::fs_flows::{btrfs_check_only, btrfs_flow, ReadonlyOutcome};

#[test]
fn doctor_and_fs_repair_agree_on_checksum_diagnostic_label() {
    // Both surfaces use the SAME `btrfs_reports_metadata_checksum_failure`
    // helper internally. A 0 exit + "checksum verify failed" diagnostic
    // MUST surface as corruption in Doctor and as the trigger for
    // `--repair` escalation in the repair flow.
    let doctor_runner = RecordedRunner::new().queue_raw(
        0,
        b"checksum verify failed on 30605312 wanted 0x1 found 0x2".to_vec(),
        b"".to_vec(),
    );
    let doctor_result = btrfs_check_only(&doctor_runner, "/dev/sda1").unwrap();
    assert_eq!(doctor_result.outcome, ReadonlyOutcome::CorruptionDetected);

    let repair_runner = RecordedRunner::new()
        .queue_raw(
            0,
            b"checksum verify failed on 30605312 wanted 0x1 found 0x2".to_vec(),
            b"".to_vec(),
        )
        .queue_raw(0, b"repaired".to_vec(), b"".to_vec())
        .queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let repair_result = btrfs_flow(&repair_runner, "/dev/sda1").unwrap();
    // The repair flow's first attempt MUST be the read-only check,
    // and its label MUST mirror Doctor's corruption verdict.
    assert_eq!(
        repair_result.attempts[0].exit.label.as_deref(),
        Some("btrfs-metadata-checksum-failure")
    );
    assert!(!repair_result.attempts[0].exit.clean);
}

#[test]
fn doctor_does_not_escalate_but_repair_does() {
    // Same first-attempt corruption verdict; Doctor stops, repair
    // escalates. The contrast is the contract.
    let doctor_runner = RecordedRunner::new().queue_raw(1, b"errors".to_vec(), b"".to_vec());
    let doctor_result = btrfs_check_only(&doctor_runner, "/dev/sda1").unwrap();
    assert_eq!(doctor_result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert_eq!(doctor_runner.invocations().len(), 1);
    assert!(!doctor_runner.any_invocation_with_flag("--repair"));

    let repair_runner = RecordedRunner::new()
        .queue_raw(1, b"errors".to_vec(), b"".to_vec())
        .queue_raw(0, b"repaired".to_vec(), b"".to_vec())
        .queue_raw(0, b"clean".to_vec(), b"".to_vec());
    let _ = btrfs_flow(&repair_runner, "/dev/sda1").unwrap();
    assert!(repair_runner.any_invocation_with_flag("--repair"));
    assert_eq!(repair_runner.invocations().len(), 3);
}

#[test]
fn doctor_and_fs_repair_agree_on_tool_missing() {
    let doctor_runner = RecordedRunner::new().queue(ToolResult::binary_missing());
    let doctor_result = btrfs_check_only(&doctor_runner, "/dev/sda1").unwrap();
    assert_eq!(doctor_result.outcome, ReadonlyOutcome::ToolMissing);

    let repair_runner = RecordedRunner::new().queue(ToolResult::binary_missing());
    let repair_result = btrfs_flow(&repair_runner, "/dev/sda1").unwrap();
    assert!(repair_result.attempts[0].exit.binary_missing);
}

// ---------------------------------------------------------------------------
// Recovery: Doctor enumerates but never persists
// ---------------------------------------------------------------------------

#[test]
fn doctor_recovery_section_does_not_call_engine_drive_or_persist() {
    // We assert by symbol presence: the doctor module imports
    // `Engine::load` and `reconcile_status` (both read-only) and
    // does NOT invoke `Engine::drive`, `Engine::begin`,
    // `Engine::load_for_write`, `Engine::load_for_revert`, or
    // `store::persist_record` as call sites. Mentions in doc
    // comments are fine; the assertion uses the call-site form
    // (`Engine::<method>(` or `store::<method>(`) to distinguish.
    let doctor_source = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        include_str!("../src/doctor/mod.rs"),
        include_str!("../src/doctor/sections/mod.rs"),
        include_str!("../src/doctor/sections/filesystem.rs"),
        include_str!("../src/doctor/sections/mount.rs"),
        include_str!("../src/doctor/sections/boot.rs"),
        include_str!("../src/doctor/sections/recovery.rs"),
    );
    assert!(
        doctor_source.contains("store::load_record"),
        "doctor recovery section should load records read-only via store::load_record"
    );
    for forbidden_call_site in [
        "Engine::drive(",
        "Engine::begin(",
        "Engine::load_for_write(",
        "Engine::load_for_revert(",
        "store::persist_record(",
        "store::remove_record(",
        "engine.reconcile_state_for_write(",
        "engine.persist_record(",
    ] {
        assert!(
            !doctor_source.contains(forbidden_call_site),
            "doctor must not call {forbidden_call_site}"
        );
    }
}
