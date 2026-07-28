//! Stage-3 filesystem capability contract.
//!
//! These tests pin the architectural boundary that did not exist in
//! the former mixed filesystem flow: diagnosis is read-only, planning is pure data,
//! and execution requires an explicit typed plan.

use catos_system::fs::command::RecordedRunner;
use catos_system::fs::diagnose::{check_only_for, BtrfsTopology, ReadonlyOutcome};
use catos_system::fs::execute::{execute_repair_plan, FlowOutcome};
use catos_system::fs::model::RepairTool;
use catos_system::fs::plan::{build_repair_plan, FsRepairPlan};
use catos_system::fs::safety::{
    authorize_repair_plan, evaluate_safety, FsRepairAuthorization, RepairTargetSelection,
};
use catos_system::target::model::{BlockDevice, DeviceClass, DiskKind, PartitionRole};
use std::path::PathBuf;

fn authorize(plan: &FsRepairPlan, fstype: &str) -> FsRepairAuthorization {
    let device = BlockDevice {
        name: "test".into(),
        dev_path: Some(PathBuf::from(plan.device())),
        major_minor: Some("8:1".into()),
        parent: "sda".into(),
        class: DeviceClass::Partition,
        disk_kind: DiskKind::Gpt,
        partition_role: PartitionRole::LinuxFilesystem,
        partition_number: Some(1),
        size_sectors: Some(1_000_000),
        read_only: false,
        removable: false,
        filesystem: Some(fstype.into()),
        uuid: None,
        part_uuid: None,
        label: None,
        part_label: None,
        mount_point: None,
        mounts: vec![],
        mounted_before_session: false,
        evidence: vec![],
    };
    let decision = evaluate_safety(
        std::slice::from_ref(&device),
        &RepairTargetSelection {
            explicit_device: device.dev_path.clone(),
        },
        None,
    );
    authorize_repair_plan(&decision, plan).expect("safe test target must authorize the plan")
}

#[test]
fn planning_is_pure_and_does_not_need_a_runner() {
    let plan = build_repair_plan("ext4", "/dev/sda1", None)
        .expect("ext4 planning must succeed")
        .expect("ext4 is supported");

    assert!(matches!(plan, FsRepairPlan::Ext(_)));
    assert_eq!(plan.tool(), RepairTool::E2fsck);
    assert_eq!(plan.device(), "/dev/sda1");
}

#[test]
fn execution_requires_and_follows_the_typed_plan() {
    let plan = build_repair_plan("ext4", "/dev/sda1", None)
        .unwrap()
        .unwrap();
    let runner = RecordedRunner::new().expect_raw(
        "e2fsck",
        ["-y", "-C", "0", "/dev/sda1"],
        0,
        Vec::new(),
        Vec::new(),
    );

    let authorization = authorize(&plan, "ext4");
    let result = execute_repair_plan(&runner, &plan, &authorization)
        .expect("planned execution must complete");

    assert_eq!(result.outcome, FlowOutcome::Clean);
    let calls = runner.invocations();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].binary, "e2fsck");
    assert_eq!(calls[0].argv.last().map(String::as_str), Some("/dev/sda1"));
    runner.assert_consumed();
}

#[test]
fn readonly_diagnosis_cannot_escalate_to_repair() {
    let runner = RecordedRunner::new().expect_raw(
        "btrfs",
        ["check", "--readonly", "/dev/sda1"],
        1,
        b"errors".to_vec(),
        Vec::new(),
    );

    let result = check_only_for("btrfs", &runner, "/dev/sda1")
        .expect("read-only diagnosis must run")
        .expect("btrfs is supported");

    assert_eq!(result.outcome, ReadonlyOutcome::CorruptionDetected);
    assert!(!runner.any_invocation_with_flag("--repair"));
    assert_eq!(runner.invocation_count(), 1);
    runner.assert_consumed();
}

#[test]
fn btrfs_plan_refuses_unverified_or_multi_device_topology() {
    assert!(build_repair_plan("btrfs", "/dev/sda1", None).is_err());
    assert!(build_repair_plan("btrfs", "/dev/sda1", Some(BtrfsTopology::MultiDevice),).is_err());

    let plan = build_repair_plan("btrfs", "/dev/sda1", Some(BtrfsTopology::SingleDevice))
        .expect("verified single-device btrfs may be planned")
        .expect("btrfs is supported");
    assert!(matches!(plan, FsRepairPlan::Btrfs(_)));
}

#[test]
fn missing_tool_is_reported_by_execution_not_planning() {
    let plan = build_repair_plan("xfs", "/dev/sda1", None)
        .unwrap()
        .unwrap();
    let runner = RecordedRunner::new().expect_missing("xfs_repair", ["/dev/sda1"]);

    let authorization = authorize(&plan, "xfs");
    let result = execute_repair_plan(&runner, &plan, &authorization).unwrap();

    assert_eq!(result.outcome, FlowOutcome::ToolMissing);
    assert_eq!(runner.invocation_count(), 1);
    assert!(!runner.any_invocation_with_flag("-L"));
    runner.assert_consumed();
}

#[test]
fn mismatched_authorization_is_refused_before_runner_invocation() {
    let authorized_plan = build_repair_plan("ext4", "/dev/sda1", None)
        .unwrap()
        .unwrap();
    let authorization = authorize(&authorized_plan, "ext4");
    let other_plan = build_repair_plan("ext4", "/dev/sda2", None)
        .unwrap()
        .unwrap();
    let runner = RecordedRunner::new();

    let error = execute_repair_plan(&runner, &other_plan, &authorization)
        .expect_err("authorization must be bound to one concrete plan");

    assert!(error.message.contains("authorization"));
    assert_eq!(runner.invocation_count(), 0);
    runner.assert_consumed();
}
