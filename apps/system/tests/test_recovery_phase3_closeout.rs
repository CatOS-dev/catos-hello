//! Phase-3 closeout regression tests.
//!
//! Each test below pins a defect called out by the phase-3 closeout
//! brief. They are written BEFORE the implementation fixes so a
//! passing run after the fix is the evidence the defect is gone,
//! not a tautology.
//!
//! ## What each test prevents
//!
//! ### `--esp-device` contract
//!
//! A script that learned `--esp-device /dev/nvme0n1p1` from the
//! phase-2 `target` command will pass it to `recovery apply`
//! expecting ESP reconciliation. Phase 3 does NOT touch the ESP; if
//! the flag were silently ignored, the operator would boot into a
//! recovery that advertised ESP maintenance and shipped a system
//! whose bootloader resources disagreed with the new root. The
//! rejection MUST happen before any mount or write, otherwise a
//! future partial implementation could leak half-mounted state.
//!
//! ### Cleanup summary persistence contract
//!
//! The persisted transaction record's `last_cleanup` field is the
//! only durable evidence of whether the recovery environment was
//! clean when the transaction ended. Tests below pin the JSON
//! round-trip and the error-kind distinction so a future refactor
//! cannot silently drop the field, flip the boolean semantics, or
//! collapse `cleanup_incomplete` into a generic `syscall_failed`.
//!
//! ### Session directory security
//!
//! Live attack tests against `/run/catos-system/sessions/` require
//! root, a private mount namespace, and the ability to tear down
//! the runtime dir between tests. Those are exercised end-to-end in
//! the QEMU recovery smoke test. At unit level we lock the JSON
//! contract pieces that let operators diagnose an unclean shutdown
//! from outside the recovery environment.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

use catos_system::snapshot::model::{
    CleanupSummary, SnapshotError, SnapshotErrorKind, TransactionRecord, TransactionState,
    TX_RECORD_SCHEMA_VERSION,
};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_catos-system"))
}

fn run(args: &[&str]) -> (bool, i32, String, String) {
    let out = Command::new(bin_path()).args(args).output().unwrap();
    (
        out.status.success(),
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn minimal_plan_payload() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 4,
        "plan_id": "tx-00000000000000000000000000000001",
        "generated_at_unix": 1,
        "filesystem": {"fsid": "fsid-A", "device_major_minor": "259:0"},
        "current_root": {
            "path": "/@",
            "subvolume_id": 256,
            "generation": 10,
            "read_only": false,
        },
        "source_snapshot": {
            "path": "/@snapshots/1",
            "subvolume_id": 300,
            "generation": 8,
            "read_only": true,
        },
        "boot_layout": {
            "boot_inside_root": true,
            "boot_separate_filesystem": false,
            "boot_separate_subvolume": false,
            "has_initramfs": false,
        },
        "boot_consistency": {"status": "consistent"},
        "backup_root_path": "/.catos-recovery/backups/tx-00000000000000000000000000000001/root-before",
        "staging_root_path": "/.catos-recovery/staging/tx-00000000000000000000000000000001/new-root",
        "fstab_root_definition": {
            "source": "/dev/null",
            "fstype": "btrfs",
            "options": ["subvol=/@"]
        },
        "predicted_steps": [],
        "refusal_conditions": [],
        "risks_and_warnings": [],
        "nonce": "00".repeat(32),
        "plan_digest": "00".repeat(32),
        "confirmation_token": "v1:unused",
    })
}

// ===========================================================================
// A. --esp-device rejection contract
// ===========================================================================
//
// Failure mode: every phase-3 subcommand silently accepts
// `--esp-device`. inspect/plan never read it; apply reads it once
// (`let _ = selection.esp_device;`) and then ignores it. A wrapper
// script that builds on the phase-2 contract (`target plan
// --esp-device ...`) has no way to learn that recovery will not
// maintain the ESP until it is far too late.
//
// The fix rejects the flag up front with a stable error code BEFORE
// any probe mount or persistent write. These tests assert the
// rejection is observable from outside the process: non-zero exit,
// pure-JSON stdout, the stable code, no transaction directory.

#[test]
fn recovery_plan_rejects_explicit_esp_with_stable_error() {
    let (ok, code, stdout, stderr) = run(&[
        "recovery",
        "plan",
        "--root-device",
        "/dev/null",
        "--snapshot-subvolume",
        "/@snapshots/1",
        "--esp-device",
        "/dev/null",
        "--json",
    ]);
    assert!(!ok, "recovery plan accepted --esp-device");
    assert_ne!(
        code, 0,
        "exit code must be non-zero so wrappers detect the rejection"
    );
    assert!(stderr.is_empty(), "JSON failure leaked to stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|err| {
        panic!(
            "stdout is not valid JSON in --esp-device rejection: {err}\n--- stdout ---\n{stdout}"
        )
    });
    assert_eq!(value["kind"], "error");
    assert_eq!(
        value["payload"]["kind"],
        SnapshotErrorKind::UnsupportedExplicitEsp.code()
    );
}

#[test]
fn recovery_inspect_rejects_explicit_esp_before_probe() {
    let (ok, code, stdout, _stderr) = run(&[
        "recovery",
        "inspect",
        "--root-device",
        "/dev/null",
        "--snapshot-subvolume",
        "/@snapshots/1",
        "--esp-device",
        "/dev/null",
        "--json",
    ]);
    assert!(!ok);
    assert_ne!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value["payload"]["kind"],
        SnapshotErrorKind::UnsupportedExplicitEsp.code()
    );
    assert!(
        value["payload"]
            .get("mount_cleanup")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "rejection must happen before any mount; payload={}",
        value["payload"]
    );
}

#[test]
fn recovery_apply_rejects_explicit_esp_before_persistent_write() {
    let tempdir = std::env::temp_dir().join(format!(
        "catos-esp-apply-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&tempdir).unwrap();
    let plan_file = tempdir.join("plan.json");
    let envelope = serde_json::json!({
        "schemaVersion": 2,
        "programVersion": "0.1.0",
        "invocation": "catos-system",
        "targetRoot": "/",
        "kind": "recovery_plan",
        "payload": minimal_plan_payload(),
    });
    std::fs::write(&plan_file, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let (ok, code, stdout, _stderr) = run(&[
        "recovery",
        "apply",
        "--root-device",
        "/dev/null",
        "--root-subvolume",
        "/@",
        "--snapshot-subvolume",
        "/@snapshots/1",
        "--esp-device",
        "/dev/null",
        "--plan-id",
        "tx-00000000000000000000000000000001",
        "--confirm",
        "v1:unused",
        "--plan-file",
        plan_file.to_str().unwrap(),
        "--json",
    ]);
    let _ = std::fs::remove_dir_all(&tempdir);
    assert!(!ok);
    assert_ne!(code, 0);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value["payload"]["kind"],
        SnapshotErrorKind::UnsupportedExplicitEsp.code(),
        "payload: {value}"
    );
    assert!(
        value["payload"]
            .get("transaction_id")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "transaction_id was assigned before --esp-device rejection: {value}"
    );
}

#[test]
fn every_phase3_subcommand_rejects_explicit_esp() {
    let cases: &[&[&str]] = &[
        &[
            "recovery",
            "list",
            "--root-device",
            "/dev/null",
            "--esp-device",
            "/dev/null",
            "--json",
        ],
        &[
            "recovery",
            "status",
            "--root-device",
            "/dev/null",
            "--transaction",
            "tx-00000000000000000000000000000001",
            "--esp-device",
            "/dev/null",
            "--json",
        ],
        &[
            "recovery",
            "resume",
            "--root-device",
            "/dev/null",
            "--root-subvolume",
            "/@",
            "--transaction",
            "tx-00000000000000000000000000000001",
            "--esp-device",
            "/dev/null",
            "--json",
        ],
        &[
            "recovery",
            "revert",
            "--root-device",
            "/dev/null",
            "--transaction",
            "tx-00000000000000000000000000000001",
            "--confirm",
            "v1:unused",
            "--esp-device",
            "/dev/null",
            "--json",
        ],
    ];
    for args in cases {
        let (ok, code, stdout, _stderr) = run(args);
        assert!(!ok, "subcommand accepted --esp-device: {args:?}");
        assert_ne!(code, 0, "exit code for {args:?}");
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|err| panic!("non-JSON stdout for {args:?}: {err}\n{stdout}"));
        assert_eq!(
            value["payload"]["kind"],
            SnapshotErrorKind::UnsupportedExplicitEsp.code(),
            "wrong error kind for {args:?}: {value}"
        );
    }
}

// ===========================================================================
// B. Cleanup summary persistence contract
// ===========================================================================
//
// Failure mode: a future refactor stores cleanup state only in a
// local variable, persists the failure-state record without the
// cleanup section, or silently downgrades `MNT_DETACH` fallback
// success to `all_clean=true`. Each of those breaks the operator's
// ability to triage a dirty recovery environment after the fact.

fn sample_record_with_cleanup(summary: Option<CleanupSummary>) -> TransactionRecord {
    use catos_system::snapshot::model::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, FstabRootDefinition, RecoveryPlan,
        RECOVERY_PLAN_SCHEMA_VERSION,
    };
    let plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: "tx-00000000000000000000000000000001".into(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-A".into(),
            device_major_minor: "259:0".into(),
            label: None,
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 10,
            uuid: None,
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshots/1".into(),
            subvolume_id: 300,
            generation: 8,
            uuid: None,
            parent_uuid: None,
            read_only: true,
            evidence: vec![],
        },
        target_catos_identity: None,
        boot_layout: Default::default(),
        boot_consistency: catos_system::boot::diagnose::layout::evaluate_readonly_consistency(
            &Default::default(),
        ),
        backup_root_path: "/.catos-recovery/backups/tx-1/root-before".into(),
        staging_root_path: "/.catos-recovery/staging/tx-1/new-root".into(),
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/null".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: "00".repeat(32),
        confirmation_token: "v1:unused".into(),
        evidence: vec![],
    };
    TransactionRecord {
        schema_version: TX_RECORD_SCHEMA_VERSION,
        transaction_id: "tx-00000000000000000000000000000001".into(),
        created_at_unix: 1,
        last_updated_unix: 2,
        plan,
        state: TransactionState::Completed,
        completed_steps: vec![],
        last_error: None,
        last_disk_facts: None,
        last_cleanup: summary,
    }
}

#[test]
fn cleanup_summary_round_trips_through_record_json() {
    let summary = CleanupSummary {
        unmounted: vec!["/run/catos-system/sessions/recovery-rw-1234".into()],
        residual: vec![
            "/run/catos-system/sessions/recovery-rw-1234: umount2 failed (errno 16); detached lazily (busy)".into(),
        ],
        all_clean: false,
    };
    let record = sample_record_with_cleanup(Some(summary.clone()));
    let json = serde_json::to_string(&record).unwrap();
    let back: TransactionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.last_cleanup, Some(summary));
}

#[test]
fn unsupported_explicit_esp_kind_round_trips() {
    let kind = SnapshotErrorKind::UnsupportedExplicitEsp;
    let j = serde_json::to_string(&kind).unwrap();
    let back: SnapshotErrorKind = serde_json::from_str(&j).unwrap();
    assert_eq!(kind, back);
    assert_eq!(kind.code(), "unsupported_explicit_esp");
}

#[test]
fn cleanup_incomplete_error_kind_is_distinct_from_syscall_failed() {
    let err = SnapshotError::new(
        SnapshotErrorKind::CleanupIncomplete,
        "umount failed and detach also failed",
    );
    let j = serde_json::to_string(&err.kind).unwrap();
    assert!(j.contains("cleanup_incomplete"));
    assert!(!j.contains("syscall_failed"));
    assert_ne!(
        SnapshotErrorKind::CleanupIncomplete.code(),
        SnapshotErrorKind::SyscallFailed.code()
    );
}

#[test]
fn session_directory_error_kinds_have_distinct_stable_codes() {
    let cases = [
        (
            SnapshotErrorKind::SessionDirectoryNotSecure,
            "session_directory_not_secure",
        ),
        (
            SnapshotErrorKind::SessionDirectoryConflict,
            "session_directory_conflict",
        ),
        (
            SnapshotErrorKind::SessionDirectoryCleanupFailed,
            "session_directory_cleanup_failed",
        ),
    ];
    let mut seen = std::collections::HashSet::new();
    for (kind, expected) in cases {
        let j = serde_json::to_string(&kind).unwrap();
        let back: SnapshotErrorKind = serde_json::from_str(&j).unwrap();
        assert_eq!(kind, back);
        assert_eq!(kind.code(), expected);
        assert!(
            seen.insert(kind.code()),
            "code {} collides with another kind",
            kind.code()
        );
    }
    assert_ne!(
        SnapshotErrorKind::SessionDirectoryNotSecure.code(),
        SnapshotErrorKind::SyscallFailed.code()
    );
    assert_ne!(
        SnapshotErrorKind::SessionDirectoryConflict.code(),
        SnapshotErrorKind::SyscallFailed.code()
    );
    assert_ne!(
        SnapshotErrorKind::SessionDirectoryCleanupFailed.code(),
        SnapshotErrorKind::SyscallFailed.code()
    );
}

// ===========================================================================
// D. Cleanup lifecycle and exit-code contract
// ===========================================================================
//
// Failure mode: a future refactor routes the recovery write path
// through `mount_btrfs_toplevel_rw` again, returns the engine
// record without calling `attach_cleanup`, or changes
// `exit_code_for` so a Completed transaction with a dirty cleanup
// still exits 0. Each of those hides a dirty recovery environment
// behind a success status, defeating the whole point of the
// explicit cleanup contract.

/// Guards: `Phase3Outcome::Apply` carrying a Completed state but a
/// `last_cleanup` whose `all_clean` is false MUST surface a
/// non-zero exit. CI/CD pipelines that gate on `$?` would
/// otherwise ship a recovery whose residual mount leaks into the
/// next boot.
#[test]
fn exit_code_for_completed_apply_with_dirty_cleanup_is_nonzero() {
    use catos_system::recovery::{exit_code_for, Phase3Outcome};
    let record = sample_record_with_cleanup(Some(CleanupSummary {
        unmounted: Vec::new(),
        residual: vec![
            "/run/catos-system/sessions/recovery-rw-1234: umount2 failed (errno 16); detached lazily".into(),
        ],
        all_clean: false,
    }));
    let dirty_cleanup = CleanupSummary {
        unmounted: Vec::new(),
        residual: vec![
            "/run/catos-system/sessions/recovery-rw-1234: umount2 failed (errno 16); detached lazily".into(),
        ],
        all_clean: false,
    };
    let outcome = Phase3Outcome::Apply {
        record,
        final_state: TransactionState::Completed,
        cleanup: dirty_cleanup,
    };
    assert_ne!(
        exit_code_for(&outcome),
        catos_system::exit_code::SUCCESS,
        "Completed + dirty cleanup must NOT be SUCCESS"
    );
}

/// Guards: the symmetric revert case. A revert that reaches
/// `Reverted` but whose session cleanup is dirty must also surface
/// non-zero, otherwise a half-reverted system would look healthy.
#[test]
fn exit_code_for_reverted_with_dirty_cleanup_is_nonzero() {
    use catos_system::recovery::{exit_code_for, Phase3Outcome};
    let dirty_cleanup = CleanupSummary {
        unmounted: Vec::new(),
        residual: vec!["session directory cleanup: residual mount".into()],
        all_clean: false,
    };
    let record = sample_record_with_cleanup(Some(dirty_cleanup.clone()));
    let outcome = Phase3Outcome::Revert {
        record,
        final_state: TransactionState::Reverted,
        cleanup: dirty_cleanup,
    };
    assert_ne!(exit_code_for(&outcome), catos_system::exit_code::SUCCESS);
}

/// Guards: the happy path is unaffected. A Completed transaction
/// with a clean cleanup summary MUST still exit 0. Without this
/// guard, a future tightening of `exit_code_for` could regress to
/// always-non-zero, breaking the contract for healthy recoveries.
#[test]
fn exit_code_for_completed_apply_with_clean_cleanup_is_success() {
    use catos_system::recovery::{exit_code_for, Phase3Outcome};
    let clean_cleanup = CleanupSummary {
        unmounted: vec!["/run/catos-system/sessions/recovery-rw-1234".into()],
        residual: Vec::new(),
        all_clean: true,
    };
    let record = sample_record_with_cleanup(Some(clean_cleanup.clone()));
    let outcome = Phase3Outcome::Apply {
        record,
        final_state: TransactionState::Completed,
        cleanup: clean_cleanup,
    };
    assert_eq!(exit_code_for(&outcome), catos_system::exit_code::SUCCESS);
}

/// Guards: `Engine::attach_cleanup` preserves `last_error` when
/// the cleanup persistence itself fails. The closeout brief
/// explicitly forbids letting a cleanup error overwrite the
/// original transaction error. Without this test a future
/// refactor that swaps the persistence order would silently hide
/// the operation failure behind the cleanup failure (or vice
/// versa).
#[test]
fn attach_cleanup_does_not_clear_last_error() {
    use catos_system::snapshot::execute::engine::{Engine, EngineOptions};
    use catos_system::snapshot::model::{
        BtrfsFilesystemIdentity, CompletedStep, RecoveryPlan, RECOVERY_PLAN_SCHEMA_VERSION,
    };
    use std::path::PathBuf;

    let top = std::env::temp_dir().join(format!(
        "catos-attach-cleanup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&top).unwrap();

    let mut plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: "tx-00000000000000000000000000000009".into(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-attach-cleanup".into(),
            device_major_minor: "259:0".into(),
            label: None,
        },
        current_root: catos_system::snapshot::model::BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 10,
            uuid: None,
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: catos_system::snapshot::model::BtrfsSubvolumeIdentity {
            path: "/@snapshots/1".into(),
            subvolume_id: 300,
            generation: 8,
            uuid: None,
            parent_uuid: None,
            read_only: true,
            evidence: vec![],
        },
        target_catos_identity: None,
        boot_layout: Default::default(),
        boot_consistency: catos_system::boot::diagnose::layout::evaluate_readonly_consistency(
            &Default::default(),
        ),
        backup_root_path:
            "/.catos-recovery/backups/tx-00000000000000000000000000000009/root-before".into(),
        staging_root_path: "/.catos-recovery/staging/tx-00000000000000000000000000000009/new-root"
            .into(),
        fstab_root_definition: catos_system::snapshot::model::FstabRootDefinition {
            source: "/dev/null".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: String::new(),
        confirmation_token: String::new(),
        evidence: vec![],
    };
    plan.plan_digest = catos_system::snapshot::plan::effective_plan_digest(&plan).unwrap();
    plan.confirmation_token = catos_system::snapshot::plan::build_confirmation_token(
        &plan.plan_id,
        &plan.plan_digest,
        &plan.nonce,
    );
    let engine = Engine::begin(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        plan,
    )
    .expect("Engine::begin must persist the initial record");

    let injected_error = SnapshotError::new(
        SnapshotErrorKind::TargetChanged,
        "synthetic operation failure for the cleanup-preservation test",
    );

    // Mutate the persisted record to inject a pre-existing failure
    // state without depending on the `test-helpers` feature.
    {
        let state_path =
            top.join(".catos-recovery/transactions/tx-00000000000000000000000000000009/state.json");
        let mut record = catos_system::snapshot::store::load_record(&state_path).unwrap();
        record.last_error = Some(injected_error);
        record.state = catos_system::snapshot::model::TransactionState::FailedRecoverable;
        catos_system::snapshot::store::persist_record(&state_path, &record).unwrap();
    }
    let mut reloaded_engine = Engine::load(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: engine.record().plan.filesystem.clone(),
        },
        "tx-00000000000000000000000000000009",
    )
    .expect("reload must succeed");
    let persisted_error = reloaded_engine
        .record()
        .last_error
        .clone()
        .expect("failure state must have been persisted");
    assert_eq!(persisted_error.kind, SnapshotErrorKind::TargetChanged);

    let summary = CleanupSummary {
        unmounted: vec!["/run/catos-system/sessions/recovery-rw-test".into()],
        residual: vec![],
        all_clean: true,
    };
    reloaded_engine
        .attach_cleanup(summary.clone())
        .expect("attach_cleanup must succeed when state file is writable");
    assert_eq!(
        reloaded_engine.record().last_cleanup,
        Some(summary.clone()),
        "cleanup summary must be persisted"
    );
    assert_eq!(
        reloaded_engine.record().last_error.as_ref().map(|e| e.kind),
        Some(SnapshotErrorKind::TargetChanged),
        "attach_cleanup must NOT clear last_error"
    );

    let _ = CompletedStep {
        state: TransactionState::Planned,
        completed_at_unix: 0,
        description: String::new(),
    };
    let _ = std::fs::remove_dir_all(&top);
}

// ===========================================================================
// E. Session directory attack surface (unit-testable parts)
// ===========================================================================
//
// Live attack tests against `/run/catos-system/sessions/` require
// root and a private mount namespace; those scenarios run in the
// QEMU recovery smoke test. At unit level we lock the contract of
// the shared `secure_dir` helpers so phase 3 cannot regress to a
// weaker local copy.

/// Guards: two near-simultaneous invocations of the same session
/// prefix receive distinct paths. PID-only uniqueness races on PID
/// reuse; the helper MUST incorporate kernel randomness.
#[test]
fn secure_dir_fresh_session_name_includes_randomness() {
    use catos_system::mount::execute::secure_dir::fresh_session_name;
    let a = fresh_session_name("recovery-rw").unwrap();
    let b = fresh_session_name("recovery-rw").unwrap();
    assert!(a.starts_with("recovery-rw-"));
    assert!(b.starts_with("recovery-rw-"));
    assert_ne!(
        a, b,
        "two consecutive session names must not collide; PID-only uniqueness regressed"
    );
}

/// Guards: `secure_dir::remove_session_dir` refuses to operate on
/// a path that is not a direct child of the parent. Without this,
/// a future refactor that takes the path as an opaque argument
/// could be tricked into removing `/etc` if a caller passed it.
#[test]
fn secure_dir_remove_session_dir_refuses_outside_parent() {
    use catos_system::mount::execute::secure_dir::remove_session_dir;
    let parent = std::env::temp_dir().join(format!(
        "catos-remove-parent-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let elsewhere = std::env::temp_dir().join(format!(
        "catos-remove-elsewhere-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let err = remove_session_dir(&parent, &elsewhere).unwrap_err();
    assert_eq!(
        err.kind,
        catos_system::mount::session::MountSessionErrorKind::SessionDirectoryCleanupFailed
    );
    let _ = std::fs::remove_dir_all(parent);
    let _ = std::fs::remove_dir_all(elsewhere);
}

/// Guards: `secure_dir::remove_session_dir` refuses to remove a
/// symlink at the session path. A symlink attack where an attacker
/// pre-places `recovery-rw-<pid>` as a symlink to `/etc` would
/// otherwise let `remove_dir_all` recursively delete the host's
/// `/etc` during cleanup.
#[test]
fn secure_dir_remove_session_dir_refuses_symlink() {
    use catos_system::mount::execute::secure_dir::remove_session_dir;
    use std::os::unix::fs::symlink;
    let parent = std::env::temp_dir().join(format!(
        "catos-remove-symlink-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&parent).unwrap();
    let target = parent.join("recovery-rw-test");
    symlink("/etc", &target).unwrap();
    let err = remove_session_dir(&parent, &target).unwrap_err();
    assert_eq!(
        err.kind,
        catos_system::mount::session::MountSessionErrorKind::SessionDirectoryCleanupFailed
    );
    let _ = std::fs::remove_dir_all(&parent);
}

// ===========================================================================
// F. Cleanup-summary persistence engine API contract
// ===========================================================================
//
// Pins the engine API contract that drove the cleanup-persistence bug
// and its fix.
//
// `Engine::attach_cleanup(summary)` is the ONLY public API that persists
// a new `last_cleanup` value to the durable transaction record. Mutating
// `engine.record_mut().last_cleanup = Some(...)` updates the in-memory
// record only — it does NOT touch the on-disk state file. The pre-fix
// phase-3 orchestrator relied on exactly that non-persistent mutation
// to "restamp" the record after the rw mount session was torn down,
// leaving the on-disk record stuck on the pre-teardown placeholder.
// The fix removes that pattern from the orchestrator and adds a
// remount-based `attach_cleanup(real)` call so the on-disk record
// matches the renderer output.
//
// This test pins the engine API contract so a future change that
// accidentally makes `record_mut` persistent (which would silently
// mask orchestrator bugs by making everything persistent) OR removes
// `attach_cleanup`'s persistence (which would silently re-introduce
// the bug) is caught immediately. The orchestrator-level regression
// coverage lives in the QEMU recovery smoke test, which observes the
// on-disk record via `status` after a real apply.

#[test]
fn record_mut_last_cleanup_is_inmemory_only_and_attach_cleanup_persists() {
    use catos_system::snapshot::execute::engine::{Engine, EngineOptions};
    use catos_system::snapshot::model::{
        BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, FstabRootDefinition, RecoveryPlan,
        RECOVERY_PLAN_SCHEMA_VERSION,
    };
    use catos_system::snapshot::store;
    use std::path::PathBuf;

    let top = std::env::temp_dir().join(format!(
        "catos-record-mut-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&top).unwrap();

    let plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: "tx-0000000000000000000000000000000a".into(),
        generated_at_unix: 1,
        generated_on_host: None,
        filesystem: BtrfsFilesystemIdentity {
            fsid: "fsid-record-mut-contract".into(),
            device_major_minor: "259:0".into(),
            label: None,
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: 256,
            generation: 10,
            uuid: None,
            parent_uuid: None,
            read_only: false,
            evidence: vec![],
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshots/1".into(),
            subvolume_id: 300,
            generation: 8,
            uuid: None,
            parent_uuid: None,
            read_only: true,
            evidence: vec![],
        },
        target_catos_identity: None,
        boot_layout: Default::default(),
        boot_consistency: catos_system::boot::diagnose::layout::evaluate_readonly_consistency(
            &Default::default(),
        ),
        backup_root_path:
            "/.catos-recovery/backups/tx-0000000000000000000000000000000a/root-before".into(),
        staging_root_path: "/.catos-recovery/staging/tx-0000000000000000000000000000000a/new-root"
            .into(),
        fstab_root_definition: FstabRootDefinition {
            source: "/dev/null".into(),
            fstype: "btrfs".into(),
            options: vec!["subvol=/@".into()],
        },
        predicted_steps: vec![],
        refusal_conditions: vec![],
        risks_and_warnings: vec![],
        nonce: "00".repeat(32),
        plan_digest: String::new(),
        confirmation_token: String::new(),
        evidence: vec![],
    };
    let mut plan = plan;
    plan.plan_digest = catos_system::snapshot::plan::effective_plan_digest(&plan).unwrap();
    plan.confirmation_token = catos_system::snapshot::plan::build_confirmation_token(
        &plan.plan_id,
        &plan.plan_digest,
        &plan.nonce,
    );

    let mut engine = Engine::begin(
        EngineOptions {
            top_level_mount: top.clone(),
            device_path: PathBuf::from("/dev/null"),
            validated_filesystem: plan.filesystem.clone(),
        },
        plan,
    )
    .expect("Engine::begin must persist the initial record");

    let placeholder = CleanupSummary {
        unmounted: Vec::new(),
        residual: Vec::new(),
        all_clean: true,
    };
    engine
        .attach_cleanup(placeholder.clone())
        .expect("attach_cleanup must persist");

    let real = CleanupSummary {
        unmounted: vec!["/run/catos-system/sessions/recovery-rw-contract".into()],
        residual: Vec::new(),
        all_clean: true,
    };
    // Mimic the pre-fix orchestrator's post-teardown restamping.
    engine.record_mut().last_cleanup = Some(real.clone());

    // The in-memory record carries the restamped value.
    assert_eq!(
        engine.record().last_cleanup,
        Some(real.clone()),
        "in-memory record must reflect record_mut updates"
    );

    // The on-disk record does NOT — record_mut is non-persistent by
    // contract. attach_cleanup is the only persistent path.
    let state_path =
        top.join(".catos-recovery/transactions/tx-0000000000000000000000000000000a/state.json");
    let on_disk = store::load_record(&state_path).expect("on-disk record must load");
    assert_eq!(
        on_disk.last_cleanup,
        Some(placeholder),
        "on-disk record must carry the last attach_cleanup value, not a record_mut mutation"
    );
    assert_ne!(
        on_disk.last_cleanup,
        Some(real),
        "record_mut must NOT persist; if this fails, the engine API contract changed and every \
         orchestrator call site must be re-audited"
    );

    let _ = std::fs::remove_dir_all(&top);
}
