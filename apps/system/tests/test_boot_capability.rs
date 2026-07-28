//! Stage-5 boot capability boundary tests.
//!
//! These tests pin the intended ownership: boot diagnosis, pure planning,
//! typed models, and target execution live under `boot`; Repair only composes
//! the capability with target discovery and mount sessions.

use std::path::PathBuf;

use catos_system::boot::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use catos_system::boot::execute::providers::base::{
    BootProviderExecutor, BootProviderVerifier, ProviderCtx,
};
use catos_system::boot::execute::providers::limine::LimineProvider;
use catos_system::boot::execute::target::{
    RecordedTargetRunner, TargetRequest, TargetRunner, TrustedTargetRunner,
};
use catos_system::boot::model::{Architecture, ProviderId};
use catos_system::boot::plan::cmdline::{build_kernel_cmdline, CmdlineInputs};
use catos_system::mount::model::MountTargetIdentity;

#[test]
fn provider_diagnosis_uses_authoritative_target_evidence() {
    let inputs = DetectionInputs {
        grub_defaults_catos: Some("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"".into()),
        installed_packages: vec!["limine".into()],
        ..DetectionInputs::default()
    };

    let verdict = detect(&inputs, &MountTargetIdentity::default());
    match verdict {
        DetectionVerdict::Detected { provider, .. } => assert_eq!(provider, ProviderId::Grub),
        other => panic!("expected authoritative GRUB detection, got {other:?}"),
    }
}

#[test]
fn cmdline_plan_is_pure_and_preserves_unowned_parameters() {
    let target = MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root-uuid".into()),
        ..MountTargetIdentity::default()
    };
    let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
        target: &target,
        existing_cmdline: "loglevel=3 mitigations=auto",
        has_plymouth: false,
        facts: &catos_system::boot::model::BootCmdlineFacts::default(),
    });

    assert!(conflicts.is_empty());
    assert!(cmdline.contains("root=UUID=root-uuid"));
    assert!(cmdline.contains("rootflags=subvol=/@"));
    assert!(cmdline.contains("loglevel=3"));
    assert!(cmdline.contains("mitigations=auto"));
}

#[test]
fn target_execution_refuses_non_allowlisted_binary_before_spawn() {
    let runner = TrustedTargetRunner::for_target("/");
    let result = runner.invoke(&TargetRequest::new(
        "sh",
        vec!["-c".into(), "touch /tmp/should-not-exist".into()],
        "attempt an untrusted shell command",
    ));

    assert_ne!(result.exit_code, 0);
    assert!(result.binary_missing);
    assert!(String::from_utf8_lossy(&result.stderr).contains("non-allow-list"));
}

#[test]
fn provider_execution_and_verification_have_distinct_contracts() {
    let target = MountTargetIdentity {
        root_device: PathBuf::from("/dev/nvme0n1p2"),
        root_fstype: "btrfs".into(),
        root_subvol: Some("/@".into()),
        root_uuid: Some("root-uuid".into()),
        esp_device: Some(PathBuf::from("/dev/nvme0n1p1")),
        ..MountTargetIdentity::default()
    };
    let ctx = ProviderCtx {
        target: &target,
        provider: ProviderId::Limine,
        cmdline: "quiet rw root=UUID=root-uuid rootflags=subvol=/@".into(),
        esp_mount_point: Some("/boot/efi".into()),
        bios_install_path: None,
        architecture: Architecture::X86_64,
        branding_name: "CatOS".into(),
        root_is_btrfs: true,
    };

    let execute_runner = RecordedTargetRunner::new()
        .expect_raw(
            "limine-install",
            std::iter::empty::<&str>(),
            0,
            Vec::new(),
            Vec::new(),
        )
        .expect_raw(
            "limine-update",
            std::iter::empty::<&str>(),
            0,
            Vec::new(),
            Vec::new(),
        );
    let execution = LimineProvider.execute(&ctx, &execute_runner);
    assert!(execution.failure.is_none());
    assert_eq!(execution.command_results.len(), 2);
    execute_runner.assert_consumed();

    let verify_runner = RecordedTargetRunner::new().expect_raw(
        "limine-list",
        std::iter::empty::<&str>(),
        0,
        Vec::new(),
        Vec::new(),
    );
    let verification = LimineProvider.verify(&ctx, &verify_runner);
    assert!(verification.passed);
    assert_eq!(verification.command_results.len(), 1);
    assert_eq!(verification.verification.checks, ["LIMINE_LIST"]);
    verify_runner.assert_consumed();
}
