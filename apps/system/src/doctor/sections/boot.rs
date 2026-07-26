//! Boot provider and Secure Boot sections.

use std::path::Path;

use crate::shared::model::doctor::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::shared::model::evidence::Evidence;
use crate::shared::model::mount_repair::TargetIdentity;
use crate::repair::boot_repair::detect::{detect, DetectionInputs, DetectionVerdict};

use super::{has_target_path, push_evidence, read_target_file, set_section, target_root_path};

pub(in crate::doctor) fn run_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Boot;
    let inputs = collect_detection_inputs(target);
    push_boot_evidence(sections, id, &inputs);
    let verdict = detect(&inputs, target);
    match verdict {
        DetectionVerdict::Detected { provider, method, evidence } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "PROVIDER_DETECTED",
                    "repair::boot_repair::detect",
                    format!("provider={} method={:?}", provider.as_str(), method),
                ),
            );
            let assets_ok = inspect_provider_assets(target, provider);
            if assets_ok {
                set_section(sections, id, DoctorSectionStatus::Healthy);
            } else {
                let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
                section.issues.push(
                    DoctorIssue::new(
                        issue_code::BOOT_ASSET_MISSING,
                        DoctorSeverity::Error,
                        id,
                        format!(
                            "provider {} detected but expected boot assets are missing",
                            provider.as_str()
                        ),
                    )
                    .with_recommendation(recommendation_code::RUN_CATOS_REPAIR_BOOT),
                );
            }
        }
        DetectionVerdict::Conflict { providers, evidence } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
            section.issues.push(
                DoctorIssue::new(
                    issue_code::BOOT_PROVIDER_CONFLICT,
                    DoctorSeverity::Error,
                    id,
                    format!("conflicting authoritative evidence: {:?}", providers),
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
            report.recommendations.push(DoctorRecommendation::new(
                recommendation_code::MANUAL_REVIEW,
                "target has conflicting bootloader provider evidence; resolve before repair",
            ));
        }
        DetectionVerdict::Ambiguous { evidence } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            let section = set_section(sections, id, DoctorSectionStatus::Unknown);
            section.issues.push(
                DoctorIssue::new(
                    issue_code::BOOT_PROVIDER_AMBIGUOUS,
                    DoctorSeverity::Warning,
                    id,
                    "no provider has authoritative target-side evidence",
                )
                .with_recommendation(recommendation_code::MANUAL_REVIEW),
            );
        }
    }
    Ok(())
}

fn collect_detection_inputs(target: &TargetIdentity) -> DetectionInputs {
    let root = target_root_path(target);
    DetectionInputs {
        grub_defaults_catos: read_target_file(&root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(&root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(&root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(&root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(&root, "boot/grub"),
        has_esp_limine_conf: false,
        has_systemd_boot_loader: false,
        has_catos_uki_deployed: false,
        has_efistub_deployed: false,
        installed_packages: Vec::new(),
    }
}

fn inspect_provider_assets(
    target: &TargetIdentity,
    provider: crate::shared::model::boot_repair::ProviderId,
) -> bool {
    let root = target_root_path(target);
    match provider {
        crate::shared::model::boot_repair::ProviderId::Grub => has_target_path(&root, "boot/grub"),
        crate::shared::model::boot_repair::ProviderId::Limine => {
            read_target_file(&root, "etc/default/limine").is_some()
        }
        crate::shared::model::boot_repair::ProviderId::SystemdBoot => {
            read_target_file(&root, "etc/kernel/install.conf.d/20-catos-bootloadu.conf").is_some()
        }
        crate::shared::model::boot_repair::ProviderId::Uki
        | crate::shared::model::boot_repair::ProviderId::Efistub => {
            read_target_file(&root, "etc/catos/firmware-boot.conf").is_some()
        }
    }
}

fn provider_evidence_to_evidence(
    ev: crate::shared::model::boot_repair::ProviderEvidence,
) -> Evidence {
    Evidence::new(ev.code, ev.source, ev.message).with_value(format!(
        "provider={} authoritative={}",
        ev.provider.as_str(),
        ev.authoritative
    ))
}

fn push_boot_evidence(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    id: DoctorSectionId,
    inputs: &DetectionInputs,
) {
    let authoritative = [
        inputs.grub_defaults_catos.is_some(),
        inputs.limine_defaults.is_some(),
        inputs.kernel_install_catos.is_some(),
        inputs.firmware_boot_conf.is_some(),
    ];
    let count = authoritative.iter().filter(|b| **b).count();
    push_evidence(
        sections,
        id,
        Evidence::new(
            "DETECTION_INPUTS",
            "repair::boot_repair::detect",
            format!("{count} authoritative provider signal(s) present"),
        ),
    );
}

pub(in crate::doctor) fn run_secure_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::SecureBoot;
    let root = target_root_path(target);

    let firmware_sb_on = read_target_file(
        Path::new("/"),
        "sys/firmware/efi/efivars/SecureBoot-8be4df61-92ca-11d2-b0b3-00a0c91f6dba",
    )
    .map(|body| secure_boot_enabled_from_efivar(body.as_bytes()))
    .unwrap_or(None);
    let target_marker = read_target_file(&root, "etc/catos/secureboot").is_some();
    let firmware_boot_conf = read_target_file(&root, "etc/catos/firmware-boot.conf");

    push_evidence(
        sections,
        id,
        Evidence::new(
            "FIRMWARE_SECURE_BOOT",
            "doctor::secure_boot",
            format!("firmware runtime state: {:?}", firmware_sb_on),
        ),
    );
    push_evidence(
        sections,
        id,
        Evidence::new(
            "TARGET_POLICY_MARKER",
            "doctor::secure_boot",
            format!("/etc/catos/secureboot present: {target_marker}"),
        ),
    );

    let esp_present = target
        .boot_layout
        .as_ref()
        .and_then(|l| l.esp_mount_point())
        .is_some();
    if !esp_present && firmware_sb_on.is_none() && firmware_boot_conf.is_none() {
        set_section(sections, id, DoctorSectionStatus::NotApplicable);
        report.limitations.push(DoctorLimitation::new(
            id,
            "SECURE_BOOT_NOT_APPLICABLE",
            "target appears to be a BIOS layout; Secure Boot is not applicable",
        ));
        return Ok(());
    }

    let policy_inconsistent = target_marker != firmware_sb_on.unwrap_or(false)
        || (target_marker && firmware_boot_conf.is_none());
    if policy_inconsistent {
        let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
        section.issues.push(DoctorIssue::new(
            issue_code::SECURE_BOOT_STATE_INCOMPLETE,
            DoctorSeverity::Error,
            id,
            "Secure Boot policy is inconsistent across firmware runtime, target marker, and firmware-boot configuration",
        ));
        report.recommendations.push(DoctorRecommendation::new(
            recommendation_code::RUN_CATOS_REPAIR_BOOT,
            "Secure Boot policy is inconsistent; catos-repair boot can re-apply the target's existing policy",
        ));
    } else {
        set_section(sections, id, DoctorSectionStatus::Healthy);
    }
    Ok(())
}

fn secure_boot_enabled_from_efivar(body: &[u8]) -> Option<bool> {
    body.get(4).map(|b| *b != 0)
}
