//! Boot provider and Secure Boot sections.

use std::path::Path;

use crate::boot::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::target::model::TargetIdentity;
use crate::target::Evidence;

use super::{has_target_path, push_evidence, read_target_file, set_section, target_root_path};

pub(in crate::doctor) fn run_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    target: &TargetIdentity,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Boot;
    let inputs = match collect_detection_inputs(target) {
        Ok(inputs) => inputs,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", message));
            return Ok(());
        }
    };
    push_boot_evidence(sections, id, &inputs);
    let repair_target = crate::mount::model::MountTargetIdentity {
        root_device: match target.root_device.clone() {
            Some(device) => device,
            None => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", "selected target has no root device"));
                return Ok(());
            }
        },
        root_fstype: match target.root_fstype.clone() {
            Some(fstype) => fstype,
            None => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", "selected target has no root filesystem type"));
                return Ok(());
            }
        },
        root_subvol: target.root_subvol.clone(),
        root_uuid: target.root_uuid.clone(),
        esp_device: None,
        esp_uuid: None,
        boot_layout: None,
    };
    let verdict = detect(&inputs, &repair_target);
    match verdict {
        DetectionVerdict::Detected {
            provider,
            method,
            evidence,
        } => {
            for ev in evidence {
                push_evidence(sections, id, provider_evidence_to_evidence(ev));
            }
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "PROVIDER_DETECTED",
                    "boot::diagnose::provider",
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
        DetectionVerdict::Conflict {
            providers,
            evidence,
        } => {
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

fn collect_detection_inputs(target: &TargetIdentity) -> Result<DetectionInputs, String> {
    let root = target_root_path(target);
    if target_has_separate_esp(&root)? {
        return Err("target ESP is a separate filesystem and is not mounted in Doctor's selected readonly root session".to_string());
    }
    Ok(DetectionInputs {
        grub_defaults_catos: read_target_file(&root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(&root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(&root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(&root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(&root, "boot/grub"),
        has_esp_limine_conf: target_path_exists(&root, "boot/efi/limine.conf") || target_path_exists(&root, "efi/limine.conf"),
        has_systemd_boot_loader: target_path_exists(&root, "boot/efi/loader/loader.conf") || target_path_exists(&root, "efi/loader/loader.conf"),
        has_catos_uki_deployed: target_path_exists(&root, "boot/efi/EFI/CatOS") || target_path_exists(&root, "efi/EFI/CatOS"),
        has_efistub_deployed: target_path_exists(&root, "boot/efi/EFI/CatOS") || target_path_exists(&root, "efi/EFI/CatOS"),
        installed_packages: installed_packages(&root)?,
    })
}

fn target_has_separate_esp(root: &Path) -> Result<bool, String> {
    let fstab = std::fs::read_to_string(root.join("etc/fstab"))
        .map_err(|error| format!("cannot read target fstab for ESP layout: {error}"))?;
    Ok(crate::target::fstab::parse_all(&fstab).iter().any(|entry| {
        matches!(entry.target.as_str(), "/efi" | "/boot/efi")
    }))
}

fn target_path_exists(root: &Path, relative: &str) -> bool {
    std::fs::symlink_metadata(root.join(relative)).is_ok()
}

fn installed_packages(root: &Path) -> Result<Vec<String>, String> {
    let db = root.join("var/lib/pacman/local");
    let entries = std::fs::read_dir(&db)
        .map_err(|error| format!("cannot read target package database {}: {error}", db.display()))?;
    let mut packages: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect();
    packages.sort();
    Ok(packages)
}

fn inspect_provider_assets(
    target: &TargetIdentity,
    provider: crate::boot::model::ProviderId,
) -> bool {
    let root = target_root_path(target);
    match provider {
        crate::boot::model::ProviderId::Grub => has_target_path(&root, "boot/grub"),
        crate::boot::model::ProviderId::Limine => {
            read_target_file(&root, "etc/default/limine").is_some()
        }
        crate::boot::model::ProviderId::SystemdBoot => {
            read_target_file(&root, "etc/kernel/install.conf.d/20-catos-bootloadu.conf").is_some()
        }
        crate::boot::model::ProviderId::Uki | crate::boot::model::ProviderId::Efistub => {
            read_target_file(&root, "etc/catos/firmware-boot.conf").is_some()
        }
    }
}

fn provider_evidence_to_evidence(ev: crate::boot::model::ProviderEvidence) -> Evidence {
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
            "boot::diagnose::provider",
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

    if firmware_sb_on.is_none() {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "FIRMWARE_SECURE_BOOT_UNAVAILABLE",
            "current-machine firmware state is unavailable and cannot be inferred from an offline target",
        ));
        return Ok(());
    }
    if firmware_boot_conf.is_none() {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "SECURE_BOOT_POLICY_INCOMPLETE",
            "target Secure Boot policy configuration is unavailable; absence is not treated as disabled",
        ));
        return Ok(());
    }

    let policy_inconsistent = target_marker != firmware_sb_on.expect("checked firmware Secure Boot state")
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
