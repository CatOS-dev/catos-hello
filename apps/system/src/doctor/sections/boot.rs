//! Boot provider and Secure Boot sections.

use std::path::Path;

use crate::boot::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::target::Evidence;

use super::{has_target_path, push_evidence, read_target_file, set_section, target_root_path};
use crate::doctor::DoctorTargetContext;

pub(in crate::doctor) fn run_boot_section(
    sections: &mut [(DoctorSectionId, DoctorSection)],
    context: Option<&DoctorTargetContext>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::Boot;
    let Some(context) = context else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(id, "TARGET_CONTEXT_UNAVAILABLE", "Boot requires the selected readonly Doctor target context"));
        return Ok(());
    };
    let inputs = match collect_detection_inputs(context) {
        Ok(inputs) => inputs,
        Err(message) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", message));
            return Ok(());
        }
    };
    let boot_layout = match context.boot_layout.as_ref() {
        Ok(layout) => layout.clone(),
        Err(error) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "BOOT_LAYOUT_INCOMPLETE", error.clone()));
            return Ok(());
        }
    };
    push_boot_evidence(sections, id, &inputs);
    push_evidence(
        sections,
        id,
        Evidence::new("BOOT_LAYOUT", "doctor::context", format!("selected target boot layout: {boot_layout:?}")),
    );
    let repair_target = crate::mount::model::MountTargetIdentity {
        root_device: match context.target.root_device.clone() {
            Some(device) => device,
            None => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", "selected target has no root device"));
                return Ok(());
            }
        },
        root_fstype: match context.target.root_fstype.clone() {
            Some(fstype) => fstype,
            None => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(id, "BOOT_FACTS_INCOMPLETE", "selected target has no root filesystem type"));
                return Ok(());
            }
        },
        root_subvol: context.target.root_subvol.clone(),
        root_uuid: context.target.root_uuid.clone(),
        esp_device: context.esp.as_ref().ok().and_then(|esp| esp.as_ref()).map(|esp| esp.device.clone()),
        esp_uuid: context.esp.as_ref().ok().and_then(|esp| esp.as_ref()).and_then(|esp| esp.uuid.clone()),
        boot_layout: Some(boot_layout),
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
            let assets_ok = match inspect_provider_assets(context, provider) {
                Ok(value) => value,
                Err(message) => {
                    set_section(sections, id, DoctorSectionStatus::Unknown);
                    report.limitations.push(DoctorLimitation::new(id, "BOOT_ASSETS_INCOMPLETE", message));
                    return Ok(());
                }
            };
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

fn collect_detection_inputs(context: &DoctorTargetContext) -> Result<DetectionInputs, String> {
    let root = target_root_path(&context.target);
    let esp = context.esp.as_ref().map_err(Clone::clone)?.as_ref();
    Ok(DetectionInputs {
        grub_defaults_catos: read_target_file(&root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(&root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(&root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(&root, "etc/kernel/cmdline"),
        has_boot_grub: boot_asset_exists(context, "grub")?,
        has_esp_limine_conf: esp.is_some_and(|esp| target_path_exists(esp.root.root(), "limine.conf")),
        has_systemd_boot_loader: esp.is_some_and(|esp| target_path_exists(esp.root.root(), "loader/loader.conf") || target_path_exists(esp.root.root(), "loader/entries")),
        has_catos_uki_deployed: esp.is_some_and(|esp| target_path_exists(esp.root.root(), "EFI/CatOS")),
        has_efistub_deployed: esp.is_some_and(|esp| target_path_exists(esp.root.root(), "EFI/CatOS")),
        installed_packages: installed_packages(&root)?,
    })
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
    context: &DoctorTargetContext,
    provider: crate::boot::model::ProviderId,
) -> Result<bool, String> {
    let root = target_root_path(&context.target);
    let esp = context.esp.as_ref().ok().and_then(|esp| esp.as_ref());
    Ok(match provider {
        crate::boot::model::ProviderId::Grub => boot_asset_exists(context, "grub")?,
        crate::boot::model::ProviderId::Limine => {
            esp.is_some_and(|esp| target_path_exists(esp.root.root(), "limine.conf"))
        }
        crate::boot::model::ProviderId::SystemdBoot => {
            esp.is_some_and(|esp| target_path_exists(esp.root.root(), "loader/loader.conf") || target_path_exists(esp.root.root(), "loader/entries"))
        }
        crate::boot::model::ProviderId::Uki | crate::boot::model::ProviderId::Efistub => {
            let Some(esp) = esp else { return Ok(false) };
            provider_firmware_asset_present(esp.root.root(), provider, read_target_file(&root, "etc/catos/firmware-boot.conf").as_deref())
        }
    })
}

fn boot_asset_exists(context: &DoctorTargetContext, relative: &str) -> Result<bool, String> {
    use crate::mount::model::BootMountLayout;

    match context.boot_layout.as_ref().map_err(Clone::clone)? {
        BootMountLayout::SeparateBootAndEsp { .. } | BootMountLayout::BootBtrfsSubvolume { .. } => {
            let session = context.boot.as_ref().map_err(Clone::clone)?
                .as_ref().ok_or_else(|| "selected target has an external /boot but no readonly boot session".to_string())?;
            Ok(target_path_exists(session.root(), relative))
        }
        BootMountLayout::EspAtBoot { .. } => {
            let esp = context.esp.as_ref().map_err(Clone::clone)?
                .as_ref().ok_or_else(|| "selected target has FAT /boot but no readonly ESP session".to_string())?;
            Ok(target_path_exists(esp.root.root(), relative))
        }
        BootMountLayout::BootInsideRoot
        | BootMountLayout::EspAtBootEfi { .. }
        | BootMountLayout::EspAtEfi { .. } => Ok(has_target_path(&context.target.root, &format!("boot/{relative}"))),
    }
}

fn provider_firmware_asset_present(
    esp_root: &Path,
    provider: crate::boot::model::ProviderId,
    firmware_boot_conf: Option<&str>,
) -> bool {
    let Some(firmware_boot_conf) = firmware_boot_conf else { return false };
    match provider {
        crate::boot::model::ProviderId::Uki => {
            firmware_boot_conf.contains("method=uki")
                && target_path_exists(esp_root, "EFI/Linux")
                && has_efi_file(esp_root.join("EFI/Linux"))
        }
        crate::boot::model::ProviderId::Efistub => {
            firmware_boot_conf.contains("method=efistub")
                && target_path_exists(esp_root, "EFI/CatOS")
                && has_efi_file(esp_root.join("EFI/CatOS"))
        }
        _ => false,
    }
}

fn has_efi_file(directory: std::path::PathBuf) -> bool {
    std::fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.file_type().ok().is_some_and(|kind| kind.is_file())
            && entry.file_name().to_str().is_some_and(|name| name.ends_with(".efi")))
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
    context: Option<&DoctorTargetContext>,
    report: &mut DoctorReport,
) -> Result<(), ()> {
    let id = DoctorSectionId::SecureBoot;
    let Some(context) = context else {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(id, "TARGET_CONTEXT_UNAVAILABLE", "Secure Boot requires the selected readonly Doctor target context"));
        return Ok(());
    };
    let root = target_root_path(&context.target);
    let esp = match context.esp.as_ref() {
        Ok(value) => value.as_ref(),
        Err(error) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "ESP_FACTS_INCOMPLETE", error.clone()));
            return Ok(());
        }
    };

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
            "TARGET_ESP_ASSETS",
            "doctor::secure_boot",
            match esp {
                Some(esp) => format!("selected target ESP {} mounted at {}", esp.device.display(), esp.mount_point),
                None => "selected target fstab did not identify an ESP; firmware mode is unknown".to_string(),
            },
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
    if esp.is_none() {
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "TARGET_ESP_UNAVAILABLE",
            "target firmware boot assets are unavailable; this is not interpreted as BIOS or Secure Boot disabled",
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

#[cfg(test)]
mod tests {
    use super::provider_firmware_asset_present;
    use crate::boot::model::ProviderId;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn uki_requires_uki_config_and_an_efi_file_in_efi_linux() {
        let root = scratch("uki");
        std::fs::create_dir_all(root.join("EFI/Linux")).unwrap();
        std::fs::write(root.join("EFI/Linux/catos.efi"), b"efi").unwrap();

        assert!(provider_firmware_asset_present(&root, ProviderId::Uki, Some("method=uki")));
        assert!(!provider_firmware_asset_present(&root, ProviderId::Efistub, Some("method=uki")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn efistub_rejects_an_empty_catos_directory() {
        let root = scratch("efistub-empty");
        std::fs::create_dir_all(root.join("EFI/CatOS")).unwrap();

        assert!(!provider_firmware_asset_present(&root, ProviderId::Efistub, Some("method=efistub")));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "catos-doctor-boot-{name}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }
}
