//! Boot provider and Secure Boot sections.

use std::path::Path;

use crate::boot::diagnose::provider::{detect, DetectionInputs, DetectionVerdict};
use crate::doctor::model::{
    issue_code, recommendation_code, DoctorIssue, DoctorLimitation, DoctorRecommendation,
    DoctorReport, DoctorSection, DoctorSectionId, DoctorSectionStatus, DoctorSeverity,
};
use crate::target::Evidence;

use super::{
    push_evidence, read_target_file, set_section, target_repair_recommendation,
    target_root_path, target_supports_standard_root_repair,
};
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
            let summary = match provider_asset_summary(context, provider) {
                Ok(summary) => summary,
                Err(message) => {
                    set_section(sections, id, DoctorSectionStatus::Unknown);
                    report.limitations.push(DoctorLimitation::new(id, "BOOT_ASSETS_INCOMPLETE", message));
                    return Ok(());
                }
            };
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
            push_evidence(
                sections,
                id,
                Evidence::new(
                    "PROVIDER_ASSET_PATHS",
                    "doctor::boot-assets",
                    summary,
                ),
            );
            if assets_ok {
                set_section(sections, id, DoctorSectionStatus::Healthy);
            } else {
                let section = set_section(sections, id, DoctorSectionStatus::Unhealthy);
                let repair_recommendation_code = if target_supports_standard_root_repair(
                    &context.target,
                ) {
                    recommendation_code::RUN_CATOS_REPAIR_BOOT
                } else {
                    recommendation_code::MANUAL_REVIEW
                };
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
                    .with_recommendation(repair_recommendation_code),
                );
                let esp_device = context
                    .esp
                    .as_ref()
                    .ok()
                    .and_then(|esp| esp.as_ref())
                    .map(|esp| esp.device.as_path());
                report.recommendations.push(target_repair_recommendation(
                    "catos-repair boot",
                    &context.target,
                    esp_device,
                    recommendation_code::RUN_CATOS_REPAIR_BOOT,
                    format!(
                        "provider {} is missing required assets; re-apply the selected target's boot recipe",
                        provider.as_str()
                    ),
                    format!(
                        "provider {} is missing required assets, but automatic boot repair supports only the CatOS standard Btrfs root /@; review this nonstandard root manually",
                        provider.as_str()
                    ),
                ));
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
        grub_defaults_catos: read_optional_file(&root, "etc/default/grub.d/00-catos.cfg")?,
        limine_defaults: read_optional_file(&root, "etc/default/limine")?,
        kernel_install_catos: read_optional_file(
            &root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        )?,
        firmware_boot_conf: read_optional_file(&root, "etc/catos/firmware-boot.conf")?,
        kernel_cmdline: read_optional_file(&root, "etc/kernel/cmdline")?,
        has_boot_grub: boot_asset_exists(context, "grub")?,
        has_esp_limine_conf: esp.map_or(Ok(false), |esp| target_path_exists(esp.root.root(), "limine.conf"))?,
        has_systemd_boot_loader: esp.map_or(Ok(false), |esp| target_path_exists(esp.root.root(), "loader/loader.conf"))?,
        has_catos_uki_deployed: esp.map_or(Ok(false), |esp| target_path_exists(esp.root.root(), "EFI/Linux"))?,
        has_efistub_deployed: esp.map_or(Ok(false), |esp| target_path_exists(esp.root.root(), "EFI/CatOS"))?,
        installed_packages: installed_packages(&root)?,
    })
}

fn read_optional_file(root: &Path, relative: &str) -> Result<Option<String>, String> {
    read_target_file(root, relative)
}

fn rooted_path(relative: &str) -> String {
    format!("/{}", relative.trim_start_matches('/'))
}

fn target_path_exists(root: &Path, relative: &str) -> Result<bool, String> {
    use crate::target::execute::confined::{rooted_path_kind, RootedPathKind};
    let rooted = rooted_path(relative);
    match rooted_path_kind(root, &rooted) {
        Ok(None) => Ok(false),
        Ok(Some(RootedPathKind::Symlink)) => {
            Err(format!("target path {rooted} is a symlink"))
        }
        Ok(Some(_)) => Ok(true),
        Err(crate::target::error::FsError::NotFound) => Ok(false),
        Err(error) => Err(format!("cannot inspect target path {rooted}: {error}")),
    }
}

fn list_target_directory(root: &Path, relative: &str) -> Result<Option<Vec<String>>, String> {
    let rooted = rooted_path(relative);
    let result = if rooted == "/" {
        crate::target::execute::confined::list_root_directory_names(root)
    } else {
        crate::target::execute::confined::list_rooted_directory_names(root, &rooted)
    };
    match result {
        Ok(entries) => entries
            .into_iter()
            .map(|entry| {
                entry.into_string().map_err(|_| {
                    format!("target directory {rooted} contains a non-UTF-8 entry")
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Err(crate::target::error::FsError::NotFound) => Ok(None),
        Err(error) => Err(format!("cannot list target directory {rooted}: {error}")),
    }
}

fn valid_grub_config(root: &Path) -> Result<bool, String> {
    let Some(body) = read_optional_file(root, "grub/grub.cfg")? else {
        return Ok(false);
    };
    let meaningful: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    Ok(!meaningful.is_empty()
        && meaningful.iter().any(|line| line.contains("menuentry"))
        && meaningful
            .iter()
            .any(|line| line.starts_with("linux ") || line.starts_with("linuxefi ")))
}

fn valid_limine_config(root: &Path) -> Result<bool, String> {
    let Some(body) = read_optional_file(root, "limine.conf")? else {
        return Ok(false);
    };
    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    Ok(lines.iter().enumerate().any(|(index, line)| {
        line.starts_with(':')
            && lines[index + 1..].iter().any(|entry| {
                entry.starts_with("KERNEL_PATH=")
                    || entry.starts_with("LINUX=")
                    || entry.starts_with("PROTOCOL=")
            })
    }))
}

fn valid_systemd_loader(root: &Path) -> Result<bool, String> {
    let Some(entries) = list_target_directory(root, "loader/entries")? else {
        return Ok(false);
    };
    for entry in entries {
        let relative = format!("loader/entries/{entry}");
        let Some(body) = read_optional_file(root, &relative)? else {
            continue;
        };
        if !body.trim().is_empty()
            && body
                .lines()
                .any(|line| line.trim_start().starts_with("title "))
            && body.lines().any(|line| {
                line.trim_start().starts_with("linux ")
                    || line.trim_start().starts_with("efi ")
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn efi_asset(root: &Path, needle: &str) -> Result<Option<String>, String> {
    use crate::target::execute::confined::{rooted_path_kind, RootedPathKind};

    let mut stack = vec![String::from("/")];
    let mut inspected = 0usize;
    while let Some(directory) = stack.pop() {
        let Some(entries) = list_target_directory(root, &directory)? else {
            continue;
        };
        for entry in entries {
            inspected += 1;
            if inspected > 4096 {
                return Err("EFI asset tree exceeds the bounded 4096-entry scan".into());
            }
            let child = if directory == "/" {
                format!("/{entry}")
            } else {
                format!("{}/{}", directory.trim_end_matches('/'), entry)
            };
            match rooted_path_kind(root, &child) {
                Ok(Some(RootedPathKind::Directory)) => stack.push(child),
                Ok(Some(RootedPathKind::RegularFile)) => {
                    let name = entry.to_ascii_lowercase();
                    if name.ends_with(".efi") && name.contains(needle) {
                        return Ok(Some(child));
                    }
                }
                Ok(Some(RootedPathKind::Symlink)) => {
                    return Err(format!("EFI asset tree contains symlink {child}"));
                }
                Ok(Some(RootedPathKind::Other)) | Ok(None) => {}
                Err(error) => {
                    return Err(format!("cannot inspect EFI asset {child}: {error}"));
                }
            }
        }
    }
    Ok(None)
}

fn installed_packages(root: &Path) -> Result<Vec<String>, String> {
    let Some(entries) = list_target_directory(root, "var/lib/pacman/local")? else {
        return Err("selected target package database is missing".into());
    };
    let mut packages = Vec::new();
    for entry in entries {
        let relative = format!("var/lib/pacman/local/{entry}/desc");
        let desc = read_optional_file(root, &relative)?
            .ok_or_else(|| format!("target package record /{relative} is missing"))?;
        let name = pacman_package_name(&desc)
            .ok_or_else(|| format!("target package record /{relative} has no %NAME% field"))?;
        packages.push(name);
    }
    packages.sort();
    Ok(packages)
}

fn pacman_package_name(desc: &str) -> Option<String> {
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        if line == "%NAME%" {
            return lines
                .next()
                .map(str::to_string)
                .filter(|value| !value.is_empty());
        }
    }
    None
}

fn inspect_provider_assets(
    context: &DoctorTargetContext,
    provider: crate::boot::model::ProviderId,
) -> Result<bool, String> {
    let root = target_root_path(&context.target);
    let esp = context.esp.as_ref().ok().and_then(|esp| esp.as_ref());
    Ok(match provider {
        crate::boot::model::ProviderId::Grub => {
            let boot_root = boot_content_root(context)?;
            valid_grub_config(&boot_root)?
                && esp.map_or(Ok(false), |esp| {
                    efi_asset(esp.root.root(), "grub").map(|asset| asset.is_some())
                })?
        }
        crate::boot::model::ProviderId::Limine => {
            let Some(esp) = esp else { return Ok(false) };
            valid_limine_config(esp.root.root())?
                && efi_asset(esp.root.root(), "limine")?.is_some()
        }
        crate::boot::model::ProviderId::SystemdBoot => {
            let Some(esp) = esp else { return Ok(false) };
            valid_systemd_loader(esp.root.root())?
                && efi_asset(esp.root.root(), "systemd-boot")?.is_some()
        }
        crate::boot::model::ProviderId::Uki | crate::boot::model::ProviderId::Efistub => {
            let Some(esp) = esp else { return Ok(false) };
            provider_firmware_asset_present(
                esp.root.root(),
                provider,
                read_optional_file(&root, "etc/catos/firmware-boot.conf")?.as_deref(),
            )?
        }
    })
}

fn provider_asset_summary(
    context: &DoctorTargetContext,
    provider: crate::boot::model::ProviderId,
) -> Result<String, String> {
    let esp = context
        .esp
        .as_ref()
        .ok()
        .and_then(|esp| esp.as_ref())
        .map(|esp| esp.root.root());
    match provider {
        crate::boot::model::ProviderId::Grub => Ok(format!(
            "config={} asset={:?}",
            boot_content_root(context)?.join("grub/grub.cfg").display(),
            esp.map(|root| efi_asset(root, "grub")).transpose()?.flatten()
        )),
        crate::boot::model::ProviderId::Limine => Ok(format!(
            "config={} asset={:?}",
            esp.map(|root| root.join("limine.conf").display().to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            esp.map(|root| efi_asset(root, "limine"))
                .transpose()?
                .flatten()
        )),
        crate::boot::model::ProviderId::SystemdBoot => Ok(format!(
            "loader={} entry={} asset={:?}",
            esp.map(|root| root.join("loader/loader.conf").display().to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            esp.map(|root| root.join("loader/entries").display().to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            esp.map(|root| efi_asset(root, "systemd-boot"))
                .transpose()?
                .flatten()
        )),
        _ => Ok(
            "firmware provider asset paths are checked from target firmware-boot.conf and ESP"
                .into(),
        ),
    }
}

fn boot_content_root(context: &DoctorTargetContext) -> Result<std::path::PathBuf, String> {
    use crate::mount::model::BootMountLayout;
    match context.boot_layout.as_ref().map_err(Clone::clone)? {
        BootMountLayout::SeparateBootAndEsp { .. }
        | BootMountLayout::BootBtrfsSubvolume { .. } => context
            .boot
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .map(|session| session.root().to_path_buf())
            .ok_or_else(|| "selected target external /boot session is unavailable".to_string()),
        BootMountLayout::EspAtBoot { .. } => context
            .esp
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .map(|esp| esp.root.root().to_path_buf())
            .ok_or_else(|| "selected target FAT /boot session is unavailable".to_string()),
        BootMountLayout::BootInsideRoot
        | BootMountLayout::EspAtBootEfi { .. }
        | BootMountLayout::EspAtEfi { .. } => Ok(context.target.root.join("boot")),
    }
}

fn boot_asset_exists(context: &DoctorTargetContext, relative: &str) -> Result<bool, String> {
    use crate::mount::model::BootMountLayout;

    match context.boot_layout.as_ref().map_err(Clone::clone)? {
        BootMountLayout::SeparateBootAndEsp { .. }
        | BootMountLayout::BootBtrfsSubvolume { .. } => {
            let session = context
                .boot
                .as_ref()
                .map_err(Clone::clone)?
                .as_ref()
                .ok_or_else(|| {
                    "selected target has an external /boot but no readonly boot session".to_string()
                })?;
            target_path_exists(session.root(), relative)
        }
        BootMountLayout::EspAtBoot { .. } => {
            let esp = context
                .esp
                .as_ref()
                .map_err(Clone::clone)?
                .as_ref()
                .ok_or_else(|| {
                    "selected target has FAT /boot but no readonly ESP session".to_string()
                })?;
            target_path_exists(esp.root.root(), relative)
        }
        BootMountLayout::BootInsideRoot
        | BootMountLayout::EspAtBootEfi { .. }
        | BootMountLayout::EspAtEfi { .. } => {
            target_path_exists(&context.target.root, &format!("boot/{relative}"))
        }
    }
}

fn provider_firmware_asset_present(
    esp_root: &Path,
    provider: crate::boot::model::ProviderId,
    firmware_boot_conf: Option<&str>,
) -> Result<bool, String> {
    let Some(firmware_boot_conf) = firmware_boot_conf else {
        return Ok(false);
    };
    let method =
        crate::boot::diagnose::provider::parse_firmware_boot_method(firmware_boot_conf);
    match provider {
        crate::boot::model::ProviderId::Uki => Ok(
            method == Some(crate::boot::model::FirmwareMethod::Uki)
                && target_path_exists(esp_root, "EFI/Linux")?
                && has_efi_file(esp_root, "EFI/Linux")?,
        ),
        crate::boot::model::ProviderId::Efistub => Ok(
            method == Some(crate::boot::model::FirmwareMethod::Efistub)
                && target_path_exists(esp_root, "EFI/CatOS")?
                && has_efi_file(esp_root, "EFI/CatOS")?,
        ),
        _ => Ok(false),
    }
}

fn has_efi_file(root: &Path, relative: &str) -> Result<bool, String> {
    use crate::target::execute::confined::{rooted_path_kind, RootedPathKind};
    let Some(entries) = list_target_directory(root, relative)? else {
        return Ok(false);
    };
    for entry in entries {
        if !entry.to_ascii_lowercase().ends_with(".efi") {
            continue;
        }
        let child = format!("{}/{}", rooted_path(relative).trim_end_matches('/'), entry);
        match rooted_path_kind(root, &child) {
            Ok(Some(RootedPathKind::RegularFile)) => return Ok(true),
            Ok(Some(RootedPathKind::Symlink)) => {
                return Err(format!("EFI asset {child} is a symlink"));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect EFI asset {child}: {error}")),
        }
    }
    Ok(false)
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

    if !context.candidate.running_environment_member {
        let target_marker = match read_target_file(&root, "etc/catos/secureboot") {
            Ok(value) => value.is_some(),
            Err(error) => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(
                    id,
                    "SECURE_BOOT_POLICY_INCOMPLETE",
                    format!("cannot read target Secure Boot marker: {error}"),
                ));
                return Ok(());
            }
        };
        let firmware_boot_conf = match read_target_file(
            &root,
            "etc/catos/firmware-boot.conf",
        ) {
            Ok(value) => value,
            Err(error) => {
                set_section(sections, id, DoctorSectionStatus::Unknown);
                report.limitations.push(DoctorLimitation::new(
                    id,
                    "SECURE_BOOT_POLICY_INCOMPLETE",
                    format!("cannot read target firmware boot policy: {error}"),
                ));
                return Ok(());
            }
        };
        push_evidence(
            sections,
            id,
            Evidence::new(
                "TARGET_POLICY_MARKER",
                "doctor::secure_boot",
                format!("/etc/catos/secureboot present: {target_marker}"),
            ),
        );
        push_evidence(
            sections,
            id,
            Evidence::new(
                "TARGET_FIRMWARE_BOOT_POLICY",
                "doctor::secure_boot",
                format!(
                    "firmware-boot.conf present: {}",
                    firmware_boot_conf.is_some()
                ),
            ),
        );
        push_evidence(
            sections,
            id,
            Evidence::new(
                "TARGET_ESP_ASSETS",
                "doctor::secure_boot",
                match esp {
                    Some(esp) => format!(
                        "selected target ESP {} mounted at {}",
                        esp.device.display(),
                        esp.mount_point
                    ),
                    None => "selected target fstab did not identify an ESP".to_string(),
                },
            ),
        );
        set_section(sections, id, DoctorSectionStatus::Unknown);
        report.limitations.push(DoctorLimitation::new(
            id,
            "OFFLINE_FIRMWARE_STATE_UNAVAILABLE",
            "the Live environment firmware state is not evidence for the selected offline target",
        ));
        return Ok(());
    }

    let firmware_sb_body = match read_target_file(
        Path::new("/"),
        "sys/firmware/efi/efivars/SecureBoot-8be4df61-92ca-11d2-b0b3-00a0c91f6dba",
    ) {
        Ok(value) => value,
        Err(error) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "FIRMWARE_SECURE_BOOT_UNAVAILABLE", format!("cannot read firmware Secure Boot state: {error}")));
            return Ok(());
        }
    };
    let firmware_sb_on = firmware_sb_body.as_deref().and_then(|body| secure_boot_enabled_from_efivar(body.as_bytes()));
    let target_marker = match read_target_file(&root, "etc/catos/secureboot") {
        Ok(value) => value.is_some(),
        Err(error) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "SECURE_BOOT_POLICY_INCOMPLETE", format!("cannot read target Secure Boot marker: {error}")));
            return Ok(());
        }
    };
    let firmware_boot_conf = match read_target_file(&root, "etc/catos/firmware-boot.conf") {
        Ok(value) => value,
        Err(error) => {
            set_section(sections, id, DoctorSectionStatus::Unknown);
            report.limitations.push(DoctorLimitation::new(id, "SECURE_BOOT_POLICY_INCOMPLETE", format!("cannot read target firmware boot policy: {error}")));
            return Ok(());
        }
    };

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
        let esp_device = context
            .esp
            .as_ref()
            .ok()
            .and_then(|esp| esp.as_ref())
            .map(|esp| esp.device.as_path());
        report.recommendations.push(target_repair_recommendation(
            "catos-repair boot",
            &context.target,
            esp_device,
            recommendation_code::RUN_CATOS_REPAIR_BOOT,
            "Secure Boot policy is inconsistent; catos-repair boot can re-apply the target's existing policy",
            "Secure Boot policy is inconsistent, but automatic boot repair supports only the CatOS standard Btrfs root /@; review this nonstandard root manually",
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
    use super::{pacman_package_name, provider_firmware_asset_present, valid_grub_config, valid_limine_config, valid_systemd_loader, efi_asset};
    use crate::boot::model::ProviderId;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn uki_requires_uki_config_and_an_efi_file_in_efi_linux() {
        let root = scratch("uki");
        std::fs::create_dir_all(root.join("EFI/Linux")).unwrap();
        std::fs::write(root.join("EFI/Linux/catos.efi"), b"efi").unwrap();

        let writer_config = "[boot]\nmethod = uki\nesp_path = /boot/efi\n";
        assert!(provider_firmware_asset_present(
            &root,
            ProviderId::Uki,
            Some(writer_config),
        )
        .unwrap());
        assert!(!provider_firmware_asset_present(
            &root,
            ProviderId::Efistub,
            Some(writer_config),
        )
        .unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn efistub_rejects_an_empty_catos_directory() {
        let root = scratch("efistub-empty");
        std::fs::create_dir_all(root.join("EFI/CatOS")).unwrap();

        assert!(!provider_firmware_asset_present(&root, ProviderId::Efistub, Some("method=efistub")).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_name_comes_from_pacman_desc_not_directory_name() {
        assert_eq!(
            pacman_package_name("%NAME%\nlimine\n\n%VERSION%\n8.0-1\n"),
            Some("limine".to_string())
        );
    }

    #[test]
    fn grub_asset_matrix_requires_config_and_efi_binary() {
        let root = scratch("grub-matrix");
        std::fs::create_dir_all(root.join("grub")).unwrap();
        std::fs::create_dir_all(root.join("EFI/GRUB")).unwrap();
        std::fs::write(root.join("grub/grub.cfg"), "# menuentry fake\nmenuentry 'CatOS' {\n linux /vmlinuz\n}").unwrap();
        std::fs::write(root.join("EFI/GRUB/grubx64.efi"), b"efi").unwrap();
        assert!(valid_grub_config(&root).unwrap());
        assert!(efi_asset(&root, "grub").unwrap().is_some());
        std::fs::write(root.join("grub/grub.cfg"), b"# menuentry fake\nmenuentry 'CatOS' {\n echo no kernel\n}").unwrap();
        assert!(!valid_grub_config(&root).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn limine_asset_matrix_rejects_empty_config_or_missing_binary() {
        let root = scratch("limine-matrix");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("limine.conf"), "TIMEOUT=5\n:CatOS\n").unwrap();
        assert!(!valid_limine_config(&root).unwrap());
        std::fs::write(root.join("limine.conf"), "TIMEOUT=5\n:CatOS\nKERNEL_PATH=boot:///vmlinuz\n").unwrap();
        std::fs::write(root.join("liminex64.efi"), b"efi").unwrap();
        assert!(valid_limine_config(&root).unwrap());
        assert!(efi_asset(&root, "limine").unwrap().is_some());
        std::fs::remove_file(root.join("liminex64.efi")).unwrap();
        assert!(efi_asset(&root, "limine").unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn efi_asset_scan_refuses_symlink_escape() {
        let root = scratch("efi-symlink");
        let outside = scratch("efi-outside");
        std::fs::create_dir_all(root.join("EFI")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("grubx64.efi"), b"host").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("EFI/GRUB")).unwrap();
        assert!(efi_asset(&root, "grub").is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn systemd_boot_matrix_requires_entry_and_binary() {
        let root = scratch("systemd-matrix");
        std::fs::create_dir_all(root.join("loader/entries")).unwrap();
        std::fs::create_dir_all(root.join("EFI")).unwrap();
        std::fs::write(root.join("loader/loader.conf"), "default catos.conf\n").unwrap();
        std::fs::write(root.join("loader/entries/catos.conf"), "title CatOS\nlinux /vmlinuz\n").unwrap();
        std::fs::write(root.join("EFI/systemd-bootx64.efi"), b"efi").unwrap();
        assert!(valid_systemd_loader(&root).unwrap());
        assert!(efi_asset(&root, "systemd-boot").unwrap().is_some());
        std::fs::remove_file(root.join("EFI/systemd-bootx64.efi")).unwrap();
        assert!(efi_asset(&root, "systemd-boot").unwrap().is_none());
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
