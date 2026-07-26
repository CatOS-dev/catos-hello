//! Bootloader provider detection. The single most important
//! behaviour of `catos-repair boot`: identify which provider the
//! target system currently uses, from the target's own
//! configuration and deployed artefacts.
//!
//! ## Hard rules
//!
//! * Detection never guesses from a single stale ESP file. A leftover
//!   `EFI/CatOS/grubx64.efi` from a previous GRUB install is NOT
//!   evidence that the current provider is GRUB if the target's
//!   `/etc` says it now uses systemd-boot.
//! * Authoritative sources (rank 1) are the target's `/etc`
//!   configuration files written by bootloadu itself. They are the
//!   only signals that, alone, identify a provider.
//! * Corroborating sources (rank 2) are ESP layout, deployed
//!   artefacts, and package presence. They support an existing
//!   authoritative signal but cannot establish one alone.
//! * When two providers each have authoritative evidence, detection
//!   returns [`DetectionVerdict::Conflict`].
//! * When zero providers have authoritative evidence, detection
//!   returns [`DetectionVerdict::Ambiguous`] regardless of how many
//!   corroborating signals exist.

use crate::shared::model::boot_repair::{FirmwareMethod, ProviderEvidence, ProviderId};
use crate::shared::model::mount_repair::TargetIdentity;

/// Inputs supplied by the orchestrator. All fields are observed
/// through the confined target reader; this module does no I/O.
#[derive(Debug, Clone, Default)]
pub struct DetectionInputs {
    /// Verbatim contents of `/etc/default/grub.d/00-catos.cfg` if it
    /// exists; `None` otherwise.
    pub grub_defaults_catos: Option<String>,
    /// Verbatim contents of `/etc/default/limine` if it exists.
    pub limine_defaults: Option<String>,
    /// Verbatim contents of
    /// `/etc/kernel/install.conf.d/20-catos-bootloadu.conf` if it
    /// exists.
    pub kernel_install_catos: Option<String>,
    /// Verbatim contents of `/etc/catos/firmware-boot.conf` if it
    /// exists.
    pub firmware_boot_conf: Option<String>,
    /// Verbatim contents of `/etc/kernel/cmdline` if it exists.
    pub kernel_cmdline: Option<String>,
    /// Whether `/boot/grub` exists in the target.
    pub has_boot_grub: bool,
    /// Whether a `limine.conf` was observed on the target ESP.
    pub has_esp_limine_conf: bool,
    /// Whether a systemd-boot loader entry was observed on the target
    /// ESP (`loader/loader.conf` or `loader/entries/`).
    pub has_systemd_boot_loader: bool,
    /// Whether the target has a CatOS UKI deployed on the ESP under
    /// the firmware-boot layout (`EFI/CatOS/*.efi` plus a matching
    /// `/etc/catos/firmware-boot.conf` with method=uki).
    pub has_catos_uki_deployed: bool,
    /// Whether the target has an EFI stub deployment registered
    /// through `/etc/catos/firmware-boot.conf` with method=efistub.
    pub has_efistub_deployed: bool,
    /// Target's installed package names, as read from its own pacman
    /// local DB. Used as corroborating evidence only.
    pub installed_packages: Vec<String>,
}

/// What detection concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionVerdict {
    /// One provider identified from authoritative evidence.
    Detected {
        provider: ProviderId,
        method: Option<FirmwareMethod>,
        evidence: Vec<ProviderEvidence>,
    },
    /// Multiple providers each have authoritative evidence. The
    /// orchestrator MUST refuse with `ambiguous_provider`.
    Conflict {
        providers: Vec<ProviderId>,
        evidence: Vec<ProviderEvidence>,
    },
    /// Zero providers have authoritative evidence. The orchestrator
    /// MUST refuse with `ambiguous_provider`.
    Ambiguous { evidence: Vec<ProviderEvidence> },
}

/// Run the evidence-based detection.
pub fn detect(inputs: &DetectionInputs, _target: &TargetIdentity) -> DetectionVerdict {
    let mut all_evidence: Vec<ProviderEvidence> = Vec::new();
    let mut authoritative: Vec<(ProviderId, Option<FirmwareMethod>)> = Vec::new();

    // Rank 1 — `/etc/catos/firmware-boot.conf`. Authoritative for
    // uki/efistub because bootloadu is the only writer.
    if let Some(conf) = inputs.firmware_boot_conf.as_deref() {
        if let Some(method) = parse_firmware_boot_method(conf) {
            let provider = match method {
                FirmwareMethod::Uki => ProviderId::Uki,
                FirmwareMethod::Efistub => ProviderId::Efistub,
            };
            all_evidence.push(ProviderEvidence {
                provider,
                code: "ETC_CATOS_FIRMWARE_BOOT_CONF".into(),
                source: "/etc/catos/firmware-boot.conf".into(),
                message: format!(
                    "method = {} declared by bootloadu-managed firmware-boot.conf",
                    method.as_str()
                ),
                authoritative: true,
            });
            authoritative.push((provider, Some(method)));
        }
    }

    // Rank 1 — `/etc/default/grub.d/00-catos.cfg`. Authoritative for
    // GRUB because bootloadu is the only writer of this exact file.
    if let Some(content) = inputs.grub_defaults_catos.as_deref() {
        if content.contains("GRUB_CMDLINE_LINUX_DEFAULT=") || content.contains("GRUB_DISTRIBUTOR=")
        {
            all_evidence.push(ProviderEvidence {
                provider: ProviderId::Grub,
                code: "ETC_DEFAULT_GRUB_D_CATOS".into(),
                source: "/etc/default/grub.d/00-catos.cfg".into(),
                message: "bootloadu-managed GRUB defaults file is present".into(),
                authoritative: true,
            });
            authoritative.push((ProviderId::Grub, None));
        }
    }

    // Rank 1 — `/etc/default/limine`. Authoritative for Limine.
    if let Some(content) = inputs.limine_defaults.as_deref() {
        if content.contains("KERNEL_CMDLINE[default]=") || content.contains("ESP_PATH=") {
            all_evidence.push(ProviderEvidence {
                provider: ProviderId::Limine,
                code: "ETC_DEFAULT_LIMINE".into(),
                source: "/etc/default/limine".into(),
                message: "bootloadu-managed Limine defaults file is present".into(),
                authoritative: true,
            });
            authoritative.push((ProviderId::Limine, None));
        }
    }

    // Rank 1 — `/etc/kernel/install.conf.d/20-catos-bootloadu.conf`.
    // Authoritative for systemd-boot.
    if let Some(content) = inputs.kernel_install_catos.as_deref() {
        if content.contains("BOOT_ROOT=") && content.contains("layout=bls") {
            all_evidence.push(ProviderEvidence {
                provider: ProviderId::SystemdBoot,
                code: "ETC_KERNEL_INSTALL_CATOS".into(),
                source: "/etc/kernel/install.conf.d/20-catos-bootloadu.conf".into(),
                message: "bootloadu-managed systemd-boot install.conf is present".into(),
                authoritative: true,
            });
            authoritative.push((ProviderId::SystemdBoot, None));
        }
    }

    // Rank 2 — corroborating ESP + package evidence. None of these
    // are authoritative on their own; they only support (or refute)
    // an existing authoritative signal.
    if inputs.has_boot_grub {
        all_evidence.push(corroborating(
            ProviderId::Grub,
            "BOOT_GRUB_DIR",
            "/boot/grub",
            "target has a /boot/grub directory",
        ));
    }
    if inputs.has_esp_limine_conf {
        all_evidence.push(corroborating(
            ProviderId::Limine,
            "ESP_LIMINE_CONF",
            "<ESP>/limine.conf",
            "target ESP carries a limine.conf",
        ));
    }
    if inputs.has_systemd_boot_loader {
        all_evidence.push(corroborating(
            ProviderId::SystemdBoot,
            "ESP_SYSTEMD_BOOT_LOADER",
            "<ESP>/loader",
            "target ESP carries a systemd-boot loader tree",
        ));
    }
    if inputs.has_catos_uki_deployed {
        all_evidence.push(corroborating(
            ProviderId::Uki,
            "ESP_CATOS_UKI",
            "<ESP>/EFI/CatOS",
            "target ESP carries a CatOS UKI deployment",
        ));
    }
    if inputs.has_efistub_deployed {
        all_evidence.push(corroborating(
            ProviderId::Efistub,
            "ESP_CATOS_EFISTUB",
            "<ESP>/EFI/CatOS",
            "target ESP carries a CatOS EFI stub deployment",
        ));
    }

    // Corroborating package presence. Each provider has a small set
    // of distinctive runtime packages; we record them only as
    // supporting evidence.
    add_package_evidence(&mut all_evidence, &inputs.installed_packages);

    // Reduce the authoritative signals. De-duplicate identical
    // (provider, method) tuples so a single source counts once.
    authoritative.dedup();
    match authoritative.len() {
        0 => DetectionVerdict::Ambiguous {
            evidence: all_evidence,
        },
        1 => {
            let (provider, method) = authoritative[0];
            DetectionVerdict::Detected {
                provider,
                method,
                evidence: all_evidence,
            }
        }
        _ => {
            let providers: Vec<ProviderId> = authoritative
                .iter()
                .map(|(provider, _)| *provider)
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            DetectionVerdict::Conflict {
                providers,
                evidence: all_evidence,
            }
        }
    }
}

fn corroborating(
    provider: ProviderId,
    code: &str,
    source: &str,
    message: &str,
) -> ProviderEvidence {
    ProviderEvidence {
        provider,
        code: code.to_string(),
        source: source.to_string(),
        message: message.to_string(),
        authoritative: false,
    }
}

fn add_package_evidence(evidence: &mut Vec<ProviderEvidence>, installed: &[String]) {
    let distinct: Vec<ProviderId> = ProviderId::all().to_vec();
    for provider in distinct {
        let packages = crate::repair::boot_repair::registry::profile(provider).runtime_packages;
        let present: Vec<&str> = packages
            .iter()
            .copied()
            .filter(|pkg| installed.iter().any(|installed| installed == pkg))
            .collect();
        if present.is_empty() {
            continue;
        }
        evidence.push(ProviderEvidence {
            provider,
            code: "TARGET_PACKAGE_PRESENT".into(),
            source: "/var/lib/pacman/local".into(),
            message: format!("target reports package(s): {}", present.join(", ")),
            authoritative: false,
        });
    }
}

/// Parse the `method = ...` line out of
/// `/etc/catos/firmware-boot.conf`. Mirrors bootloadu's writer.
pub fn parse_firmware_boot_method(conf: &str) -> Option<FirmwareMethod> {
    for line in conf.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            if key.trim() == "method" {
                return FirmwareMethod::parse_registry_str(value.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn empty_target() -> TargetIdentity {
        TargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root".into()),
            esp_device: Some(PathBuf::from("/dev/sda1")),
            esp_uuid: Some("esp".into()),
            boot_layout: None,
        }
    }

    #[test]
    fn grub_defaults_is_authoritative_for_grub() {
        let inputs = DetectionInputs {
            grub_defaults_catos: Some(
                "GRUB_DISTRIBUTOR=CatOS\nGRUB_CMDLINE_LINUX_DEFAULT='quiet rw'\n".into(),
            ),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Detected { provider, .. } => {
                assert_eq!(provider, ProviderId::Grub);
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn limine_defaults_is_authoritative_for_limine() {
        let inputs = DetectionInputs {
            limine_defaults: Some(
                "ESP_PATH=\"/boot/efi\"\nKERNEL_CMDLINE[default]=quiet rw\n".into(),
            ),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Detected { provider, .. } => {
                assert_eq!(provider, ProviderId::Limine);
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn systemd_boot_install_conf_is_authoritative() {
        let inputs = DetectionInputs {
            kernel_install_catos: Some("BOOT_ROOT=/boot/efi\nlayout=bls\n".into()),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Detected { provider, .. } => {
                assert_eq!(provider, ProviderId::SystemdBoot);
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn firmware_boot_conf_uki_is_authoritative() {
        let inputs = DetectionInputs {
            firmware_boot_conf: Some("[boot]\nmethod = uki\nesp_path = /boot/efi\n".into()),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Detected {
                provider, method, ..
            } => {
                assert_eq!(provider, ProviderId::Uki);
                assert_eq!(method, Some(FirmwareMethod::Uki));
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn firmware_boot_conf_efistub_is_authoritative() {
        let inputs = DetectionInputs {
            firmware_boot_conf: Some("[boot]\nmethod = efistub\nesp_path = /boot/efi\n".into()),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Detected {
                provider, method, ..
            } => {
                assert_eq!(provider, ProviderId::Efistub);
                assert_eq!(method, Some(FirmwareMethod::Efistub));
            }
            other => panic!("expected Detected, got {other:?}"),
        }
    }

    #[test]
    fn stale_esp_artefact_alone_is_not_authoritative() {
        // The user's explicit instruction: don't identify a provider
        // from a leftover ESP file alone.
        let inputs = DetectionInputs {
            has_boot_grub: true,
            has_esp_limine_conf: true,
            has_systemd_boot_loader: true,
            has_catos_uki_deployed: true,
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        assert!(matches!(verdict, DetectionVerdict::Ambiguous { .. }));
    }

    #[test]
    fn conflicting_authoritative_sources_surface_conflict() {
        let inputs = DetectionInputs {
            grub_defaults_catos: Some(
                "GRUB_DISTRIBUTOR=CatOS\nGRUB_CMDLINE_LINUX_DEFAULT='quiet rw'\n".into(),
            ),
            limine_defaults: Some(
                "KERNEL_CMDLINE[default]=quiet rw\nESP_PATH=\"/boot/efi\"\n".into(),
            ),
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        match verdict {
            DetectionVerdict::Conflict { providers, .. } => {
                assert!(providers.contains(&ProviderId::Grub));
                assert!(providers.contains(&ProviderId::Limine));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn package_presence_alone_is_not_authoritative() {
        let inputs = DetectionInputs {
            installed_packages: vec![
                "grub".into(),
                "efibootmgr".into(),
                "limine".into(),
                "limine-tool".into(),
            ],
            ..DetectionInputs::default()
        };
        let verdict = detect(&inputs, &empty_target());
        assert!(matches!(verdict, DetectionVerdict::Ambiguous { .. }));
    }

    #[test]
    fn parse_firmware_boot_method_handles_whitespace() {
        assert_eq!(
            parse_firmware_boot_method("[boot]\n  method  =  uki\n"),
            Some(FirmwareMethod::Uki)
        );
        assert_eq!(
            parse_firmware_boot_method("method=efistub\n"),
            Some(FirmwareMethod::Efistub)
        );
        assert_eq!(parse_firmware_boot_method("[boot]\nno method here\n"), None);
    }
}
