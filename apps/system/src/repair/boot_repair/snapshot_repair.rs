//! Bootable-snapshot (Snapper) repair integration: detect existing
//! Snapper setup from target evidence, restore missing config files,
//! and run the per-provider snapshot enablement commands.

use std::path::Path;

use crate::repair::boot_repair::config_tx::ConfigTransaction;
use crate::repair::boot_repair::registry as boot_registry;
use crate::repair::boot_repair::target_exec::{TargetRequest, TargetRunner};
use crate::shared::model::boot_repair::{BootAction, ProviderId};

use super::read_target_file;

#[derive(Debug, Clone, Default)]
pub(super) struct SnapshotRepairState {
    pub enabled: bool,
    pub restore_root_config: Option<String>,
}

#[derive(Default)]
pub(super) struct SnapshotExecution {
    pub actions: Vec<BootAction>,
    pub failure: Option<String>,
}

/// Snapshot repair is deliberately opt-in from evidence already stored in the
/// target. A Btrfs root alone is not evidence that its owner intended bootable
/// snapshots, so it must never cause us to create a new Snapper setup.
pub(super) fn snapshot_repair_state(
    target_root: &Path,
    provider: ProviderId,
    root_fstype: &str,
    _installed_packages: &[String],
) -> SnapshotRepairState {
    if root_fstype != "btrfs" || boot_registry::snapshot_profile(provider).is_none() {
        return SnapshotRepairState::default();
    }

    if crate::target::execute::confined::read_rooted_file(
        target_root,
        "/etc/snapper/configs/root",
    )
    .is_ok()
    {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: None,
        };
    }

    let template = crate::target::execute::confined::read_rooted_file(
        target_root,
        "/etc/snapper/config-templates/catos-root",
    )
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok());
    if super::has_target_path(target_root, ".snapshots") && template.is_some() {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: template,
        };
    }

    SnapshotRepairState::default()
}

pub(super) fn write_restored_snapper_config(
    transaction: &mut ConfigTransaction,
    target_root: &Path,
    template: &str,
) -> Result<Vec<BootAction>, String> {
    let current = read_target_file(target_root, "etc/conf.d/snapper");
    let registration = register_snapper_root(current.as_deref())?;
    Ok(vec![
        transaction.write("/etc/snapper/configs/root", template)?,
        transaction.write("/etc/conf.d/snapper", &registration)?,
    ])
}

fn register_snapper_root(existing: Option<&str>) -> Result<String, String> {
    let mut lines = existing
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut found = false;
    for line in &mut lines {
        let trimmed = line.trim_start();
        let Some(value) = trimmed.strip_prefix("SNAPPER_CONFIGS=") else {
            continue;
        };
        let value = value.trim();
        let Some(values) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            return Err("cannot safely update non-quoted SNAPPER_CONFIGS".into());
        };
        let mut configs = values.split_whitespace().collect::<Vec<_>>();
        if configs.iter().any(|name| {
            name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-'))
        }) {
            return Err("cannot safely update invalid SNAPPER_CONFIGS value".into());
        }
        if !configs.contains(&"root") {
            configs.push("root");
        }
        *line = format!("SNAPPER_CONFIGS=\"{}\"", configs.join(" "));
        found = true;
        break;
    }
    if !found {
        lines.push("SNAPPER_CONFIGS=\"root\"".into());
    }
    Ok(format!("{}\n", lines.join("\n")))
}

pub(super) fn requires_pre_provider_snapshot_initramfs_rebuild(
    provider: ProviderId,
    snapshots_enabled: bool,
) -> bool {
    snapshots_enabled
        && matches!(
            provider,
            ProviderId::Limine | ProviderId::SystemdBoot
        )
}

pub(super) fn run_snapshot_repair(
    provider: ProviderId,
    target_root: &Path,
    runner: &dyn TargetRunner,
) -> SnapshotExecution {
    let mut execution = SnapshotExecution::default();
    let target_has_snapshots = target_snapshot_catalog_has_entries(target_root);
    let mut run = |binary: &str, argv: Vec<String>, description: &str, require_deployment: bool| {
        if execution.failure.is_some() {
            return;
        }
        let result = runner.invoke(&TargetRequest::new(binary, argv, description));
        let success = !result.binary_missing && !result.timed_out && result.exit_code == 0;
        let zero_deployment = require_deployment
            && target_has_snapshots
            && snapshot_generate_reports_zero_deployment(&result);
        execution
            .actions
            .push(BootAction::SnapshotStep {
                description: description.into(),
                result: Some(result),
            });
        if !success {
            execution.failure = Some(format!("{description} failed"));
        } else if zero_deployment {
            execution.failure = Some(format!(
                "{description} reported success but deployed zero snapshots"
            ));
        }
    };

    run(
        "snapper",
        vec!["--no-dbus".into(), "-c".into(), "root".into(), "get-config".into()],
        "validate Snapper root configuration",
        false,
    );
    run(
        "systemctl",
        vec!["enable".into(), "snapper-cleanup.timer".into()],
        "enable Snapper cleanup timer",
        false,
    );

    match provider {
        ProviderId::Grub => {
            if snapshot_unit_present(target_root, "grub-btrfsd.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "grub-btrfsd.service".into()],
                    "enable grub-btrfsd service",
                    false,
                );
            }
            run(
                "grub-mkconfig",
                vec!["-o".into(), "/boot/grub/grub.cfg".into()],
                "regenerate GRUB snapshot entries",
                false,
            );
        }
        ProviderId::Limine => {
            run("limine-btrfs", vec!["generate".into()], "generate Limine snapshot entries", true);
            run("limine-btrfs", vec!["verify".into()], "verify Limine snapshot entries", false);
            if snapshot_unit_present(target_root, "limine-btrfs.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "limine-btrfs.service".into()],
                    "enable limine-btrfs service",
                    false,
                );
            }
        }
        ProviderId::SystemdBoot => {
            run("sdboot-btrfs", vec!["generate".into()], "generate systemd-boot snapshot entries", true);
            run("sdboot-btrfs", vec!["verify".into()], "verify systemd-boot snapshot entries", false);
            if snapshot_unit_present(target_root, "sdboot-btrfs.service") {
                run(
                    "systemctl",
                    vec!["enable".into(), "sdboot-btrfs.service".into()],
                    "enable sdboot-btrfs service",
                    false,
                );
            }
        }
        ProviderId::Uki | ProviderId::Efistub => {
            execution.failure = Some("snapshot repair requested for unsupported provider".into());
        }
    }
    execution
}

fn target_snapshot_catalog_has_entries(target_root: &Path) -> bool {
    crate::target::execute::confined::list_rooted_directory_names(target_root, "/.snapshots")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter(|entry| entry.chars().all(|character| character.is_ascii_digit()))
        .any(|entry| {
            crate::target::execute::confined::rooted_regular_file_size(
                target_root,
                &format!("/.snapshots/{entry}/info.xml"),
            )
            .is_ok()
                && crate::target::execute::confined::list_rooted_directory_names(
                    target_root,
                    &format!("/.snapshots/{entry}/snapshot"),
                )
                .is_ok()
        })
}

fn snapshot_generate_reports_zero_deployment(
    result: &crate::shared::model::boot_repair::TargetCommandResult,
) -> bool {
    let output = result
        .stdout
        .iter()
        .chain(result.stderr.iter())
        .copied()
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&output)
        .to_ascii_lowercase()
        .contains("deployed 0 snapshots")
}

fn snapshot_unit_present(target_root: &Path, unit: &str) -> bool {
    crate::target::execute::confined::read_rooted_file(
        target_root,
        &format!("/usr/lib/systemd/system/{unit}"),
    )
    .is_ok()
        || crate::target::execute::confined::read_rooted_file(
            target_root,
            &format!("/etc/systemd/system/{unit}"),
        )
        .is_ok()
}
