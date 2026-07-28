//! Bootable-snapshot (Snapper) repair integration: detect existing
//! Snapper setup from target evidence, restore missing config files,
//! and run the per-provider snapshot enablement commands.

use std::path::Path;

use crate::execute::config::ConfigTransaction;
use crate::execute::target::{TargetRequest, TargetRunner};
use crate::model::{BootAction, ProviderId};
use crate::plan::registry as boot_registry;

use crate::io::read_target_file;

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

    let root_config = read_nonempty_target_text(target_root, "/etc/snapper/configs/root");
    if root_config.is_some() {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: None,
        };
    }

    let template = read_nonempty_target_text(
        target_root,
        "/etc/snapper/config-templates/catos-root",
    );
    let snapshots_directory_present =
        catos_target::execute::confined::list_rooted_directory_names(target_root, "/.snapshots")
            .is_ok();
    if snapshots_directory_present && template.is_some() {
        return SnapshotRepairState {
            enabled: true,
            restore_root_config: template,
        };
    }

    SnapshotRepairState::default()
}

fn read_nonempty_target_text(target_root: &Path, rooted: &str) -> Option<String> {
    catos_target::execute::confined::read_rooted_file(target_root, rooted)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|text| !text.trim().is_empty())
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
                || !name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
                })
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
    snapshots_enabled && matches!(provider, ProviderId::Limine | ProviderId::SystemdBoot)
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
        execution.actions.push(BootAction::SnapshotStep {
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
        vec![
            "--no-dbus".into(),
            "-c".into(),
            "root".into(),
            "get-config".into(),
        ],
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
            run(
                "limine-btrfs",
                vec!["generate".into()],
                "generate Limine snapshot entries",
                true,
            );
            run(
                "limine-btrfs",
                vec!["verify".into()],
                "verify Limine snapshot entries",
                false,
            );
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
            run(
                "sdboot-btrfs",
                vec!["generate".into()],
                "generate systemd-boot snapshot entries",
                true,
            );
            run(
                "sdboot-btrfs",
                vec!["verify".into()],
                "verify systemd-boot snapshot entries",
                false,
            );
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
    catos_target::execute::confined::list_rooted_directory_names(target_root, "/.snapshots")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter(|entry| entry.chars().all(|character| character.is_ascii_digit()))
        .any(|entry| {
            let info_present = matches!(
                catos_target::execute::confined::rooted_regular_file_size(
                    target_root,
                    &format!("/.snapshots/{entry}/info.xml"),
                ),
                Ok(Some(size)) if size > 0
            );
            let snapshot_directory_present =
                catos_target::execute::confined::list_rooted_directory_names(
                    target_root,
                    &format!("/.snapshots/{entry}/snapshot"),
                )
                .is_ok();
            info_present && snapshot_directory_present
        })
}

fn snapshot_generate_reports_zero_deployment(result: &crate::model::TargetCommandResult) -> bool {
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
    catos_target::execute::confined::read_rooted_file(
        target_root,
        &format!("/usr/lib/systemd/system/{unit}"),
    )
    .is_ok()
        || catos_target::execute::confined::read_rooted_file(
            target_root,
            &format!("/etc/systemd/system/{unit}"),
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{snapshot_repair_state, target_snapshot_catalog_has_entries};
    use crate::model::ProviderId;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(name: &str) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "catos-boot-snapshot-{name}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn empty_root_config_is_restored_from_a_valid_target_template() {
        let root = TempRoot::new("restore-empty-root");
        std::fs::create_dir_all(root.0.join("etc/snapper/configs")).unwrap();
        std::fs::create_dir_all(root.0.join("etc/snapper/config-templates")).unwrap();
        std::fs::create_dir_all(root.0.join(".snapshots")).unwrap();
        std::fs::write(root.0.join("etc/snapper/configs/root"), b"").unwrap();
        std::fs::write(
            root.0.join("etc/snapper/config-templates/catos-root"),
            b"SUBVOLUME=\"/\"\n",
        )
        .unwrap();

        let state = snapshot_repair_state(&root.0, ProviderId::Grub, "btrfs", &[]);
        assert!(state.enabled);
        assert_eq!(
            state.restore_root_config.as_deref(),
            Some("SUBVOLUME=\"/\"\n")
        );
    }

    #[test]
    fn empty_root_config_without_a_valid_template_is_not_enabled() {
        let root = TempRoot::new("reject-empty-root");
        std::fs::create_dir_all(root.0.join("etc/snapper/configs")).unwrap();
        std::fs::create_dir_all(root.0.join(".snapshots")).unwrap();
        std::fs::write(root.0.join("etc/snapper/configs/root"), b"\n").unwrap();

        let state = snapshot_repair_state(&root.0, ProviderId::Grub, "btrfs", &[]);
        assert!(!state.enabled);
        assert!(state.restore_root_config.is_none());
    }

    #[test]
    fn snapshot_catalog_requires_real_info_and_snapshot_directory() {
        let root = TempRoot::new("catalog");
        let entry = root.0.join(".snapshots/1");
        std::fs::create_dir_all(entry.join("snapshot")).unwrap();
        assert!(!target_snapshot_catalog_has_entries(&root.0));

        std::fs::write(entry.join("info.xml"), b"").unwrap();
        assert!(!target_snapshot_catalog_has_entries(&root.0));

        std::fs::write(entry.join("info.xml"), b"<snapshot/>\n").unwrap();
        assert!(target_snapshot_catalog_has_entries(&root.0));
    }
}
