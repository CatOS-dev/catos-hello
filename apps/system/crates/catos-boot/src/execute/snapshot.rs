//! Bootable-snapshot (Snapper) repair integration: detect existing
//! Snapper setup from target evidence, restore missing config files,
//! and run the per-provider snapshot enablement commands.

use std::path::Path;

use crate::execute::config::ConfigTransaction;
use crate::execute::target::{TargetRequest, TargetRunner};
use crate::model::{BootAction, ProviderId};
use crate::plan::registry as boot_registry;

use crate::io::read_target_file_checked;

#[derive(Debug, Clone, Default)]
pub(super) struct SnapshotRepairState {
    pub enabled: bool,
    pub restore_root_config: Option<String>,
    pub target_has_snapshots: bool,
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
) -> Result<SnapshotRepairState, String> {
    if root_fstype != "btrfs" || boot_registry::snapshot_profile(provider).is_none() {
        return Ok(SnapshotRepairState::default());
    }

    let root_config = read_nonempty_target_text(target_root, "/etc/snapper/configs/root")?;
    let target_has_snapshots = target_snapshot_catalog_has_entries(target_root)?;
    if root_config.is_some() {
        return Ok(SnapshotRepairState {
            enabled: true,
            restore_root_config: None,
            target_has_snapshots,
        });
    }

    let template = read_nonempty_target_text(
        target_root,
        "/etc/snapper/config-templates/catos-root",
    )?;
    let snapshots_directory_present = target_directory_present(target_root, "/.snapshots")?;
    if snapshots_directory_present && template.is_some() {
        return Ok(SnapshotRepairState {
            enabled: true,
            restore_root_config: template,
            target_has_snapshots,
        });
    }

    Ok(SnapshotRepairState {
        target_has_snapshots,
        ..SnapshotRepairState::default()
    })
}

fn read_nonempty_target_text(
    target_root: &Path,
    rooted: &str,
) -> Result<Option<String>, String> {
    match catos_target::execute::confined::read_rooted_file(target_root, rooted) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|error| format!("target {rooted} is not UTF-8: {error}"))
            .map(|text| (!text.trim().is_empty()).then_some(text)),
        Err(catos_target::FsError::NotFound) => Ok(None),
        Err(error) => Err(format!("cannot read target {rooted}: {error}")),
    }
}

fn target_directory_present(target_root: &Path, rooted: &str) -> Result<bool, String> {
    match catos_target::execute::confined::list_rooted_directory_names(target_root, rooted) {
        Ok(_) => Ok(true),
        Err(catos_target::FsError::NotFound) => Ok(false),
        Err(error) => Err(format!("cannot inspect target directory {rooted}: {error}")),
    }
}

pub(super) fn write_restored_snapper_config(
    transaction: &mut ConfigTransaction,
    target_root: &Path,
    template: &str,
) -> Result<Vec<BootAction>, String> {
    let current = read_target_file_checked(target_root, "etc/conf.d/snapper")?;
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
    target_has_snapshots: bool,
    runner: &dyn TargetRunner,
) -> SnapshotExecution {
    let mut execution = SnapshotExecution::default();
    let optional_unit = match provider {
        ProviderId::Grub => Some("grub-btrfsd.service"),
        ProviderId::Limine => Some("limine-btrfs.service"),
        ProviderId::SystemdBoot => Some("sdboot-btrfs.service"),
        ProviderId::Uki | ProviderId::Efistub => None,
    };
    let optional_unit_present = match optional_unit {
        Some(unit) => match snapshot_unit_present(target_root, unit) {
            Ok(present) => present,
            Err(error) => {
                execution.failure = Some(error);
                return execution;
            }
        },
        None => false,
    };
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
            if optional_unit_present {
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
            if optional_unit_present {
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
            if optional_unit_present {
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

fn target_snapshot_catalog_has_entries(target_root: &Path) -> Result<bool, String> {
    let entries = match catos_target::execute::confined::list_rooted_directory_names(
        target_root,
        "/.snapshots",
    ) {
        Ok(entries) => entries,
        Err(catos_target::FsError::NotFound) => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot enumerate target snapshot catalog /.snapshots: {error}"
            ))
        }
    };
    for entry in entries {
        let Some(entry) = entry.to_str() else {
            continue;
        };
        if !entry.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }
        let info_present = match catos_target::execute::confined::rooted_regular_file_size(
            target_root,
            &format!("/.snapshots/{entry}/info.xml"),
        ) {
            Ok(Some(size)) => size > 0,
            Ok(None) | Err(catos_target::FsError::NotFound) => false,
            Err(error) => {
                return Err(format!(
                    "cannot inspect target snapshot {entry} info.xml: {error}"
                ))
            }
        };
        let snapshot_directory_present = match
            catos_target::execute::confined::list_rooted_directory_names(
                target_root,
                &format!("/.snapshots/{entry}/snapshot"),
            )
        {
            Ok(_) => true,
            Err(catos_target::FsError::NotFound) => false,
            Err(error) => {
                return Err(format!(
                    "cannot inspect target snapshot {entry} directory: {error}"
                ))
            }
        };
        if info_present && snapshot_directory_present {
            return Ok(true);
        }
    }
    Ok(false)
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

fn snapshot_unit_present(target_root: &Path, unit: &str) -> Result<bool, String> {
    for rooted in [
        format!("/usr/lib/systemd/system/{unit}"),
        format!("/etc/systemd/system/{unit}"),
    ] {
        match catos_target::execute::confined::rooted_regular_file_size(target_root, &rooted) {
            Ok(Some(_)) => return Ok(true),
            Ok(None) | Err(catos_target::FsError::NotFound) => {}
            Err(error) => {
                return Err(format!("cannot inspect target snapshot unit {rooted}: {error}"))
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{
        run_snapshot_repair, snapshot_repair_state, target_snapshot_catalog_has_entries,
        write_restored_snapper_config,
    };
    use crate::execute::config::ConfigTransaction;
    use crate::execute::target::RecordedTargetRunner;
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
    fn unreadable_root_config_is_not_silently_treated_as_disabled() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = TempRoot::new("unreadable-root");
        let config = root.0.join("etc/snapper/configs/root");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, b"SUBVOLUME=\"/\"\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = snapshot_repair_state(&root.0, ProviderId::Grub, "btrfs", &[]);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn non_utf8_snapper_registration_is_not_overwritten() {
        let root = TempRoot::new("non-utf8-registration");
        let registration = root.0.join("etc/conf.d/snapper");
        std::fs::create_dir_all(registration.parent().unwrap()).unwrap();
        std::fs::write(&registration, [0xff, 0xfe]).unwrap();
        let mut transaction = ConfigTransaction::new(&root.0);

        let result = write_restored_snapper_config(
            &mut transaction,
            &root.0,
            "SUBVOLUME=\"/\"\n",
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(registration).unwrap(), [0xff, 0xfe]);
    }

    #[test]
    fn unreadable_snapshot_catalog_is_not_reported_empty() {
        use std::os::unix::fs::symlink;

        let root = TempRoot::new("catalog-symlink");
        let outside = TempRoot::new("catalog-outside");
        symlink(&outside.0, root.0.join(".snapshots")).unwrap();

        assert!(target_snapshot_catalog_has_entries(&root.0).is_err());
    }

    #[test]
    fn snapshot_unit_inspection_failure_runs_no_target_commands() {
        use std::os::unix::fs::symlink;

        let root = TempRoot::new("unit-symlink");
        let outside = TempRoot::new("unit-outside");
        let unit = root.0.join("usr/lib/systemd/system/grub-btrfsd.service");
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        symlink(outside.0.join("unit"), &unit).unwrap();
        let runner = RecordedTargetRunner::new();

        let result = run_snapshot_repair(ProviderId::Grub, &root.0, false, &runner);

        assert!(result.failure.as_deref().is_some_and(|failure| {
            failure.contains("cannot inspect target snapshot unit")
        }));
        assert!(result.actions.is_empty());
        runner.assert_consumed();
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

        let state = snapshot_repair_state(&root.0, ProviderId::Grub, "btrfs", &[]).unwrap();
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

        let state = snapshot_repair_state(&root.0, ProviderId::Grub, "btrfs", &[]).unwrap();
        assert!(!state.enabled);
        assert!(state.restore_root_config.is_none());
    }

    #[test]
    fn snapshot_catalog_requires_real_info_and_snapshot_directory() {
        let root = TempRoot::new("catalog");
        let entry = root.0.join(".snapshots/1");
        std::fs::create_dir_all(entry.join("snapshot")).unwrap();
        assert!(!target_snapshot_catalog_has_entries(&root.0).unwrap());

        std::fs::write(entry.join("info.xml"), b"").unwrap();
        assert!(!target_snapshot_catalog_has_entries(&root.0).unwrap());

        std::fs::write(entry.join("info.xml"), b"<snapshot/>\n").unwrap();
        assert!(target_snapshot_catalog_has_entries(&root.0).unwrap());
    }
}
