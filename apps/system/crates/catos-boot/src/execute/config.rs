//! Atomic target-config transaction: writes config files with
//! backup-on-overwrite and rollback. Used by the boot-repair
//! orchestrator to batch provider config mutations so a failure
//! rolls every file back to its pre-repair state.

use std::path::Path;

use crate::model::{BootAction, FirmwareMethod, ProviderId};

pub(super) struct ConfigTransaction {
    root: std::path::PathBuf,
    changes: Vec<ConfigChange>,
}

struct ConfigChange {
    target_path: String,
    original: Option<Vec<u8>>,
}

impl ConfigTransaction {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            changes: Vec::new(),
        }
    }

    pub(super) fn write(
        &mut self,
        target_path: &str,
        contents: &str,
    ) -> Result<BootAction, String> {
        let parent = Path::new(target_path)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| format!("invalid target configuration path {target_path:?}"))?;
        catos_target::execute::confined::create_rooted_directory(&self.root, parent)
            .map_err(|error| format!("cannot create target config parent {parent}: {error}"))?;
        let existing =
            catos_target::execute::confined::read_rooted_file(&self.root, target_path).ok();
        if existing.as_deref() == Some(contents.as_bytes()) {
            return Ok(BootAction::ConfigUnchanged {
                target_path: target_path.to_string(),
            });
        }
        let backup_path = existing.as_ref().map(|bytes| {
            let backup_path = format!("{target_path}.catos-repair.backup");
            catos_target::execute::confined::atomic_write_rooted(
                &self.root,
                &backup_path,
                bytes,
                0o600,
            )
            .map_err(|error| format!("cannot write backup {backup_path}: {error}"))?;
            Ok::<String, String>(backup_path)
        });
        let backup_path = backup_path.transpose()?;
        catos_target::execute::confined::atomic_write_rooted(
            &self.root,
            target_path,
            contents.as_bytes(),
            0o644,
        )
        .map_err(|error| format!("cannot write target config {target_path}: {error}"))?;
        self.changes.push(ConfigChange {
            target_path: target_path.to_string(),
            original: existing,
        });
        Ok(BootAction::ConfigWritten {
            target_path: target_path.to_string(),
            backup_path,
            bytes: contents.len(),
        })
    }

    pub(super) fn rollback(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for change in self.changes.drain(..).rev() {
            let result = match change.original {
                Some(original) => catos_target::execute::confined::atomic_write_rooted(
                    &self.root,
                    &change.target_path,
                    &original,
                    0o644,
                ),
                None => catos_target::execute::confined::remove_rooted_file(
                    &self.root,
                    &change.target_path,
                ),
            };
            if let Err(error) = result {
                errors.push(format!("{}: {error}", change.target_path));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

pub(super) fn write_provider_configs(
    transaction: &mut ConfigTransaction,
    provider: ProviderId,
    ctx: &crate::execute::providers::base::ProviderCtx<'_>,
    efi_device: Option<&(String, u32)>,
    mkinitcpio_text: &str,
    mkinitcpio_inputs: &crate::plan::initramfs::MkinitcpioInputs<'_>,
) -> Result<Vec<BootAction>, String> {
    use crate::execute::providers;
    use crate::plan::initramfs as mkinitcpio;

    // bootloadu configures mkinitcpio before every provider. Limine and
    // systemd-boot snapshot overlays therefore need the same target config,
    // not only GRUB.
    let arrays = mkinitcpio::compute_arrays(mkinitcpio_inputs);
    let mut actions = vec![transaction.write(
        "/etc/mkinitcpio.conf",
        &mkinitcpio::serialise(mkinitcpio_text, &arrays),
    )?];

    match provider {
        ProviderId::Grub => {
            actions.push(transaction.write(
                "/etc/default/grub.d/00-catos.cfg",
                &providers::grub::build_grub_defaults(ctx),
            )?);
        }
        ProviderId::Limine => {
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/default/limine",
                &providers::limine::build_limine_defaults(ctx),
            )?);
        }
        ProviderId::SystemdBoot => {
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/kernel/install.conf.d/20-catos-bootloadu.conf",
                &providers::systemd_boot::build_install_conf(ctx),
            )?);
        }
        ProviderId::Uki | ProviderId::Efistub => {
            let method = match provider {
                ProviderId::Uki => FirmwareMethod::Uki,
                ProviderId::Efistub => FirmwareMethod::Efistub,
                _ => unreachable!(),
            };
            let efi_device = efi_device.ok_or_else(|| {
                "firmware boot repair requires verified ESP disk and partition facts before writing its configuration"
                    .to_string()
            })?;
            actions.push(transaction.write("/etc/kernel/cmdline", &format!("{}\n", ctx.cmdline))?);
            actions.push(transaction.write(
                "/etc/catos/firmware-boot.conf",
                &providers::firmware::build_firmware_boot_conf(method, ctx, Some(efi_device)),
            )?);
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "catos-boot-repair-config-tx-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn read(root: &Path, relative: &str) -> Option<String> {
        std::fs::read_to_string(root.join(relative.trim_start_matches('/'))).ok()
    }

    #[test]
    fn target_config_write_is_atomic_and_records_a_backup() {
        let root = temp_root();
        fs::create_dir_all(root.join("etc/default/grub.d")).unwrap();
        fs::write(root.join("etc/default/grub.d/00-catos.cfg"), "old\n").unwrap();

        let action = ConfigTransaction::new(&root)
            .write("/etc/default/grub.d/00-catos.cfg", "new\n")
            .unwrap();

        assert_eq!(
            read(&root, "etc/default/grub.d/00-catos.cfg").as_deref(),
            Some("new\n")
        );
        assert_eq!(
            read(&root, "etc/default/grub.d/00-catos.cfg.catos-repair.backup").as_deref(),
            Some("old\n")
        );
        assert!(matches!(action, BootAction::ConfigWritten { .. }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_transaction_rolls_back_existing_and_new_files() {
        let root = temp_root();
        fs::create_dir_all(root.join("etc/catos")).unwrap();
        fs::write(root.join("etc/catos/existing.conf"), "before\n").unwrap();
        let mut transaction = ConfigTransaction::new(&root);

        transaction
            .write("/etc/catos/existing.conf", "after\n")
            .unwrap();
        transaction.write("/etc/catos/new.conf", "new\n").unwrap();
        transaction.rollback().unwrap();

        assert_eq!(
            read(&root, "etc/catos/existing.conf").as_deref(),
            Some("before\n")
        );
        assert!(read(&root, "etc/catos/new.conf").is_none());
        let _ = fs::remove_dir_all(root);
    }
}
