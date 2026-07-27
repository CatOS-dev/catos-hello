//! [`BootRepairTargetSession`]: discover and mount the exact target
//! required by boot repair without ever entering mount repair's
//! write/apply flow. The returned session owns the shared device lock
//! and every mount it creates.

use std::path::{Path, PathBuf};

use crate::shared::model::mount_repair::{BootMountLayout, TargetIdentity};
use crate::shared::model::recovery::CleanupSummary;
use crate::shared::model::runtime::DetectionStatus;
use crate::shared::model::storage::BlockDevice;
use crate::shared::mount::probe::{inspect_selected_root, probe_unmounted_candidates};
use crate::shared::mount::syscall::{self, ms_flags};
use crate::shared::probe::discover_devices;
use crate::shared::probe::fs_probe::RealFilesystem;
use crate::shared::snapshot_engine::lock::DeviceLock;

use super::select::{
    inspect_running_root, is_running_root_device, same_block_device, select_cli_root,
    select_mount_repair_esp,
};
use super::session::MountRepairRwSession;
use super::detect_boot_mount_layout;

pub(crate) struct BootRepairTargetSession {
    target: TargetIdentity,
    devices: Vec<BlockDevice>,
    root_session: MountRepairRwSession,
    auxiliary_mounts: Vec<PathBuf>,
    _lock: DeviceLock,
}

impl BootRepairTargetSession {
    pub(crate) fn target(&self) -> &TargetIdentity {
        &self.target
    }

    pub(crate) fn target_root(&self) -> PathBuf {
        self.root_session.target_root()
    }

    pub(crate) fn devices(&self) -> &[BlockDevice] {
        &self.devices
    }

    pub(crate) fn cleanup(&mut self) -> CleanupSummary {
        let mut cleanup = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        };
        for mount_point in self.auxiliary_mounts.drain(..).rev() {
            match syscall::umount2(&mount_point, 0) {
                Ok(()) => cleanup.unmounted.push(mount_point.display().to_string()),
                Err(error) => {
                    let detach = syscall::umount2(
                        &mount_point,
                        crate::shared::mount::syscall::mnt_flags::MNT_DETACH,
                    );
                    cleanup.all_clean = false;
                    cleanup.residual.push(match detach {
                        Ok(()) => format!(
                            "{}: umount2 failed ({error}); detached lazily",
                            mount_point.display()
                        ),
                        Err(detach_error) => format!(
                            "{}: umount2 failed ({error}); lazy detach failed ({detach_error})",
                            mount_point.display()
                        ),
                    });
                }
            }
        }
        let root_cleanup = self.root_session.cleanup();
        cleanup.unmounted.extend(root_cleanup.unmounted);
        cleanup.residual.extend(root_cleanup.residual);
        cleanup.all_clean &= root_cleanup.all_clean;
        cleanup
    }
}

/// Discover and mount the exact target required by boot repair without ever
/// entering mount repair's write/apply flow.  The returned session owns the
/// shared device lock and every mount it creates.
pub(crate) fn open_boot_repair_target_session(
    root_device: Option<&str>,
    root_subvolume: Option<&str>,
    esp_device: Option<&str>,
) -> Result<BootRepairTargetSession, String> {
    let fs = RealFilesystem;
    let (devices, _) = discover_devices(&fs);
    let root = select_cli_root(&devices, root_device)
        .ok_or_else(|| "root device must identify exactly one verified CatOS root".to_string())?;
    let requested_subvol = match (root.filesystem.as_deref(), root_subvolume) {
        (Some("btrfs"), Some(value)) => value,
        (Some("btrfs"), None) => "/@",
        (_, Some(_)) => return Err("--root-subvolume is valid only for Btrfs roots".into()),
        (_, None) => "",
    };
    if root.filesystem.as_deref() == Some("btrfs") && requested_subvol != "/@" {
        return Err("boot repair supports the CatOS standard Btrfs root subvolume /@".into());
    }
    let root_device_path = root
        .dev_path
        .as_deref()
        .ok_or_else(|| "selected root has no stable device path".to_string())?;
    let running_root = is_running_root_device(root);
    let selected_probe = if running_root {
        inspect_running_root()
    } else {
        inspect_selected_root(
            root,
            (root.filesystem.as_deref() == Some("btrfs")).then_some(requested_subvol),
        )
        .map_err(|error| error.message)
    }
    .map_err(|error| format!("cannot inspect selected target read-only: {error}"))?;
    if selected_probe.inspection.is_catos_target.status != DetectionStatus::Detected {
        return Err("selected target is not identified as CatOS".into());
    }
    let topology_probe = probe_unmounted_candidates(&devices, &selected_probe.fstab);
    let esp = select_mount_repair_esp(
        &devices,
        &selected_probe.fstab,
        &topology_probe.esps,
        esp_device,
    )?;
    let boot_layout = detect_boot_mount_layout(
        &selected_probe.fstab,
        &devices,
        root_device_path,
        esp.and_then(|device| device.dev_path.as_deref()),
    )?;
    let target = TargetIdentity {
        root_device: root_device_path.to_path_buf(),
        root_fstype: root.filesystem.clone().unwrap_or_default(),
        root_subvol: (root.filesystem.as_deref() == Some("btrfs"))
            .then(|| requested_subvol.to_string()),
        root_uuid: root.uuid.clone(),
        esp_device: esp.and_then(|device| device.dev_path.clone()),
        esp_uuid: esp.and_then(|device| device.uuid.clone()),
        boot_layout: Some(boot_layout),
    };
    let lock = DeviceLock::try_acquire(root_device_path).map_err(|error| error.message)?;
    let root_session = MountRepairRwSession::mount(
        root_device_path,
        root.filesystem.as_deref().unwrap_or_default(),
        running_root,
    )
    .map_err(|error| error.message.to_string())?;
    let mut session = BootRepairTargetSession {
        target,
        devices,
        root_session,
        auxiliary_mounts: Vec::new(),
        _lock: lock,
    };
    if let Err(error) = session
        .mount_runtime_filesystems()
        .and_then(|_| session.mount_boot_layout())
    {
        let cleanup = session.cleanup();
        return Err(format!(
            "cannot mount target boot layout: {error}; cleanup residuals: {:?}",
            cleanup.residual
        ));
    }
    Ok(session)
}

pub(super) fn boot_runtime_bind_flags(source: &str) -> u64 {
    // /dev/fd resolves through /proc/self/fd and mkinitcpio expects the usual
    // recursive /dev and /proc views. /sys and /run, however, contain many
    // unrelated host submounts; copying those recursively makes one cleanup
    // entry insufficient. Efivars is mounted explicitly below when present.
    match source {
        "/dev" | "/proc" => ms_flags::MS_BIND | ms_flags::MS_REC,
        _ => ms_flags::MS_BIND,
    }
}

impl BootRepairTargetSession {
    fn mount_runtime_filesystems(&mut self) -> Result<(), String> {
        for source in ["/dev", "/proc", "/sys", "/run"] {
            if !Path::new(source).is_dir() {
                return Err(format!(
                    "required host runtime mount {source} is unavailable"
                ));
            }
            self.bind_host_path(source, source)?;
        }
        let efivars = Path::new("/sys/firmware/efi/efivars");
        if efivars.is_dir() {
            self.bind_host_path("/sys/firmware/efi/efivars", "/sys/firmware/efi/efivars")?;
        }
        Ok(())
    }

    fn mount_boot_layout(&mut self) -> Result<(), String> {
        let Some(layout) = self.target.boot_layout.clone() else {
            return Err("target boot layout was not detected".into());
        };
        match layout {
            BootMountLayout::BootInsideRoot => Ok(()),
            BootMountLayout::EspAtBootEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/boot/efi", None)
            }
            BootMountLayout::EspAtEfi { esp_device } => {
                self.mount_device_at(&esp_device, "/efi", None)
            }
            BootMountLayout::EspAtBoot { esp_device } => {
                self.mount_device_at(&esp_device, "/boot", None)
            }
            BootMountLayout::SeparateBootAndEsp {
                boot_device,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(&boot_device, "/boot", None)?;
                self.mount_device_at(&esp_device, &esp_mount_point, None)
            }
            BootMountLayout::BootBtrfsSubvolume {
                subvolume,
                esp_device,
                esp_mount_point,
            } => {
                self.mount_device_at(
                    &self.target.root_device.clone(),
                    "/boot",
                    Some(format!("subvol={subvolume}")),
                )?;
                match (esp_device, esp_mount_point) {
                    (Some(device), Some(mount_point)) => {
                        self.mount_device_at(&device, &mount_point, None)
                    }
                    (None, None) => Ok(()),
                    _ => Err("Btrfs /boot layout has incomplete ESP metadata".into()),
                }
            }
        }
    }

    fn mount_device_at(
        &mut self,
        device: &Path,
        target_relative: &str,
        options: Option<String>,
    ) -> Result<(), String> {
        let filesystem = self
            .devices
            .iter()
            .find(|candidate| {
                candidate
                    .dev_path
                    .as_deref()
                    .is_some_and(|path| same_block_device(path, device))
            })
            .and_then(|candidate| candidate.filesystem.as_deref())
            .ok_or_else(|| format!("{} has no detected filesystem", device.display()))?;
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        let source = device
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", device.display()))?;
        syscall::mount(
            Some(source),
            &mount_point,
            Some(filesystem),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            options.as_deref(),
        )
        .map_err(|error| {
            format!(
                "mount {} at {}: {error}",
                device.display(),
                mount_point.display()
            )
        })?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }

    fn bind_host_path(&mut self, source: &str, target_relative: &str) -> Result<(), String> {
        let mount_point = self
            .target_root()
            .join(target_relative.trim_start_matches('/'));
        match std::fs::symlink_metadata(&mount_point) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", mount_point.display()));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{} is not a directory", mount_point.display()));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", mount_point.display())),
        }
        syscall::mount(
            Some(source),
            &mount_point,
            None,
            boot_runtime_bind_flags(source),
            None,
        )
        .map_err(|error| format!("bind mount {source} at {}: {error}", mount_point.display()))?;
        self.auxiliary_mounts.push(mount_point);
        Ok(())
    }
}

