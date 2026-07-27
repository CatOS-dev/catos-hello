//! Pure Chroot mount planning.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::model::{BlockDevice, ChrootMount, ChrootMountKind, ChrootPlan, FsTabEntry, Subvolume};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraMountSelection {
    pub device: BlockDevice,
    pub mount_point: String,
}

pub struct ChrootPlanInputs<'a> {
    pub root_device: &'a BlockDevice,
    pub root_subvolume: Option<&'a Subvolume>,
    pub fstab: &'a [FsTabEntry],
    pub devices: &'a [BlockDevice],
    pub extra_mounts: &'a [ExtraMountSelection],
    pub use_systemd_chroot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChrootPlanError {
    message: String,
}

impl ChrootPlanError {
    fn unsafe_mount_point(value: &str) -> Self {
        Self {
            message: format!("unsafe mount point {value:?}"),
        }
    }

    fn undiscovered_device(device: &BlockDevice) -> Self {
        Self {
            message: format!(
                "device {} was not present in the diagnosed device set",
                device.name
            ),
        }
    }

    fn invalid_root_subvolume(device: &BlockDevice) -> Self {
        Self {
            message: format!(
                "root subvolume was selected for non-Btrfs device {}",
                device.name
            ),
        }
    }
}

impl std::fmt::Display for ChrootPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChrootPlanError {}

pub fn build_plan(inputs: ChrootPlanInputs<'_>) -> Result<ChrootPlan, ChrootPlanError> {
    if !inputs
        .devices
        .iter()
        .any(|device| device.id() == inputs.root_device.id())
    {
        return Err(ChrootPlanError::undiscovered_device(inputs.root_device));
    }
    if inputs.root_subvolume.is_some() && !inputs.root_device.is_btrfs() {
        return Err(ChrootPlanError::invalid_root_subvolume(inputs.root_device));
    }
    let root_options = inputs
        .root_subvolume
        .map(|subvolume| vec![format!("subvolid={}", subvolume.id)])
        .unwrap_or_default();
    let root = ChrootMount {
        device: inputs.root_device.clone(),
        mount_point: "/".into(),
        options: root_options,
        kind: ChrootMountKind::Root,
    };

    let mut mounts = Vec::new();
    let mut warnings = Vec::new();
    let mut mounted_devices = HashSet::from([inputs.root_device.id()]);
    let mut mounted_points = HashSet::from(["/".to_string()]);

    for entry in inputs.fstab {
        if entry.vfs_type == "swap"
            || entry.mountpoint == "/"
            || entry.mount_options.iter().any(|option| option == "noauto")
        {
            continue;
        }
        validate_mount_point(&entry.mountpoint)?;
        let Some(device) = inputs
            .devices
            .iter()
            .find(|device| device.matches_spec(&entry.fs_spec))
        else {
            warnings.push(format!(
                "fstab device {} for {} was not discovered",
                entry.fs_spec, entry.mountpoint
            ));
            continue;
        };
        if mounted_devices.contains(&device.id()) || mounted_points.contains(&entry.mountpoint) {
            continue;
        }
        mounted_devices.insert(device.id());
        mounted_points.insert(entry.mountpoint.clone());
        mounts.push(ChrootMount {
            device: device.clone(),
            mount_point: entry.mountpoint.clone(),
            options: btrfs_mount_options(entry),
            kind: ChrootMountKind::Fstab,
        });
    }

    for selection in inputs.extra_mounts {
        validate_mount_point(&selection.mount_point)?;
        if !inputs
            .devices
            .iter()
            .any(|device| device.id() == selection.device.id())
        {
            return Err(ChrootPlanError::undiscovered_device(&selection.device));
        }
        if mounted_devices.contains(&selection.device.id())
            || mounted_points.contains(&selection.mount_point)
        {
            warnings.push(format!(
                "additional mount {} at {} duplicates an existing mount",
                selection.device.name, selection.mount_point
            ));
            continue;
        }
        mounted_devices.insert(selection.device.id());
        mounted_points.insert(selection.mount_point.clone());
        mounts.push(ChrootMount {
            device: selection.device.clone(),
            mount_point: selection.mount_point.clone(),
            options: Vec::new(),
            kind: ChrootMountKind::Extra,
        });
    }

    mounts.sort_by_key(|mount| Path::new(&mount.mount_point).components().count());

    Ok(ChrootPlan {
        root,
        mounts,
        use_systemd_chroot: inputs.use_systemd_chroot,
        warnings,
    })
}

fn validate_mount_point(value: &str) -> Result<(), ChrootPlanError> {
    let path = Path::new(value);
    if !path.is_absolute() || value == "/" {
        return Err(ChrootPlanError::unsafe_mount_point(value));
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ChrootPlanError::unsafe_mount_point(value));
            }
        }
    }
    Ok(())
}

fn btrfs_mount_options(entry: &FsTabEntry) -> Vec<String> {
    if entry.vfs_type != "btrfs" {
        return Vec::new();
    }
    entry
        .mount_options
        .iter()
        .find(|option| option.starts_with("subvolid="))
        .or_else(|| {
            entry
                .mount_options
                .iter()
                .find(|option| option.starts_with("subvol="))
        })
        .cloned()
        .into_iter()
        .collect()
}
