//! Pure Chroot mount planning.

use std::collections::{HashMap, HashSet};
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
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn unsafe_mount_point(value: &str) -> Self {
        Self::new(format!("unsafe mount point {value:?}"))
    }

    fn undiscovered_device(device: &BlockDevice) -> Self {
        Self::new(format!(
            "device {} was not present in the diagnosed device set",
            device.name
        ))
    }

    fn invalid_root_subvolume(device: &BlockDevice) -> Self {
        Self::new(format!(
            "root subvolume was selected for non-Btrfs device {}",
            device.name
        ))
    }
}

impl std::fmt::Display for ChrootPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChrootPlanError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MountIdentity {
    device_identity: String,
    filesystem: String,
    selector: Option<String>,
    mount_point: String,
}

impl MountIdentity {
    fn from_mount(mount: &ChrootMount) -> Result<Self, ChrootPlanError> {
        let filesystem = mount
            .device
            .fs_type
            .as_deref()
            .ok_or_else(|| {
                ChrootPlanError::new(format!(
                    "device {} has no diagnosed filesystem type",
                    mount.device.name
                ))
            })?
            .to_ascii_lowercase();
        Ok(Self {
            device_identity: format!("{}|{}", mount.device.name, mount.device.id()),
            filesystem,
            selector: mount.options.first().cloned(),
            mount_point: mount.mount_point.clone(),
        })
    }
}

pub fn build_plan(inputs: ChrootPlanInputs<'_>) -> Result<ChrootPlan, ChrootPlanError> {
    if !inputs
        .devices
        .iter()
        .any(|device| device == inputs.root_device)
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
    let root_identity = MountIdentity::from_mount(&root)?;

    let mut mounts = Vec::new();
    let mut warnings = Vec::new();
    let mut exact_mounts = HashSet::from([root_identity.clone()]);
    let mut mount_points = HashMap::from([("/".to_string(), root_identity)]);

    for entry in inputs.fstab {
        if entry.mountpoint == "/" {
            if let Err(error) = validate_root_fstab_entry(
                entry,
                inputs.root_device,
                inputs.root_subvolume,
                inputs.devices,
            ) {
                warnings.push(format!(
                    "root fstab entry was ignored; selected root remains authoritative: {error}"
                ));
            }
            continue;
        }
        if entry.vfs_type.eq_ignore_ascii_case("swap") {
            continue;
        }
        if entry.mount_options.iter().any(|option| option == "noauto") {
            continue;
        }
        if is_pseudo_filesystem(entry) {
            warnings.push(format!(
                "fstab pseudo-filesystem {} at {} is delegated to arch-chroot runtime setup",
                entry.vfs_type, entry.mountpoint
            ));
            continue;
        }

        if let Err(error) = validate_mount_point(&entry.mountpoint) {
            warnings.push(format!(
                "fstab entry {} at {} was skipped: {error}",
                entry.fs_spec, entry.mountpoint
            ));
            continue;
        }
        let device = match resolve_device(&entry.fs_spec, inputs.devices) {
            Ok(device) => device,
            Err(error) => {
                warnings.push(fstab_skip_warning(entry, &error));
                continue;
            }
        };
        if let Err(error) = validate_entry_filesystem(entry, device) {
            warnings.push(fstab_skip_warning(entry, &error));
            continue;
        }
        let options = match selected_mount_options(entry, device) {
            Ok(options) => options,
            Err(error) => {
                warnings.push(fstab_skip_warning(entry, &error));
                continue;
            }
        };
        let mount = ChrootMount {
            device: device.clone(),
            mount_point: entry.mountpoint.clone(),
            options,
            kind: ChrootMountKind::Fstab,
        };
        if let Err(error) = register_mount(
            mount,
            &mut mounts,
            &mut exact_mounts,
            &mut mount_points,
            &mut warnings,
        ) {
            warnings.push(fstab_skip_warning(entry, &error));
        }
    }

    for selection in inputs.extra_mounts {
        validate_mount_point(&selection.mount_point)?;
        if !inputs
            .devices
            .iter()
            .any(|device| device == &selection.device)
        {
            return Err(ChrootPlanError::undiscovered_device(&selection.device));
        }
        let mount = ChrootMount {
            device: selection.device.clone(),
            mount_point: selection.mount_point.clone(),
            options: Vec::new(),
            kind: ChrootMountKind::Extra,
        };
        register_mount(
            mount,
            &mut mounts,
            &mut exact_mounts,
            &mut mount_points,
            &mut warnings,
        )?;
    }

    mounts.sort_by(|left, right| {
        Path::new(&left.mount_point)
            .components()
            .count()
            .cmp(&Path::new(&right.mount_point).components().count())
            .then_with(|| left.mount_point.cmp(&right.mount_point))
    });

    Ok(ChrootPlan {
        root,
        mounts,
        use_systemd_chroot: inputs.use_systemd_chroot,
        warnings,
    })
}

fn fstab_skip_warning(entry: &FsTabEntry, error: &ChrootPlanError) -> String {
    format!(
        "fstab entry {} at {} was skipped: {error}",
        entry.fs_spec, entry.mountpoint
    )
}

fn register_mount(
    mount: ChrootMount,
    mounts: &mut Vec<ChrootMount>,
    exact_mounts: &mut HashSet<MountIdentity>,
    mount_points: &mut HashMap<String, MountIdentity>,
    warnings: &mut Vec<String>,
) -> Result<(), ChrootPlanError> {
    let identity = MountIdentity::from_mount(&mount)?;
    if exact_mounts.contains(&identity) {
        warnings.push(format!(
            "duplicate mount {} at {} was ignored",
            mount.device.name, mount.mount_point
        ));
        return Ok(());
    }
    if let Some(existing) = mount_points.get(&mount.mount_point) {
        return Err(ChrootPlanError::new(format!(
            "conflicting mount entries for {}: {} ({}, {:?}) versus {} ({}, {:?})",
            mount.mount_point,
            existing.device_identity,
            existing.filesystem,
            existing.selector,
            identity.device_identity,
            identity.filesystem,
            identity.selector
        )));
    }
    exact_mounts.insert(identity.clone());
    mount_points.insert(mount.mount_point.clone(), identity);
    mounts.push(mount);
    Ok(())
}

fn validate_root_fstab_entry(
    entry: &FsTabEntry,
    root_device: &BlockDevice,
    root_subvolume: Option<&Subvolume>,
    devices: &[BlockDevice],
) -> Result<(), ChrootPlanError> {
    let device = resolve_device(&entry.fs_spec, devices)
        .map_err(|error| ChrootPlanError::new(format!("root fstab entry is invalid: {error}")))?;
    validate_entry_filesystem(entry, device)
        .map_err(|error| ChrootPlanError::new(format!("root fstab entry is invalid: {error}")))?;
    if device.name != root_device.name {
        return Err(ChrootPlanError::new(format!(
            "root fstab entry resolves to {}, but selected root is {}",
            device.name, root_device.name
        )));
    }

    let selector = selected_mount_options(entry, device)?.into_iter().next();
    match (root_subvolume, selector.as_deref()) {
        (None, None) => Ok(()),
        (None, Some(selector)) => Err(ChrootPlanError::new(format!(
            "root fstab entry selects {selector}, but the selected root has no Btrfs subvolume"
        ))),
        (Some(subvolume), Some(selector)) if selector_matches_subvolume(selector, subvolume) => {
            Ok(())
        }
        (Some(subvolume), Some(selector)) => Err(ChrootPlanError::new(format!(
            "root fstab entry selects {selector}, but selected root is subvolid={} subvol={}",
            subvolume.id, subvolume.name
        ))),
        (Some(subvolume), None) => Err(ChrootPlanError::new(format!(
            "root fstab entry does not identify selected Btrfs subvolume {} ({})",
            subvolume.name, subvolume.id
        ))),
    }
}

fn selector_matches_subvolume(selector: &str, subvolume: &Subvolume) -> bool {
    selector
        .strip_prefix("subvolid=")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|id| id == subvolume.id)
        || selector.strip_prefix("subvol=").is_some_and(|name| {
            normalize_subvolume_name(name) == normalize_subvolume_name(&subvolume.name)
        })
}

fn validate_entry_filesystem(
    entry: &FsTabEntry,
    device: &BlockDevice,
) -> Result<(), ChrootPlanError> {
    let diagnosed = device.fs_type.as_deref().ok_or_else(|| {
        ChrootPlanError::new(format!(
            "device {} for {} has no diagnosed filesystem type",
            device.name, entry.mountpoint
        ))
    })?;
    if !entry.vfs_type.eq_ignore_ascii_case("auto")
        && !diagnosed.eq_ignore_ascii_case(&entry.vfs_type)
    {
        return Err(ChrootPlanError::new(format!(
            "fstab filesystem {} for {} disagrees with diagnosed {} on {}",
            entry.vfs_type, entry.mountpoint, diagnosed, device.name
        )));
    }
    Ok(())
}

fn resolve_device<'a>(
    spec: &str,
    devices: &'a [BlockDevice],
) -> Result<&'a BlockDevice, ChrootPlanError> {
    let matches = devices
        .iter()
        .filter(|device| device.matches_spec(spec))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [device] => Ok(*device),
        [] => Err(ChrootPlanError::new(format!(
            "fstab device {spec} was not discovered"
        ))),
        _ => Err(ChrootPlanError::new(format!(
            "fstab device {spec} is ambiguous across {} discovered devices",
            matches.len()
        ))),
    }
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

fn selected_mount_options(
    entry: &FsTabEntry,
    device: &BlockDevice,
) -> Result<Vec<String>, ChrootPlanError> {
    let subvolid = entry
        .mount_options
        .iter()
        .find(|option| option.starts_with("subvolid="));
    let subvol = entry
        .mount_options
        .iter()
        .find(|option| option.starts_with("subvol="));
    if !device.is_btrfs() && (subvolid.is_some() || subvol.is_some()) {
        return Err(ChrootPlanError::new(format!(
            "Btrfs selector is not valid for non-Btrfs filesystem {} at {}",
            device.name, entry.mountpoint
        )));
    }

    if let Some(option) = subvolid {
        let raw = option.trim_start_matches("subvolid=");
        let id = raw.parse::<u64>().map_err(|_| {
            ChrootPlanError::new(format!(
                "invalid Btrfs subvolid {raw:?} for {} at {}",
                device.name, entry.mountpoint
            ))
        })?;
        return Ok(vec![format!("subvolid={id}")]);
    }

    if let Some(option) = subvol {
        let raw = option.trim_start_matches("subvol=");
        let normalized = normalize_subvolume_name(raw);
        if normalized.is_empty() {
            return Err(ChrootPlanError::new(format!(
                "empty Btrfs selector for {} at {}",
                device.name, entry.mountpoint
            )));
        }
        return Ok(vec![format!("subvol={normalized}")]);
    }

    Ok(Vec::new())
}

fn normalize_subvolume_name(value: &str) -> &str {
    value.trim_start_matches('/')
}

fn is_pseudo_filesystem(entry: &FsTabEntry) -> bool {
    matches!(
        entry.vfs_type.to_ascii_lowercase().as_str(),
        "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "tmpfs"
            | "efivarfs"
            | "cgroup"
            | "cgroup2"
            | "securityfs"
            | "debugfs"
            | "tracefs"
            | "configfs"
            | "pstore"
            | "bpf"
            | "ramfs"
            | "hugetlbfs"
            | "mqueue"
    )
}
