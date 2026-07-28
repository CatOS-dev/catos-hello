//! Target-side inspection and post-repair verification helpers.

use crate::diagnose::provider::DetectionInputs;
use crate::io::{has_target_path, read_target_file};
use catos_mount::model::MountTargetIdentity;
use catos_target::diagnose::candidate::device_matches_fstab_source;
use catos_target::fstab::{parse_all_with_diagnostics, FstabEntryKind, FstabSource};
use catos_target::model::BlockDevice;
use catos_target::Evidence;
use std::path::Path;
use std::time::Duration;

/// Collect the complete target-side root encryption and resume identity used by
/// boot providers. Any unresolved or ambiguous encrypted identity is fatal: the
/// caller must refuse before writing provider configuration.
pub fn collect_boot_cmdline_facts(
    target: &MountTargetIdentity,
    target_root: &Path,
    devices: &[BlockDevice],
) -> Result<crate::model::BootCmdlineFacts, crate::model::BootCmdlineFactsError> {
    collect_boot_cmdline_facts_with(
        target,
        target_root,
        devices,
        observed_mapper_name,
        map_btrfs_swapfile,
    )
}

fn collect_boot_cmdline_facts_with<M, S>(
    target: &MountTargetIdentity,
    target_root: &Path,
    devices: &[BlockDevice],
    mut mapper_name: M,
    mut map_swapfile: S,
) -> Result<crate::model::BootCmdlineFacts, crate::model::BootCmdlineFactsError>
where
    M: FnMut(&BlockDevice) -> Result<Option<String>, String>,
    S: FnMut(&Path) -> Result<u64, String>,
{
    use crate::model::{BootCmdlineFacts, LuksMapping, ResumeTarget};

    let mut evidence = Vec::new();
    let root_device = find_inventory_device(&target.root_device, devices, &mut mapper_name)
        .map_err(|message| facts_error("ROOT_DEVICE_IDENTITY_UNRESOLVED", message, &evidence))?;

    let root_mapper = mapper_name(root_device)
        .map_err(|message| facts_error("ROOT_MAPPER_UNREADABLE", message, &evidence))?;
    let root_parent = parent_device_checked(root_device, devices)
        .map_err(|message| facts_error("ROOT_BACKING_DEVICE_UNRESOLVED", message, &evidence))?;
    if root_mapper.is_some() && root_device.parent.is_empty() {
        return Err(facts_error(
            "ROOT_MAPPER_BACKING_MISSING",
            format!(
                "mapped root {} has no verified backing-device relationship",
                display_device(root_device)
            ),
            &evidence,
        ));
    }
    let root_is_luks =
        root_parent.is_some_and(|parent| is_crypto_luks(parent.filesystem.as_deref()));
    if !root_is_luks
        && ancestor_contains_luks(root_device, devices)
            .map_err(|message| facts_error("ROOT_BACKING_DEVICE_UNRESOLVED", message, &evidence))?
    {
        return Err(facts_error(
            "ROOT_LUKS_STACK_UNSUPPORTED",
            format!(
                "root {} is above a multi-layer device-mapper/LUKS stack; the dm-crypt mapper cannot be safely inferred",
                display_device(root_device)
            ),
            &evidence,
        ));
    }
    let luks_root = if root_is_luks {
        let parent = root_parent.expect("checked LUKS parent");
        let luks_uuid = parent
            .uuid
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                facts_error(
                    "ROOT_LUKS_UUID_MISSING",
                    format!(
                        "encrypted root backing device {} has no LUKS UUID",
                        display_device(parent)
                    ),
                    &evidence,
                )
            })?;
        let mapper_name = root_mapper.ok_or_else(|| {
            facts_error(
                "ROOT_MAPPER_NAME_MISSING",
                format!(
                    "encrypted root {} has no verified dm-crypt mapper name",
                    target.root_device.display()
                ),
                &evidence,
            )
        })?;
        evidence.push(
            Evidence::new(
                "ROOT_LUKS_IDENTITY",
                display_device(parent),
                "root dm-crypt backing UUID and mapper name established from block topology",
            )
            .with_value(format!("UUID={luks_uuid} mapper={mapper_name}")),
        );
        Some(LuksMapping {
            luks_uuid,
            mapper_name,
        })
    } else {
        evidence.push(Evidence::new(
            "ROOT_NOT_LUKS",
            display_device(root_device),
            "root block topology has no crypto_LUKS backing device",
        ));
        None
    };
    if luks_root.is_none()
        && target
            .root_uuid
            .as_deref()
            .map_or(true, |value| value.is_empty())
    {
        return Err(facts_error(
            "ROOT_UUID_MISSING",
            format!(
                "unencrypted root {} has no stable filesystem UUID",
                display_device(root_device)
            ),
            &evidence,
        ));
    }

    let fstab_bytes = catos_target::execute::confined::read_rooted_file(target_root, "/etc/fstab")
        .map_err(|error| {
            facts_error(
                "TARGET_FSTAB_UNREADABLE",
                format!("cannot read selected target /etc/fstab: {error}"),
                &evidence,
            )
        })?;
    let fstab = String::from_utf8(fstab_bytes).map_err(|_| {
        facts_error(
            "TARGET_FSTAB_NON_UTF8",
            "selected target /etc/fstab is not UTF-8".into(),
            &evidence,
        )
    })?;
    let (entries, diagnostics) = parse_all_with_diagnostics(&fstab);
    if !diagnostics.is_empty() {
        return Err(facts_error(
            "TARGET_FSTAB_INVALID",
            format!(
                "selected target fstab contains {} malformed line(s)",
                diagnostics.len()
            ),
            &evidence,
        ));
    }

    let mut resume_candidates = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == FstabEntryKind::Swap)
        .filter(|entry| !entry.noauto)
    {
        match &entry.source {
            FstabSource::Path(path) if !path.starts_with("/dev/") => {
                if target.root_fstype != "btrfs" {
                    return Err(facts_error(
                        "SWAPFILE_OFFSET_UNSUPPORTED",
                        format!(
                            "swap file {path} requires an offset probe unsupported for {}",
                            target.root_fstype
                        ),
                        &evidence,
                    ));
                }
                let swapfile = safe_target_file_path(target_root, path)
                    .map_err(|message| facts_error("SWAPFILE_PATH_UNSAFE", message, &evidence))?;
                let offset = map_swapfile(&swapfile).map_err(|message| {
                    facts_error("SWAPFILE_OFFSET_UNRESOLVED", message, &evidence)
                })?;
                let device = luks_root
                    .as_ref()
                    .map(|mapping| format!("/dev/mapper/{}", mapping.mapper_name))
                    .unwrap_or_else(|| target.root_device.display().to_string());
                evidence.push(
                    Evidence::new(
                        "SWAPFILE_RESUME_IDENTITY",
                        swapfile.display().to_string(),
                        "Btrfs swap-file backing device and resume offset established",
                    )
                    .with_value(format!("device={device} offset={offset}")),
                );
                resume_candidates.push(ResumeTarget::SwapFile { device, offset });
            }
            source => {
                let mut matches = Vec::new();
                for device in devices {
                    if boot_source_matches(device, source, &mut mapper_name).map_err(|message| {
                        facts_error("SWAP_MAPPER_UNREADABLE", message, &evidence)
                    })? {
                        matches.push(device);
                    }
                }
                let device = match matches.as_slice() {
                    [device] => *device,
                    [] => {
                        return Err(facts_error(
                            "SWAP_DEVICE_UNRESOLVED",
                            format!("swap source {:?} resolves to no inventory device", source),
                            &evidence,
                        ))
                    }
                    _ => {
                        return Err(facts_error(
                            "SWAP_DEVICE_AMBIGUOUS",
                            format!(
                                "swap source {:?} resolves to {} inventory devices",
                                source,
                                matches.len()
                            ),
                            &evidence,
                        ))
                    }
                };
                let mapper = mapper_name(device)
                    .map_err(|message| facts_error("SWAP_MAPPER_UNREADABLE", message, &evidence))?;
                let parent = parent_device_checked(device, devices).map_err(|message| {
                    facts_error("SWAP_BACKING_DEVICE_UNRESOLVED", message, &evidence)
                })?;
                if mapper.is_some() && device.parent.is_empty() {
                    return Err(facts_error(
                        "SWAP_MAPPER_BACKING_MISSING",
                        format!(
                            "mapped swap {} has no verified backing-device relationship",
                            display_device(device)
                        ),
                        &evidence,
                    ));
                }
                let encrypted =
                    parent.is_some_and(|parent| is_crypto_luks(parent.filesystem.as_deref()));
                if !encrypted
                    && ancestor_contains_luks(device, devices).map_err(|message| {
                        facts_error("SWAP_BACKING_DEVICE_UNRESOLVED", message, &evidence)
                    })?
                {
                    return Err(facts_error(
                        "SWAP_LUKS_STACK_UNSUPPORTED",
                        format!(
                            "swap {} is above a multi-layer device-mapper/LUKS stack; the dm-crypt mapper cannot be safely inferred",
                            display_device(device)
                        ),
                        &evidence,
                    ));
                }
                if encrypted {
                    let mapper_name = mapper.ok_or_else(|| {
                        facts_error(
                            "SWAP_MAPPER_NAME_MISSING",
                            format!(
                                "encrypted swap {} has no verified mapper name",
                                display_device(device)
                            ),
                            &evidence,
                        )
                    })?;
                    evidence.push(
                        Evidence::new(
                            "SWAP_LUKS_IDENTITY",
                            display_device(device),
                            "encrypted swap mapper established from target fstab and block topology",
                        )
                        .with_value(mapper_name.clone()),
                    );
                    resume_candidates.push(ResumeTarget::Mapper { mapper_name });
                } else {
                    let uuid = device
                        .uuid
                        .clone()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            facts_error(
                                "SWAP_UUID_MISSING",
                                format!(
                                    "swap device {} has no filesystem UUID",
                                    display_device(device)
                                ),
                                &evidence,
                            )
                        })?;
                    evidence.push(
                        Evidence::new(
                            "SWAP_UUID_IDENTITY",
                            display_device(device),
                            "swap UUID established from target fstab and block inventory",
                        )
                        .with_value(uuid.clone()),
                    );
                    resume_candidates.push(ResumeTarget::Uuid { uuid });
                }
            }
        }
    }
    if resume_candidates.len() > 1 {
        return Err(facts_error(
            "MULTIPLE_RESUME_TARGETS",
            format!(
                "target fstab defines {} automatic swap targets; hibernation resume is ambiguous",
                resume_candidates.len()
            ),
            &evidence,
        ));
    }
    if resume_candidates.is_empty() {
        evidence.push(Evidence::new(
            "NO_RESUME_TARGET",
            "selected-target:/etc/fstab",
            "target fstab defines no automatic swap partition or swap file",
        ));
    }

    Ok(BootCmdlineFacts {
        luks_root,
        resume: resume_candidates.pop(),
        evidence,
    })
}

fn facts_error(
    code: &str,
    message: String,
    evidence: &[Evidence],
) -> crate::model::BootCmdlineFactsError {
    crate::model::BootCmdlineFactsError {
        code: code.into(),
        message,
        evidence: evidence.to_vec(),
    }
}

fn is_crypto_luks(filesystem: Option<&str>) -> bool {
    filesystem.is_some_and(|value| value.eq_ignore_ascii_case("crypto_LUKS"))
}

fn parent_device_checked<'a>(
    device: &BlockDevice,
    devices: &'a [BlockDevice],
) -> Result<Option<&'a BlockDevice>, String> {
    if device.parent.is_empty() {
        return Ok(None);
    }
    let matches = devices
        .iter()
        .filter(|candidate| candidate.name == device.parent)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [parent] => Ok(Some(*parent)),
        [] => Err(format!(
            "backing device {} for {} is absent from inventory",
            device.parent,
            display_device(device)
        )),
        _ => Err(format!(
            "backing device {} for {} is ambiguous",
            device.parent,
            display_device(device)
        )),
    }
}

fn ancestor_contains_luks(device: &BlockDevice, devices: &[BlockDevice]) -> Result<bool, String> {
    let mut current = device;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..=devices.len() {
        if !visited.insert(current.name.as_str()) {
            return Err(format!(
                "block backing chain for {} contains a cycle at {}",
                display_device(device),
                current.name
            ));
        }
        let Some(parent) = parent_device_checked(current, devices)? else {
            return Ok(false);
        };
        if is_crypto_luks(parent.filesystem.as_deref()) {
            return Ok(true);
        }
        current = parent;
    }
    Err(format!(
        "block backing chain for {} exceeds inventory size",
        display_device(device)
    ))
}

fn display_device(device: &BlockDevice) -> String {
    device
        .dev_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| device.name.clone())
}

fn observed_mapper_name(device: &BlockDevice) -> Result<Option<String>, String> {
    if let Some(path) = device.dev_path.as_deref() {
        if path.parent() == Some(Path::new("/dev/mapper")) {
            return Ok(path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string));
        }
    }
    let path = Path::new("/sys/class/block")
        .join(&device.name)
        .join("dm/name");
    match std::fs::read_to_string(&path) {
        Ok(name) => {
            let name = name.trim();
            if name.is_empty() {
                Err(format!("{} contains an empty mapper name", path.display()))
            } else {
                Ok(Some(name.to_string()))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn find_inventory_device<'a, M>(
    path: &Path,
    devices: &'a [BlockDevice],
    mapper_name: &mut M,
) -> Result<&'a BlockDevice, String>
where
    M: FnMut(&BlockDevice) -> Result<Option<String>, String>,
{
    let requested_mapper = (path.parent() == Some(Path::new("/dev/mapper")))
        .then(|| path.file_name().and_then(|name| name.to_str()))
        .flatten();
    let mut matches = Vec::new();
    for device in devices {
        if device.dev_path.as_deref() == Some(path) {
            matches.push(device);
            continue;
        }
        if let Some(requested) = requested_mapper {
            if mapper_name(device)?.as_deref() == Some(requested) {
                matches.push(device);
            }
        }
    }
    match matches.as_slice() {
        [device] => Ok(*device),
        [] => Err(format!(
            "{} is absent from the current block inventory",
            path.display()
        )),
        _ => Err(format!(
            "{} matches multiple block inventory entries",
            path.display()
        )),
    }
}

fn boot_source_matches<M>(
    device: &BlockDevice,
    source: &FstabSource,
    mapper_name: &mut M,
) -> Result<bool, String>
where
    M: FnMut(&BlockDevice) -> Result<Option<String>, String>,
{
    if device_matches_fstab_source(device, source) {
        return Ok(true);
    }
    let FstabSource::Path(path) = source else {
        return Ok(false);
    };
    let path = Path::new(path);
    if path.parent() != Some(Path::new("/dev/mapper")) {
        return Ok(false);
    }
    Ok(mapper_name(device)?.as_deref() == path.file_name().and_then(|name| name.to_str()))
}

fn safe_target_file_path(root: &Path, absolute: &str) -> Result<std::path::PathBuf, String> {
    use std::path::Component;
    let path = Path::new(absolute);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!(
            "swap file path {absolute:?} is not a safe absolute target path"
        ));
    }
    let mut current = root.to_path_buf();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(component) => current.push(component),
            Component::ParentDir | Component::Prefix(_) => unreachable!(),
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect {}: {error}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "swap file path crosses symlink {}",
                current.display()
            ));
        }
    }
    let metadata = std::fs::metadata(&current)
        .map_err(|error| format!("cannot inspect swap file {}: {error}", current.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "swap file {} is not a regular file",
            current.display()
        ));
    }
    Ok(current)
}

fn map_btrfs_swapfile(path: &Path) -> Result<u64, String> {
    let path = path
        .to_str()
        .ok_or_else(|| format!("swap file path {} is not UTF-8", path.display()))?;
    let output = catos_process::run_trusted_tool(
        "btrfs",
        &["inspect-internal", "map-swapfile", "-r", path],
        Duration::from_secs(10),
        64 * 1024,
    )?;
    if output.timed_out || output.stdout_truncated || output.stderr_truncated {
        return Err("btrfs map-swapfile did not return complete output".into());
    }
    if !output.success() {
        return Err(format!(
            "btrfs map-swapfile failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "btrfs map-swapfile output is not UTF-8".to_string())?
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("invalid btrfs resume offset: {error}"))
}

pub fn detect_target_architecture(root: &Path) -> Option<crate::model::Architecture> {
    let executable =
        catos_target::execute::confined::read_rooted_file(root, "/usr/lib/systemd/systemd").ok()?;
    let machine = executable.get(18..20)?;
    match u16::from_le_bytes([machine[0], machine[1]]) {
        62 => Some(crate::model::Architecture::X86_64),
        183 => Some(crate::model::Architecture::Aarch64),
        _ => None,
    }
}

pub fn detect_partition_table(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> crate::model::PartitionTable {
    use catos_target::model::DiskKind;

    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    });
    match root.map(|device| device.disk_kind) {
        Some(DiskKind::Gpt) => crate::model::PartitionTable::Gpt,
        Some(DiskKind::Mbr) => crate::model::PartitionTable::Msdos,
        _ => crate::model::PartitionTable::Unknown,
    }
}

pub fn derive_bios_install_disk(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> Option<String> {
    let root = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == target.root_device)
    })?;
    if root.parent.is_empty() {
        return None;
    }
    let matches: Vec<&catos_target::model::BlockDevice> = devices
        .iter()
        .filter(|device| device.name == root.parent)
        .filter(|device| device.parent.is_empty())
        .filter(|device| device.dev_path.is_some())
        .collect();
    match matches.as_slice() {
        [disk] => disk.dev_path.as_ref()?.to_str().map(str::to_string),
        _ => None,
    }
}

pub fn derive_efi_device(
    target: &MountTargetIdentity,
    devices: &[catos_target::model::BlockDevice],
) -> Option<(String, u32)> {
    let esp_path = target.esp_device.as_deref()?;
    let esp = devices.iter().find(|device| {
        device
            .dev_path
            .as_deref()
            .is_some_and(|path| path == esp_path)
    })?;
    let partition = esp.partition_number?;
    if esp.parent.is_empty() {
        return None;
    }
    let disk = devices
        .iter()
        .find(|device| device.name == esp.parent && device.parent.is_empty())?;
    let disk_path = disk.dev_path.as_ref()?.to_str()?.to_string();
    Some((disk_path, partition))
}

pub fn collect_detection_inputs_from_target_root(root: &Path) -> DetectionInputs {
    DetectionInputs {
        grub_defaults_catos: read_target_file(root, "etc/default/grub.d/00-catos.cfg"),
        limine_defaults: read_target_file(root, "etc/default/limine"),
        kernel_install_catos: read_target_file(
            root,
            "etc/kernel/install.conf.d/20-catos-bootloadu.conf",
        ),
        firmware_boot_conf: read_target_file(root, "etc/catos/firmware-boot.conf"),
        kernel_cmdline: read_target_file(root, "etc/kernel/cmdline"),
        has_boot_grub: has_target_path(root, "boot/grub"),
        has_esp_limine_conf: target_regular_file_in_any(
            root,
            &[
                "boot/limine.conf",
                "boot/efi/limine.conf",
                "efi/limine.conf",
            ],
        ),
        has_systemd_boot_loader: target_regular_file_in_any(
            root,
            &[
                "boot/loader/loader.conf",
                "boot/efi/loader/loader.conf",
                "efi/loader/loader.conf",
            ],
        ),
        has_catos_uki_deployed: target_uki_deployed(root),
        has_efistub_deployed: target_efistub_deployed(root),
        installed_packages: Vec::new(),
    }
}

pub fn collect_installed_packages_from_target_root(root: &Path) -> Vec<String> {
    catos_target::execute::confined::list_rooted_directory_names(root, "/var/lib/pacman/local")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_string().ok())
        .filter_map(|entry| {
            catos_target::execute::confined::read_rooted_file(
                root,
                &format!("/var/lib/pacman/local/{entry}/desc"),
            )
            .ok()
        })
        .filter_map(|contents| String::from_utf8(contents).ok())
        .filter_map(|contents| pacman_package_name(&contents))
        .collect()
}

pub fn collect_target_kernels(root: &Path) -> Vec<crate::plan::initramfs::Kernel> {
    let entries =
        catos_target::execute::confined::list_rooted_directory_names(root, "/usr/lib/modules")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .map(|version| {
                let base = format!("/usr/lib/modules/{version}");
                let pkgbase = catos_target::execute::confined::read_rooted_file(
                    root,
                    &format!("{base}/pkgbase"),
                )
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
                let has_vmlinuz = catos_target::execute::confined::rooted_regular_file_size(
                    root,
                    &format!("{base}/vmlinuz"),
                )
                .ok()
                .flatten()
                .is_some_and(|size| size > 0);
                (version, !pkgbase.is_empty(), has_vmlinuz, pkgbase)
            })
            .collect::<Vec<_>>();
    crate::plan::initramfs::discover_kernels(&entries)
}

fn pacman_package_name(desc: &str) -> Option<String> {
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        if line == "%NAME%" {
            return lines
                .next()
                .map(str::to_string)
                .filter(|name| !name.is_empty());
        }
    }
    None
}

pub fn target_regular_file_present(root: &Path, relative: &str) -> bool {
    catos_target::execute::confined::rooted_regular_file_size(root, &format!("/{relative}"))
        .ok()
        .flatten()
        .is_some_and(|size| size > 0)
}

pub fn target_regular_file_in_any(root: &Path, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| target_regular_file_present(root, candidate))
}

pub fn target_uki_deployed(root: &Path) -> bool {
    ["/boot/EFI/Linux", "/boot/efi/EFI/Linux", "/efi/EFI/Linux"]
        .iter()
        .any(|directory| {
            catos_target::execute::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .any(|entry| {
                    entry
                        .to_str()
                        .is_some_and(|entry| entry.starts_with("catos-") && entry.ends_with(".efi"))
                })
        })
}

pub fn target_efistub_deployed(root: &Path) -> bool {
    ["/boot/EFI/CatOS", "/boot/efi/EFI/CatOS", "/efi/EFI/CatOS"]
        .iter()
        .any(|directory| {
            catos_target::execute::confined::list_rooted_directory_names(root, directory)
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| entry.to_str().map(str::to_string))
                .any(|package| {
                    target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/vmlinuz.efi",
                            directory.trim_start_matches('/')
                        ),
                    ) && target_regular_file_present(
                        root,
                        &format!(
                            "{}/{package}/initramfs.img",
                            directory.trim_start_matches('/')
                        ),
                    )
                })
        })
}
pub fn target_secureboot_marker_present(target_root: &Path) -> bool {
    has_target_path(target_root, "etc/catos/secureboot")
        || read_target_file(target_root, "etc/catos/secureboot.conf").is_some()
        || has_target_path(target_root, "var/lib/catos/secureboot")
}

pub fn target_signed_catos_efi_present(target_root: &Path, esp_mount_point: Option<&str>) -> bool {
    let Some(esp_mount_point) = esp_mount_point else {
        return false;
    };
    let directory = format!("/{}/EFI/CatOS", esp_mount_point.trim_start_matches('/'));
    let entries =
        catos_target::execute::confined::list_rooted_directory_names(target_root, &directory)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .collect::<Vec<_>>();
    entries.iter().any(|entry| entry.ends_with(".efi"))
        && entries
            .iter()
            .any(|entry| entry.ends_with(".sig") || entry.ends_with(".p7b"))
}

#[cfg(test)]
mod cmdline_facts_tests {
    use super::*;
    use crate::model::{LuksMapping, ResumeTarget};
    use catos_target::model::{DeviceClass, DiskKind, PartitionRole};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(fstab: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "catos-boot-cmdline-facts-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("etc")).unwrap();
            std::fs::write(path.join("etc/fstab"), fstab).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn device(
        name: &str,
        path: &str,
        parent: &str,
        filesystem: Option<&str>,
        uuid: Option<&str>,
    ) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            dev_path: Some(PathBuf::from(path)),
            major_minor: None,
            parent: parent.into(),
            class: if parent.is_empty() {
                DeviceClass::Partition
            } else {
                DeviceClass::DeviceMapper
            },
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: filesystem.map(str::to_string),
            uuid: uuid.map(str::to_string),
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        }
    }

    fn target(path: &str) -> MountTargetIdentity {
        MountTargetIdentity {
            root_device: PathBuf::from(path),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("root-fs".into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        }
    }

    fn mapper_name(device: &BlockDevice) -> Result<Option<String>, String> {
        Ok(device
            .dev_path
            .as_deref()
            .filter(|path| path.parent() == Some(Path::new("/dev/mapper")))
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_string))
    }

    #[test]
    fn encrypted_root_and_swap_are_derived_from_target_topology() {
        let root = TempRoot::new(
            "UUID=root-fs / btrfs defaults,subvol=/@ 0 0\n/dev/mapper/cryptswap none swap defaults 0 0\n",
        );
        let devices = vec![
            device(
                "nvme0n1p2",
                "/dev/nvme0n1p2",
                "",
                Some("crypto_LUKS"),
                Some("luks-root"),
            ),
            device(
                "dm-0",
                "/dev/mapper/cryptroot",
                "nvme0n1p2",
                Some("btrfs"),
                Some("root-fs"),
            ),
            device(
                "nvme0n1p3",
                "/dev/nvme0n1p3",
                "",
                Some("crypto_LUKS"),
                Some("luks-swap"),
            ),
            device(
                "dm-1",
                "/dev/mapper/cryptswap",
                "nvme0n1p3",
                Some("swap"),
                Some("swap-fs"),
            ),
        ];

        let facts = collect_boot_cmdline_facts_with(
            &target("/dev/mapper/cryptroot"),
            &root.0,
            &devices,
            mapper_name,
            |_| panic!("partition swap must not request swapfile mapping"),
        )
        .unwrap();

        assert_eq!(
            facts.luks_root,
            Some(LuksMapping {
                luks_uuid: "luks-root".into(),
                mapper_name: "cryptroot".into(),
            })
        );
        assert_eq!(
            facts.resume,
            Some(ResumeTarget::Mapper {
                mapper_name: "cryptswap".into(),
            })
        );
    }

    #[test]
    fn plain_swap_partition_uses_real_swap_uuid() {
        let root = TempRoot::new(
            "UUID=root-fs / btrfs defaults,subvol=/@ 0 0\nUUID=swap-uuid none swap defaults 0 0\n",
        );
        let devices = vec![
            device("sda2", "/dev/sda2", "", Some("btrfs"), Some("root-fs")),
            device("sda3", "/dev/sda3", "", Some("swap"), Some("swap-uuid")),
        ];
        let facts = collect_boot_cmdline_facts_with(
            &target("/dev/sda2"),
            &root.0,
            &devices,
            mapper_name,
            |_| panic!("partition swap must not request swapfile mapping"),
        )
        .unwrap();
        assert_eq!(
            facts.resume,
            Some(ResumeTarget::Uuid {
                uuid: "swap-uuid".into(),
            })
        );
    }

    #[test]
    fn btrfs_swapfile_records_resume_device_and_offset() {
        let root = TempRoot::new(
            "UUID=root-fs / btrfs defaults,subvol=/@ 0 0\n/swapfile none swap defaults 0 0\n",
        );
        std::fs::write(root.0.join("swapfile"), b"fixture").unwrap();
        let devices = vec![device(
            "sda2",
            "/dev/sda2",
            "",
            Some("btrfs"),
            Some("root-fs"),
        )];
        let facts = collect_boot_cmdline_facts_with(
            &target("/dev/sda2"),
            &root.0,
            &devices,
            mapper_name,
            |path| {
                assert_eq!(path, root.0.join("swapfile"));
                Ok(8192)
            },
        )
        .unwrap();
        assert_eq!(
            facts.resume,
            Some(ResumeTarget::SwapFile {
                device: "/dev/sda2".into(),
                offset: 8192,
            })
        );
    }

    #[test]
    fn plain_root_without_uuid_fails_before_cmdline_generation() {
        let root = TempRoot::new("/dev/sda2 / btrfs defaults,subvol=/@ 0 0\n");
        let devices = vec![device("sda2", "/dev/sda2", "", Some("btrfs"), None)];
        let mut target = target("/dev/sda2");
        target.root_uuid = None;
        let error = collect_boot_cmdline_facts_with(
            &target,
            &root.0,
            &devices,
            mapper_name,
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(error.code, "ROOT_UUID_MISSING");
    }

    #[test]
    fn multiple_automatic_swap_targets_fail_closed() {
        let root = TempRoot::new(
            "UUID=root-fs / btrfs defaults,subvol=/@ 0 0\nUUID=swap-a none swap defaults 0 0\nUUID=swap-b none swap defaults 0 0\n",
        );
        let devices = vec![
            device("sda2", "/dev/sda2", "", Some("btrfs"), Some("root-fs")),
            device("sda3", "/dev/sda3", "", Some("swap"), Some("swap-a")),
            device("sda4", "/dev/sda4", "", Some("swap"), Some("swap-b")),
        ];
        let error = collect_boot_cmdline_facts_with(
            &target("/dev/sda2"),
            &root.0,
            &devices,
            mapper_name,
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(error.code, "MULTIPLE_RESUME_TARGETS");
    }

    #[test]
    fn multilayer_lvm_on_luks_root_fails_closed_instead_of_guessing_mapper() {
        let root = TempRoot::new("UUID=root-fs / btrfs defaults,subvol=/@ 0 0\n");
        let devices = vec![
            device(
                "nvme0n1p2",
                "/dev/nvme0n1p2",
                "",
                Some("crypto_LUKS"),
                Some("luks-root"),
            ),
            device(
                "dm-0",
                "/dev/mapper/cryptlvm",
                "nvme0n1p2",
                Some("LVM2_member"),
                None,
            ),
            device(
                "dm-1",
                "/dev/mapper/vg-root",
                "dm-0",
                Some("btrfs"),
                Some("root-fs"),
            ),
        ];
        let error = collect_boot_cmdline_facts_with(
            &target("/dev/mapper/vg-root"),
            &root.0,
            &devices,
            mapper_name,
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(error.code, "ROOT_LUKS_STACK_UNSUPPORTED");
    }

    #[test]
    fn mapped_root_without_backing_identity_is_not_treated_as_plain() {
        let root = TempRoot::new("UUID=root-fs / btrfs defaults,subvol=/@ 0 0\n");
        let devices = vec![device(
            "dm-0",
            "/dev/mapper/cryptroot",
            "",
            Some("btrfs"),
            Some("root-fs"),
        )];
        let error = collect_boot_cmdline_facts_with(
            &target("/dev/mapper/cryptroot"),
            &root.0,
            &devices,
            mapper_name,
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(error.code, "ROOT_MAPPER_BACKING_MISSING");
    }
}
