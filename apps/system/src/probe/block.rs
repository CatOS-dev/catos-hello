//! Read-only block-device discovery from sysfs, mountinfo, and blkid.
// allow: SIZE_OK — phase-2 contract requires discovery and its fixture tests in this module.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::model::evidence::Evidence;
use crate::model::inspection::Warning;
use crate::model::storage::{BlockDevice, DeviceClass, DiskKind, MountObservation, PartitionRole};
use crate::parse::{blkid, mountinfo};
use crate::probe::fs_probe::FilesystemProbe;
use crate::shared::process::run_trusted_tool;

const BLOCK_ROOT: &str = "/sys/class/block";
const MOUNTINFO: &str = "/proc/self/mountinfo";
const LINUX_FILESYSTEM_GUID: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

/// Discover block devices and supplement their signatures with `blkid` when available.
pub fn discover_devices(fs: &dyn FilesystemProbe) -> (Vec<BlockDevice>, Vec<Warning>) {
    let (mut devices, mut warnings) = discover_sysfs(fs);
    warnings.extend(supplement_from_udev_database(fs, &mut devices));
    warnings.extend(supplement_with_blkid(fs, &mut devices));
    (devices, warnings)
}

/// Probe every discovered device with `blkid -p -o udev`; failures are non-fatal warnings.
pub fn supplement_with_blkid(
    _fs: &dyn FilesystemProbe,
    devices: &mut [BlockDevice],
) -> Vec<Warning> {
    supplement_with_blkid_using(devices, |device| {
        if device.filesystem.is_some() && device.uuid.is_some() {
            return Ok(Vec::new());
        }
        let path = device
            .dev_path
            .as_ref()
            .ok_or_else(|| format!("no device path for {}", device.name))?;
        let path = path
            .to_str()
            .ok_or_else(|| format!("device path for {} is not UTF-8", device.name))?;
        let output = run_trusted_tool(
            "blkid",
            &["-p", "-o", "udev", path],
            Duration::from_secs(2),
            64 * 1024,
        )?;
        if output.timed_out {
            return Err(format!(
                "{} timed out probing {path}",
                output.path.display()
            ));
        }
        if output.stdout_truncated || output.stderr_truncated {
            return Err(format!(
                "{} output exceeded safety limit for {path}",
                output.path.display()
            ));
        }
        if output.success() {
            Ok(output.stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "{} failed for {path} with status {}: {}",
                output.path.display(),
                output.status,
                stderr.trim()
            ))
        }
    })
}

fn supplement_from_udev_database(
    fs: &dyn FilesystemProbe,
    devices: &mut [BlockDevice],
) -> Vec<Warning> {
    let mut warnings = Vec::new();
    for device in devices {
        let Some(major_minor) = device.major_minor.as_deref() else {
            continue;
        };
        let path = PathBuf::from(format!("/run/udev/data/b{major_minor}"));
        match fs.read_to_string(&path) {
            Ok(body) => {
                let info = blkid::parse_udev(&body);
                if info.present {
                    apply_blkid(device, info);
                    device.evidence.push(Evidence::new(
                        "UDEV_SIGNATURE",
                        path.display().to_string(),
                        "filesystem signature read from udev database",
                    ));
                }
            }
            Err(crate::shared::error::FsError::NotFound) => {}
            Err(error) => warnings.push(Warning::new(
                "UDEV_DATABASE_UNREADABLE",
                format!("cannot read {}: {error}", path.display()),
            )),
        }
    }
    warnings
}

fn discover_sysfs(fs: &dyn FilesystemProbe) -> (Vec<BlockDevice>, Vec<Warning>) {
    let root = Path::new(BLOCK_ROOT);
    let names = match fs.read_dir_names(root) {
        Ok(names) => names,
        Err(error) => {
            return (
                Vec::new(),
                vec![Warning::new(
                    "BLOCK_SYSFS_UNREADABLE",
                    format!("cannot enumerate {BLOCK_ROOT}: {error}"),
                )],
            );
        }
    };
    let mounts = match fs.read_to_string(Path::new(MOUNTINFO)) {
        Ok(body) => mountinfo::parse_all(&body),
        Err(error) => {
            return discover_without_mountinfo(fs, names, error);
        }
    };
    let mut devices: Vec<BlockDevice> = names
        .iter()
        .map(|name| device_from_sysfs(fs, name, &mounts))
        .collect();
    apply_relationships(fs, &mut devices);
    (devices, Vec::new())
}

fn discover_without_mountinfo(
    fs: &dyn FilesystemProbe,
    names: Vec<String>,
    error: crate::shared::error::FsError,
) -> (Vec<BlockDevice>, Vec<Warning>) {
    let mut devices: Vec<BlockDevice> = names
        .iter()
        .map(|name| device_from_sysfs(fs, name, &[]))
        .collect();
    apply_relationships(fs, &mut devices);
    (
        devices,
        vec![Warning::new(
            "MOUNTINFO_UNREADABLE",
            format!("cannot read {MOUNTINFO}: {error}"),
        )],
    )
}

fn device_from_sysfs(
    fs: &dyn FilesystemProbe,
    name: &str,
    mounts: &[mountinfo::MountInfo],
) -> BlockDevice {
    let base = Path::new(BLOCK_ROOT).join(name);
    let uevent_path = base.join("uevent");
    let uevent = fs
        .read_to_string(&uevent_path)
        .map(|body| parse_key_values(&body))
        .unwrap_or_default();
    let partition_path = base.join("partition");
    let partition = fs.read_to_string(&partition_path).ok();
    let class = classify(name, partition.is_some());
    let dev_path = PathBuf::from("/dev").join(name);
    let major_minor = match (uevent.get("MAJOR"), uevent.get("MINOR")) {
        (Some(major), Some(minor)) => Some(format!("{major}:{minor}")),
        _ => fs
            .read_to_string(&base.join("dev"))
            .ok()
            .map(|value| value.trim().to_string()),
    };
    let matching_mounts: Vec<&mountinfo::MountInfo> = mounts
        .iter()
        .filter(|entry| {
            entry.is_block_backed()
                && (major_minor
                    .as_ref()
                    .is_some_and(|value| entry.major_minor == *value)
                    || entry.source == dev_path.to_string_lossy())
        })
        .collect();
    let mount = matching_mounts.first().copied();
    let mount_observations: Vec<MountObservation> = matching_mounts
        .iter()
        .map(|entry| MountObservation {
            mount_point: entry.mount_point.clone(),
            root: PathBuf::from(&entry.root),
            fstype: entry.fstype.clone(),
            read_only: entry.is_read_only(),
        })
        .collect();
    let mut evidence = vec![Evidence::new(
        "BLOCK_DEVICE_DISCOVERED",
        base.display().to_string(),
        "block device entry enumerated from sysfs",
    )];
    match fs.read_to_string(&uevent_path) {
        Ok(_) => evidence.push(Evidence::new(
            "SYSFS_UEVENT_READ",
            uevent_path.display().to_string(),
            "parsed block-device uevent metadata",
        )),
        Err(error) => evidence.push(Evidence::new(
            "SYSFS_UEVENT_UNREADABLE",
            uevent_path.display().to_string(),
            format!("could not read uevent metadata: {error}"),
        )),
    }
    let size_sectors = read_number(fs, &base.join("size"), "SYSFS_SIZE", &mut evidence);
    let read_only = read_bool(fs, &base.join("ro"), "SYSFS_READ_ONLY", &mut evidence);
    let removable = read_bool(
        fs,
        &base.join("removable"),
        "SYSFS_REMOVABLE",
        &mut evidence,
    );
    if let Some(entry) = mount {
        evidence.push(
            Evidence::new(
                "MOUNTINFO_MATCH",
                MOUNTINFO,
                "device is mounted in the current mount namespace",
            )
            .with_value(entry.mount_point.display().to_string()),
        );
    }
    BlockDevice {
        name: uevent
            .get("DEVNAME")
            .cloned()
            .unwrap_or_else(|| name.to_string()),
        dev_path: Some(dev_path),
        major_minor,
        parent: if partition.is_some() {
            parent_name(name)
        } else {
            String::new()
        },
        class,
        disk_kind: if name.starts_with("loop") {
            DiskKind::Loop
        } else {
            DiskKind::Unknown
        },
        partition_role: if partition.is_some() {
            PartitionRole::Unknown
        } else {
            PartitionRole::WholeDisk
        },
        partition_number: uevent
            .get("PARTN")
            .and_then(|value| value.parse().ok())
            .or_else(|| partition.and_then(|value| value.trim().parse().ok())),
        size_sectors,
        read_only,
        removable,
        filesystem: mount.map(|entry| entry.fstype.clone()),
        uuid: None,
        part_uuid: None,
        label: None,
        part_label: None,
        mount_point: mount.map(|entry| entry.mount_point.clone()),
        mounts: mount_observations,
        mounted_before_session: !matching_mounts.is_empty(),
        evidence,
    }
}

fn apply_relationships(fs: &dyn FilesystemProbe, devices: &mut [BlockDevice]) {
    let indexes: HashMap<String, usize> = devices
        .iter()
        .enumerate()
        .map(|(index, device)| (device.name.clone(), index))
        .collect();
    for index in 0..devices.len() {
        let name = devices[index].name.clone();
        let base = Path::new(BLOCK_ROOT).join(&name);
        let slaves = read_relation_names(fs, &base.join("slaves"));
        let holders = read_relation_names(fs, &base.join("holders"));
        if devices[index].parent.is_empty() {
            if let Some(parent) = slaves.first() {
                devices[index].parent = parent.clone();
            }
        }
        for slave in &slaves {
            devices[index].evidence.push(
                Evidence::new(
                    "SYSFS_SLAVE",
                    base.join("slaves").display().to_string(),
                    "backing block device",
                )
                .with_value(slave),
            );
        }
        for holder in &holders {
            devices[index].evidence.push(
                Evidence::new(
                    "SYSFS_HOLDER",
                    base.join("holders").display().to_string(),
                    "dependent block device",
                )
                .with_value(holder),
            );
            if let Some(child_index) = indexes.get(holder) {
                if devices[*child_index].parent.is_empty() {
                    devices[*child_index].parent = name.clone();
                }
            }
        }
    }
}

fn supplement_with_blkid_using<F>(devices: &mut [BlockDevice], mut run: F) -> Vec<Warning>
where
    F: FnMut(&BlockDevice) -> Result<Vec<u8>, String>,
{
    let mut warnings = Vec::new();
    for device in devices {
        let output = match run(device) {
            Ok(output) => output,
            Err(message) => {
                warnings.push(Warning::new("BLKID_FAILED", message));
                continue;
            }
        };
        let body = match String::from_utf8(output) {
            Ok(body) => body,
            Err(_) => {
                warnings.push(Warning::new(
                    "BLKID_NON_UTF8",
                    format!("blkid output for /dev/{} was not UTF-8", device.name),
                ));
                continue;
            }
        };
        let info = blkid::parse_udev(&body);
        if info.present {
            apply_blkid(device, info);
            device.evidence.push(Evidence::new(
                "BLKID_SIGNATURE",
                format!("/dev/{}", device.name),
                "filesystem signature supplemented from blkid",
            ));
        }
    }
    warnings
}

fn apply_blkid(device: &mut BlockDevice, info: blkid::BlkidInfo) {
    let partition_role = role_from_blkid(&info);
    device.filesystem = info.fs_type;
    device.uuid = info.fs_uuid;
    device.label = info.fs_label;
    device.part_uuid = info.part_uuid;
    device.part_label = info.part_label;
    if let Some(number) = info.part_number {
        device.partition_number = Some(number);
    }
    match info.part_table_type.as_deref() {
        Some("gpt") => device.disk_kind = DiskKind::Gpt,
        Some("dos") | Some("msdos") => device.disk_kind = DiskKind::Mbr,
        Some(_) | None => {}
    }
    if device.class == DeviceClass::Partition {
        device.partition_role = partition_role;
    }
}

fn role_from_blkid(info: &blkid::BlkidInfo) -> PartitionRole {
    match info.gpt_role() {
        Some("esp") => PartitionRole::Esp,
        Some("bios_boot") => PartitionRole::BiosBoot,
        Some(_) => PartitionRole::Unknown,
        None => match info.part_type_raw.as_deref() {
            Some(raw) if raw.eq_ignore_ascii_case(LINUX_FILESYSTEM_GUID) => {
                PartitionRole::LinuxFilesystem
            }
            Some(raw) if raw.len() == 2 => u8::from_str_radix(raw, 16)
                .map(PartitionRole::MbrOther)
                .unwrap_or_else(|_| PartitionRole::GptOther(raw.to_string())),
            Some(raw) => PartitionRole::GptOther(raw.to_string()),
            None => PartitionRole::Unknown,
        },
    }
}

fn classify(name: &str, is_partition: bool) -> DeviceClass {
    if is_partition {
        DeviceClass::Partition
    } else if name.starts_with("dm-") {
        DeviceClass::DeviceMapper
    } else if name.starts_with("md") {
        DeviceClass::MdRaid
    } else if name.starts_with("loop") {
        DeviceClass::Loop
    } else {
        DeviceClass::Disk
    }
}

fn parent_name(name: &str) -> String {
    let prefix = name.trim_end_matches(|character: char| character.is_ascii_digit());
    if prefix.len() != name.len() {
        if let Some(without_p) = prefix.strip_suffix('p') {
            if without_p.starts_with("nvme") || without_p.starts_with("mmcblk") {
                return without_p.to_string();
            }
        }
        return prefix.to_string();
    }
    String::new()
}

fn parse_key_values(body: &str) -> HashMap<String, String> {
    body.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn read_number(
    fs: &dyn FilesystemProbe,
    path: &Path,
    code: &str,
    evidence: &mut Vec<Evidence>,
) -> Option<u64> {
    let value: u64 = fs.read_to_string(path).ok()?.trim().parse().ok()?;
    evidence.push(
        Evidence::new(
            code,
            path.display().to_string(),
            "read sysfs numeric attribute",
        )
        .with_value(value.to_string()),
    );
    Some(value)
}

fn read_bool(
    fs: &dyn FilesystemProbe,
    path: &Path,
    code: &str,
    evidence: &mut Vec<Evidence>,
) -> bool {
    let Some(value) = fs.read_to_string(path).ok() else {
        return false;
    };
    let parsed = matches!(value.trim(), "1" | "true");
    evidence.push(
        Evidence::new(
            code,
            path.display().to_string(),
            "read sysfs boolean attribute",
        )
        .with_value(value.trim()),
    );
    parsed
}

fn read_relation_names(fs: &dyn FilesystemProbe, path: &Path) -> Vec<String> {
    fs.read_dir_names(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::fs_probe::FixtureFilesystem;

    fn block(fs: FixtureFilesystem, name: &str, uevent: &str) -> FixtureFilesystem {
        fs.dir(BLOCK_ROOT)
            .dir(format!("{BLOCK_ROOT}/{name}"))
            .file(format!("{BLOCK_ROOT}/{name}/uevent"), uevent)
    }

    fn basic_fs() -> FixtureFilesystem {
        FixtureFilesystem::new()
            .dir("/")
            .dir("/sys")
            .dir("/sys/class")
            .dir("/proc")
            .dir("/proc/self")
    }

    fn device(name: &str) -> BlockDevice {
        BlockDevice {
            name: name.to_string(),
            dev_path: Some(PathBuf::from(format!("/dev/{name}"))),
            major_minor: None,
            parent: String::new(),
            class: DeviceClass::Disk,
            disk_kind: DiskKind::Unknown,
            partition_role: PartitionRole::WholeDisk,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: None,
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: vec![],
            mounted_before_session: false,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn discovers_realistic_catos_nvme_layout() {
        let fs = block(
            basic_fs(),
            "nvme0n1",
            "MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\nDEVTYPE=disk\n",
        )
        .file("/sys/class/block/nvme0n1/size", "1000000\n")
        .file("/sys/class/block/nvme0n1/ro", "0\n")
        .file("/sys/class/block/nvme0n1/removable", "0\n")
        .dir("/sys/class/block/nvme0n1p1")
        .file(
            "/sys/class/block/nvme0n1p1/uevent",
            "MAJOR=259\nMINOR=1\nDEVNAME=nvme0n1p1\nPARTN=1\n",
        )
        .file("/sys/class/block/nvme0n1p1/partition", "1\n")
        .dir("/sys/class/block/nvme0n1p2")
        .file(
            "/sys/class/block/nvme0n1p2/uevent",
            "MAJOR=259\nMINOR=2\nDEVNAME=nvme0n1p2\nPARTN=2\n",
        )
        .file("/sys/class/block/nvme0n1p2/partition", "2\n")
        .file(MOUNTINFO, "1 0 259:2 /@ / rw - btrfs /dev/nvme0n1p2 rw\n");
        let (devices, _) = discover_sysfs(&fs);
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[1].parent, "nvme0n1");
        assert_eq!(devices[2].filesystem.as_deref(), Some("btrfs"));
        assert_eq!(devices[2].mount_point, Some(PathBuf::from("/")));
    }

    #[test]
    fn missing_sysfs_attributes_remain_unknown() {
        let fs =
            block(basic_fs(), "zram0", "MAJOR=254\nMINOR=0\nDEVNAME=zram0\n").file(MOUNTINFO, "");
        let (devices, _) = discover_sysfs(&fs);
        assert_eq!(devices[0].size_sectors, None);
        assert!(!devices[0].read_only);
        assert!(!devices[0].removable);
    }

    #[test]
    fn classifies_device_mapper_and_relationships() {
        let fs = block(basic_fs(), "sda", "DEVNAME=sda\n")
            .dir("/sys/class/block/sda/holders")
            .dir("/sys/class/block/sda/holders/dm-0")
            .dir("/sys/class/block/dm-0")
            .file("/sys/class/block/dm-0/uevent", "DEVNAME=dm-0\n")
            .dir("/sys/class/block/dm-0/slaves")
            .dir("/sys/class/block/dm-0/slaves/sda")
            .file(MOUNTINFO, "");
        let (devices, _) = discover_sysfs(&fs);
        // FixtureFilesystem::read_dir_names returns names sorted; `dm-0`
        // sorts before `sda`, so we look up by name rather than by index.
        let dm = devices
            .iter()
            .find(|d| d.name == "dm-0")
            .expect("dm-0 should be discovered");
        assert_eq!(dm.class, DeviceClass::DeviceMapper);
        assert_eq!(dm.parent, "sda");
    }

    #[test]
    fn classifies_loop_devices() {
        let fs = block(basic_fs(), "loop0", "DEVNAME=loop0\n").file(MOUNTINFO, "");
        let (devices, _) = discover_sysfs(&fs);
        assert_eq!(devices[0].class, DeviceClass::Loop);
        assert_eq!(devices[0].disk_kind, DiskKind::Loop);
    }

    #[test]
    fn merges_mountinfo_only_for_matching_device() {
        let fs = block(basic_fs(), "sda1", "DEVNAME=sda1\nPARTN=1\n")
            .file("/sys/class/block/sda1/partition", "1\n")
            .dir("/sys/class/block/sdb1")
            .file("/sys/class/block/sdb1/uevent", "DEVNAME=sdb1\nPARTN=1\n")
            .file("/sys/class/block/sdb1/partition", "1\n")
            .file(MOUNTINFO, "1 0 8:1 / /mnt rw - ext4 /dev/sda1 rw\n");
        let (devices, _) = discover_sysfs(&fs);
        assert!(devices[0].mounted_before_session);
        assert!(!devices[1].mounted_before_session);
    }

    #[test]
    fn blkid_missing_is_a_warning_not_an_error() {
        let _fs = FixtureFilesystem::new().dir("/");
        let mut devices = vec![device("sda1")];
        let warnings =
            supplement_with_blkid_using(&mut devices, |_| Err("blkid missing".to_string()));
        assert_eq!(warnings[0].code, "BLKID_FAILED");
        assert_eq!(devices[0].filesystem, None);
    }

    #[test]
    fn blkid_failure_is_a_warning_not_an_error() {
        let _fs = FixtureFilesystem::new().dir("/");
        let mut devices = vec![device("dm-0")];
        let warnings = supplement_with_blkid_using(&mut devices, |_| Err("status 2".to_string()));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "BLKID_FAILED");
    }

    #[test]
    fn derives_partition_parent_names_without_regex() {
        let _fs = FixtureFilesystem::new().dir("/");
        assert_eq!(parent_name("nvme0n1p2"), "nvme0n1");
        assert_eq!(parent_name("mmcblk0p1"), "mmcblk0");
        assert_eq!(parent_name("sda1"), "sda");
    }

    #[test]
    fn applies_blkid_esp_and_linux_partition_roles() {
        let _fs = FixtureFilesystem::new().dir("/");
        let mut devices = vec![device("nvme0n1p1"), device("nvme0n1p2")];
        devices[0].class = DeviceClass::Partition;
        devices[1].class = DeviceClass::Partition;
        let warnings =
            supplement_with_blkid_using(&mut devices, |device| match device.name.as_str() {
                "nvme0n1p1" => Ok(
                    b"ID_FS_TYPE=vfat\nID_PART_ENTRY_TYPE=c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n"
                        .to_vec(),
                ),
                "nvme0n1p2" => Ok(
                    b"ID_FS_TYPE=btrfs\nID_PART_ENTRY_TYPE=0fc63daf-8483-4772-8e79-3d69d8477de4\n"
                        .to_vec(),
                ),
                _ => Err("unexpected device".to_string()),
            });
        assert!(warnings.is_empty());
        assert_eq!(devices[0].partition_role, PartitionRole::Esp);
        assert_eq!(devices[1].partition_role, PartitionRole::LinuxFilesystem);
    }

    #[test]
    fn udev_database_is_used_before_privileged_blkid() {
        let fs = FixtureFilesystem::new().file(
            "/run/udev/data/b8:1",
            "E:ID_FS_TYPE=ext4\nE:ID_FS_UUID=root-uuid\n",
        );
        let mut devices = vec![device("sda1")];
        devices[0].major_minor = Some("8:1".into());
        let warnings = supplement_from_udev_database(&fs, &mut devices);
        assert!(warnings.is_empty());
        assert_eq!(devices[0].filesystem.as_deref(), Some("ext4"));
        assert_eq!(devices[0].uuid.as_deref(), Some("root-uuid"));
    }
}
