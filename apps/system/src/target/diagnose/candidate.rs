//! Root/ESP candidate identification + target-root inspection (migrated
//! from `shared::probe::devices::{candidate,target}`).

use std::path::{Path, PathBuf};

use crate::shared::error::FsError;
use crate::shared::model::evidence::Evidence;
use crate::shared::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::target::diagnose::filesystem::{FilesystemProbe, MetaData, RealFilesystem};
use crate::target::diagnose::system_root::SystemRoot;
use crate::target::model::{
    Ambiguity, AmbiguityKind, BlockDevice, Capability, CapabilityKind, CapabilityStatus,
    DemotionReason, Detection, EspCandidate, EspSignals, OsLayoutSignals, OsRelease,
    PartitionRole, Presence, Presence2, RootCandidate, RootCandidateConfidence, TargetInspection,
    ToolPath, Warning,
};

const ESP_MIN_BYTES: u64 = 32 * 1024 * 1024;
const ESP_MAX_BYTES: u64 = 1024 * 1024 * 1024;

pub fn device_matches_fstab_source(dev: &BlockDevice, src: &FstabSource) -> bool {
    match src {
        FstabSource::Uuid(value) => dev
            .uuid
            .as_deref()
            .is_some_and(|uuid| uuid.eq_ignore_ascii_case(value)),
        FstabSource::PartUuid(value) => dev
            .part_uuid
            .as_deref()
            .is_some_and(|part_uuid| part_uuid.eq_ignore_ascii_case(value)),
        FstabSource::Label(value) => dev.label.as_deref() == Some(value),
        FstabSource::PartLabel(value) => dev.part_label.as_deref() == Some(value),
        FstabSource::Path(value) => dev
            .dev_path
            .as_ref()
            .is_some_and(|path| path == Path::new(value)),
        FstabSource::Pseudo(_) => false,
    }
}

pub fn identify_candidates(
    devices: &[BlockDevice],
    fstab: &[FstabEntry],
) -> (
    Vec<RootCandidate>,
    Vec<EspCandidate>,
    Vec<Ambiguity>,
    Vec<Warning>,
) {
    let root_entries: Vec<&FstabEntry> = fstab
        .iter()
        .filter(|entry| matches!(entry.kind, FstabEntryKind::Root))
        .collect();
    let root_candidates = devices
        .iter()
        .filter(|device| is_root_filesystem(device.filesystem.as_deref()))
        .map(|device| root_candidate(device, &root_entries))
        .collect::<Vec<_>>();
    let esp_candidates = devices
        .iter()
        .filter(|device| is_esp_device(device))
        .map(|device| esp_candidate(device, fstab))
        .collect::<Vec<_>>();
    let ambiguities = candidate_ambiguities(&root_candidates, &esp_candidates);
    (root_candidates, esp_candidates, ambiguities, Vec::new())
}

fn is_root_filesystem(filesystem: Option<&str>) -> bool {
    matches!(
        filesystem,
        Some("ext2" | "ext3" | "ext4" | "btrfs" | "xfs" | "f2fs")
    )
}

fn is_esp_device(device: &BlockDevice) -> bool {
    matches!(device.partition_role, PartitionRole::Esp)
        || matches!(
            device.filesystem.as_deref(),
            Some("vfat" | "fat" | "fat32" | "fat16" | "fat12")
        )
}

fn root_candidate(device: &BlockDevice, root_entries: &[&FstabEntry]) -> RootCandidate {
    let matching_entry = root_entries
        .iter()
        .copied()
        .find(|entry| device_matches_fstab_source(device, &entry.source));
    let inspected = inspect_mounted_target(device);
    let (confidence, mut demotion_reasons) = classify_root_confidence(
        inspected.as_ref(),
        matching_entry.is_some(),
        !root_entries.is_empty(),
    );
    let subvolume = matching_entry
        .filter(|_| matches!(device.filesystem.as_deref(), Some("btrfs")))
        .and_then(|entry| {
            entry
                .options
                .iter()
                .find_map(|option| option.strip_prefix("subvol=").map(str::to_owned))
        });
    let source = device_source(device);
    let mut evidence = device.evidence.clone();
    evidence.push(
        Evidence::new(
            "ROOT_FILESYSTEM_PLAUSIBLE",
            source.clone(),
            "filesystem is in the read-only root allow-list",
        )
        .with_value(device.filesystem.clone().unwrap_or_default()),
    );
    if matching_entry.is_some() {
        evidence.push(
            Evidence::new("FSTAB_ROOT_MATCH", "fstab", "fstab root source matches this device")
                .with_value(source.clone()),
        );
    } else if !root_entries.is_empty() {
        evidence.push(
            Evidence::new(
                "FSTAB_ROOT_POINTS_ELSEWHERE",
                "fstab",
                "fstab contains a root entry for a different discovered device",
            )
            .with_value(source.clone()),
        );
        if !demotion_reasons.contains(&DemotionReason::FstabPointsElsewhere) {
            demotion_reasons.push(DemotionReason::FstabPointsElsewhere);
        }
    }
    if inspected.is_none() {
        evidence.push(Evidence::new(
            "ROOT_UNINSPECTED",
            source.clone(),
            "candidate content has not been inspected through a read-only mount",
        ));
    }
    if let Some(value) = &subvolume {
        evidence.push(
            Evidence::new("BTRFS_SUBVOL", "fstab", "root fstab entry specifies subvol")
                .with_value(value.clone()),
        );
    }

    let (is_catos, signals) = inspected
        .map(|inspection| {
            let signals = OsLayoutSignals {
                has_os_release: if inspection.os_release.is_some() {
                    Presence2::Present
                } else {
                    Presence2::Absent
                },
                has_fstab: inspection.has_fstab.into(),
                has_usr: inspection.has_usr.into(),
                has_pacman_db: inspection.has_pacman_db.into(),
                has_boot: inspection.has_boot.into(),
            };
            (inspection.is_catos_target, signals)
        })
        .unwrap_or_else(|| {
            (
                Detection::unknown(vec![Evidence::new(
                    "ROOT_NOT_INSPECTED",
                    "candidate",
                    "os-release inspection requires an existing or temporary read-only mount",
                )]),
                OsLayoutSignals::default(),
            )
        });

    RootCandidate {
        source,
        filesystem: device.filesystem.clone(),
        subvolume,
        confidence,
        is_catos,
        mounted_at: device.mount_point.clone(),
        signals,
        demotion_reasons,
        evidence,
    }
}

fn esp_candidate(device: &BlockDevice, fstab: &[FstabEntry]) -> EspCandidate {
    let source = device_source(device);
    let gpt_esp_type = matches!(device.partition_role, PartitionRole::Esp);
    let fat_filesystem = matches!(
        device.filesystem.as_deref(),
        Some("vfat" | "fat" | "fat32" | "fat16" | "fat12")
    );
    let plausible_size = device
        .size_bytes()
        .is_some_and(|size| (ESP_MIN_BYTES..=ESP_MAX_BYTES).contains(&size));
    let mounted_at_esp_location = device
        .mount_point
        .as_ref()
        .is_some_and(|mount| is_esp_location(mount.to_string_lossy().as_ref()));
    let fstab_referenced = fstab
        .iter()
        .any(|entry| is_esp_location(&entry.target) && device_matches_fstab_source(device, &entry.source));
    let has_efi_directory = mounted_directory_exists(device.mount_point.as_deref(), "EFI");
    let signals = EspSignals {
        gpt_esp_type,
        fat_filesystem,
        plausible_size,
        mounted_at_esp_location,
        fstab_referenced,
        has_efi_directory,
    };
    let confidence = if fat_filesystem && (gpt_esp_type || has_efi_directory) {
        RootCandidateConfidence::High
    } else if gpt_esp_type || fstab_referenced || mounted_at_esp_location {
        RootCandidateConfidence::Medium
    } else {
        RootCandidateConfidence::Low
    };
    let mut evidence = device.evidence.clone();
    evidence.push(Evidence::new(
        "ESP_CANDIDATE",
        source.clone(),
        "device has ESP type or FAT filesystem",
    ));
    if gpt_esp_type {
        evidence.push(Evidence::new(
            "ESP_TYPE_GUID",
            source.clone(),
            "partition role is EFI System Partition",
        ));
    }
    if fstab_referenced {
        evidence.push(
            Evidence::new("FSTAB_ESP_MATCH", "fstab", "fstab boot target matches this device")
                .with_value(source.clone()),
        );
    }
    if plausible_size {
        evidence.push(Evidence::new(
            "ESP_PLAUSIBLE_SIZE",
            source.clone(),
            "partition size is within ESP range",
        ));
    }
    if mounted_at_esp_location {
        evidence.push(Evidence::new(
            "ESP_MOUNTED",
            source.clone(),
            "device is mounted at an ESP location",
        ));
    }
    if has_efi_directory {
        evidence.push(Evidence::new(
            "ESP_EFI_DIRECTORY",
            source.clone(),
            "mounted candidate contains an EFI directory",
        ));
    }
    EspCandidate {
        source,
        confidence,
        signals,
        evidence,
    }
}

fn inspect_mounted_target(device: &BlockDevice) -> Option<TargetInspection> {
    let mount_point = device.mount_point.as_ref()?;
    let root = SystemRoot::from_user_input(mount_point.to_str()?).ok()?;
    let mut warnings = Vec::new();
    Some(inspect_target(&RealFilesystem, &root, &mut warnings))
}

fn classify_root_confidence(
    inspection: Option<&TargetInspection>,
    fstab_matches: bool,
    fstab_has_other_root: bool,
) -> (RootCandidateConfidence, Vec<DemotionReason>) {
    use crate::target::model::DetectionStatus;
    let Some(inspection) = inspection else {
        return if fstab_matches {
            (RootCandidateConfidence::Medium, vec![DemotionReason::MissingOsLayout])
        } else if fstab_has_other_root {
            (RootCandidateConfidence::Low, vec![DemotionReason::FstabPointsElsewhere])
        } else {
            (RootCandidateConfidence::Unknown, Vec::new())
        };
    };

    let has_os_release = inspection.os_release.is_some();
    let has_usr = inspection.has_usr == Presence::Present;
    let has_package_db = inspection.has_pacman_db == Presence::Present;
    let has_fstab = inspection.has_fstab == Presence::Present;
    let strong_layout = has_usr && (has_package_db || has_fstab);

    if inspection.is_catos_target.status == DetectionStatus::Detected
        && has_os_release
        && strong_layout
    {
        return (RootCandidateConfidence::High, Vec::new());
    }

    let mut reasons = Vec::new();
    if !has_os_release {
        reasons.push(DemotionReason::NoOsRelease);
    } else if inspection.is_catos_target.status == DetectionStatus::NotDetected {
        reasons.push(DemotionReason::NotCatOs);
    }
    if !strong_layout {
        reasons.push(DemotionReason::MissingOsLayout);
    }

    if has_os_release || strong_layout {
        (RootCandidateConfidence::Medium, reasons)
    } else if has_usr || has_package_db || has_fstab || fstab_matches {
        (RootCandidateConfidence::Low, reasons)
    } else {
        (RootCandidateConfidence::Unknown, reasons)
    }
}

fn mounted_directory_exists(mount_point: Option<&Path>, relative: &str) -> bool {
    let Some(mount_point) = mount_point else {
        return false;
    };
    let Some(path) = mount_point.to_str() else {
        return false;
    };
    let Ok(root) = SystemRoot::from_user_input(path) else {
        return false;
    };
    RealFilesystem
        .rooted_metadata(root.canonical_path(), Path::new(relative))
        .is_ok_and(|metadata| metadata.is_dir)
}

fn device_source(device: &BlockDevice) -> String {
    device
        .dev_path
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("/dev/{}", device.name))
}

fn is_esp_location(target: &str) -> bool {
    matches!(target, "/boot/efi" | "/efi" | "/boot")
}

pub fn candidate_ambiguities(roots: &[RootCandidate], esps: &[EspCandidate]) -> Vec<Ambiguity> {
    let mut ambiguities = Vec::new();
    for confidence in [
        RootCandidateConfidence::High,
        RootCandidateConfidence::Medium,
        RootCandidateConfidence::Low,
        RootCandidateConfidence::Unknown,
    ] {
        let sources = roots
            .iter()
            .filter(|candidate| candidate.confidence == confidence)
            .map(root_candidate_identity)
            .collect::<Vec<_>>();
        if sources.len() > 1 {
            ambiguities.push(ambiguity(AmbiguityKind::Root, confidence, sources));
        }
        let sources = esps
            .iter()
            .filter(|candidate| candidate.confidence == confidence)
            .map(|candidate| candidate.source.clone())
            .collect::<Vec<_>>();
        if sources.len() > 1 {
            ambiguities.push(ambiguity(AmbiguityKind::Esp, confidence, sources));
        }
    }
    ambiguities
}

fn root_candidate_identity(candidate: &RootCandidate) -> String {
    match candidate.subvolume.as_deref() {
        Some(subvolume) => format!("{}#subvol={subvolume}", candidate.source),
        None => candidate.source.clone(),
    }
}

fn ambiguity(
    kind: AmbiguityKind,
    confidence: RootCandidateConfidence,
    candidates: Vec<String>,
) -> Ambiguity {
    Ambiguity {
        kind,
        candidates,
        evidence: vec![Evidence::new(
            "CANDIDATE_CONFIDENCE_TIE",
            "candidate",
            "multiple candidates share a confidence level",
        )
        .with_value(confidence_name(confidence))],
    }
}

const fn confidence_name(confidence: RootCandidateConfidence) -> &'static str {
    match confidence {
        RootCandidateConfidence::High => "high",
        RootCandidateConfidence::Medium => "medium",
        RootCandidateConfidence::Low => "low",
        RootCandidateConfidence::Unknown => "unknown",
    }
}

pub fn inspect_target(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    warnings: &mut Vec<String>,
) -> TargetInspection {
    let os_release = read_os_release(fs, root, warnings);

    let has_fstab = presence_file(fs, root, "etc/fstab", warnings);
    let has_crypttab = presence_file(fs, root, "etc/crypttab", warnings);
    let has_pacman_db = presence_dir(fs, root, "var/lib/pacman/local", warnings);
    let has_usr = presence_dir(fs, root, "usr", warnings);
    let has_boot = presence_dir(fs, root, "boot", warnings);
    let has_efi = presence_dir(fs, root, "efi", warnings);
    let has_boot_efi = presence_dir(fs, root, "boot/efi", warnings);

    let is_catos_target = classify_catos_target(&os_release);
    let tool_paths = probe_target_tools(fs, root);

    TargetInspection {
        root: PathBuf::from(root.as_str()),
        os_release,
        has_fstab,
        has_crypttab,
        has_pacman_db,
        has_usr,
        has_boot,
        has_efi,
        has_boot_efi,
        is_catos_target,
        tool_paths,
    }
}

fn logical_path(root: &SystemRoot, rel: &str) -> Result<PathBuf, FsError> {
    root.try_join(rel)
        .map_err(|e| FsError::OutsideRoot(e.to_string()))
}

pub fn target_metadata(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    rel: &str,
) -> Result<(PathBuf, MetaData), FsError> {
    let logical = logical_path(root, rel)?;
    let metadata = fs.rooted_metadata(root.canonical_path(), Path::new(rel))?;
    Ok((logical, metadata))
}

pub fn target_read_to_string(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    rel: &str,
) -> Result<(PathBuf, String), FsError> {
    let logical = logical_path(root, rel)?;
    let content = fs.rooted_read_to_string(root.canonical_path(), Path::new(rel))?;
    Ok((logical, content))
}

fn presence_file(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    rel: &str,
    warnings: &mut Vec<String>,
) -> Presence {
    match target_metadata(fs, root, rel) {
        Ok((_, metadata)) if metadata.is_file => Presence::Present,
        Ok((path, _)) => {
            warnings.push(format!("{} exists but is not a regular file", path.display()));
            Presence::Absent
        }
        Err(FsError::NotFound) => Presence::Absent,
        Err(error) => {
            warnings.push(format!("cannot inspect {}: {error}", root.join(rel).display()));
            Presence::Unknown
        }
    }
}

fn presence_dir(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    rel: &str,
    warnings: &mut Vec<String>,
) -> Presence {
    match target_metadata(fs, root, rel) {
        Ok((_, metadata)) if metadata.is_dir => Presence::Present,
        Ok((path, _)) => {
            warnings.push(format!("{} exists but is not a directory", path.display()));
            Presence::Absent
        }
        Err(FsError::NotFound) => Presence::Absent,
        Err(error) => {
            warnings.push(format!("cannot inspect {}: {error}", root.join(rel).display()));
            Presence::Unknown
        }
    }
}

fn read_os_release(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    warnings: &mut Vec<String>,
) -> Option<OsRelease> {
    let content = match target_read_to_string(fs, root, "etc/os-release") {
        Ok((_, content)) => content,
        Err(FsError::NotFound) => match target_read_to_string(fs, root, "usr/lib/os-release") {
            Ok((_, content)) => content,
            Err(FsError::NotFound) => return None,
            Err(error) => {
                warnings.push(format!(
                    "cannot read {}: {error}",
                    root.join("usr/lib/os-release").display()
                ));
                return None;
            }
        },
        Err(error) => {
            warnings.push(format!(
                "cannot read {}: {error}",
                root.join("etc/os-release").display()
            ));
            return None;
        }
    };

    Some(OsRelease::parse(&content))
}

fn classify_catos_target(os_release: &Option<OsRelease>) -> Detection {
    match os_release {
        Some(os) if os.looks_like_catos() => Detection::detected(vec![Evidence::new(
            "OS_RELEASE_IDENTIFIES_CATOS",
            "etc/os-release",
            "target os-release identifies as CatOS (id / id_like / name)",
        )
        .with_value(
            os.id
                .clone()
                .or_else(|| os.id_like.clone())
                .unwrap_or_default(),
        )]),
        Some(os) => {
            let mut evidence = vec![Evidence::new(
                "OS_RELEASE_NOT_CATOS",
                "etc/os-release",
                "target os-release does not identify as CatOS",
            )];
            if let Some(id) = &os.id {
                evidence.push(
                    Evidence::new(
                        "OS_RELEASE_ID",
                        "etc/os-release",
                        "target identifies as a different distribution",
                    )
                    .with_value(id.clone()),
                );
            }
            Detection::not_detected(evidence)
        }
        None => Detection::unknown(vec![Evidence::new(
            "OS_RELEASE_MISSING_OR_UNREADABLE",
            "etc/os-release, usr/lib/os-release",
            "no confined os-release could be read; cannot classify target",
        )]),
    }
}

pub fn probe_target_tool(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    name: &str,
    rel: &str,
) -> ToolPath {
    let path = root.join(rel);
    match target_metadata(fs, root, rel) {
        Ok((_, metadata)) if metadata.is_file && metadata.is_executable() => ToolPath {
            name: name.to_string(),
            path: path.clone(),
            status: CapabilityStatus::Available,
            evidence: vec![Evidence::new(
                "TARGET_TOOL_EXECUTABLE",
                path.display().to_string(),
                format!("{name} exists in target root and is executable"),
            )],
        },
        Ok((_, metadata)) => ToolPath {
            name: name.to_string(),
            path: path.clone(),
            status: CapabilityStatus::Unavailable,
            evidence: vec![Evidence::new(
                "TARGET_TOOL_NOT_EXECUTABLE",
                path.display().to_string(),
                format!("{name} exists but is not an executable regular file"),
            )
            .with_value(format!("mode={:#o}", metadata.mode))],
        },
        Err(FsError::NotFound) => ToolPath {
            name: name.to_string(),
            path: path.clone(),
            status: CapabilityStatus::Unavailable,
            evidence: vec![Evidence::new(
                "TARGET_TOOL_MISSING",
                path.display().to_string(),
                format!("{name} not found in target root"),
            )],
        },
        Err(FsError::PermissionDenied) => ToolPath {
            name: name.to_string(),
            path: path.clone(),
            status: CapabilityStatus::Unknown,
            evidence: vec![Evidence::new(
                "TARGET_TOOL_PERMISSION_DENIED",
                path.display().to_string(),
                format!("permission denied checking {name} in target root"),
            )],
        },
        Err(error) => ToolPath {
            name: name.to_string(),
            path: path.clone(),
            status: CapabilityStatus::Unknown,
            evidence: vec![Evidence::new(
                "TARGET_TOOL_CHECK_FAILED",
                path.display().to_string(),
                format!("cannot safely inspect {name}: {error}"),
            )],
        },
    }
}

fn probe_target_tools(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Vec<ToolPath> {
    [("pacman", "usr/bin/pacman"), ("mkinitcpio", "usr/bin/mkinitcpio")]
        .iter()
        .map(|(name, rel)| probe_target_tool(fs, root, name, rel))
        .collect()
}

pub fn host_tool_exists(fs: &dyn FilesystemProbe, name: &str) -> Option<PathBuf> {
    let dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"];
    for directory in dirs {
        let path = Path::new(directory).join(name);
        if let Ok(metadata) = fs.metadata(&path) {
            if metadata.is_file && metadata.is_executable() {
                return Some(path);
            }
        }
    }
    None
}

pub fn host_efivars_path() -> &'static Path {
    Path::new("/sys/firmware/efi/efivars")
}

// Silence unused-symbol warnings for symbols kept for parity with the
// legacy module surface.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = Capability::available(CapabilityKind::ReadTargetRoot, Vec::new());
    let _ = Warning::new("x", "y");
    let _ = RealFilesystem;
}
