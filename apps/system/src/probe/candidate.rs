//! Evidence-driven root and EFI System Partition candidate identification.

use std::path::Path;

use crate::model::evidence::Evidence;
use crate::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::model::inspection::Warning;
use crate::model::runtime::Detection;
use crate::model::storage::{
    Ambiguity, AmbiguityKind, BlockDevice, DemotionReason, EspCandidate, EspSignals,
    OsLayoutSignals, PartitionRole, RootCandidate, RootCandidateConfidence,
};

const ESP_MIN_BYTES: u64 = 32 * 1024 * 1024;
const ESP_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Compare a discovered device with one fstab source specification.
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

/// Identify every plausible root and ESP without selecting among ties.
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
            Some("vfat" | "fat" | "fat32" | "fat16" | "fat12" | "exfat")
        )
}

fn root_candidate(device: &BlockDevice, root_entries: &[&FstabEntry]) -> RootCandidate {
    let matching_entry = root_entries
        .iter()
        .copied()
        .find(|entry| device_matches_fstab_source(device, &entry.source));
    let (confidence, demotion_reasons) = match (
        matching_entry,
        root_entries.is_empty(),
        device.mount_point.is_some(),
    ) {
        (Some(_), _, _) => (RootCandidateConfidence::High, Vec::new()),
        (None, false, _) => (
            RootCandidateConfidence::Low,
            vec![DemotionReason::FstabPointsElsewhere],
        ),
        (None, true, true) => (RootCandidateConfidence::Medium, Vec::new()),
        (None, true, false) => (RootCandidateConfidence::Unknown, Vec::new()),
    };
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
    match confidence {
        RootCandidateConfidence::High => evidence.push(
            Evidence::new(
                "FSTAB_ROOT_MATCH",
                "fstab",
                "fstab root source matches this device",
            )
            .with_value(source.clone()),
        ),
        RootCandidateConfidence::Low => evidence.push(
            Evidence::new(
                "FSTAB_ROOT_POINTS_ELSEWHERE",
                "fstab",
                "fstab contains a root entry for a different discovered device",
            )
            .with_value(source.clone()),
        ),
        RootCandidateConfidence::Medium => evidence.push(Evidence::new(
            "ROOT_MOUNTED_WITHOUT_FSTAB_REFERENCE",
            source.clone(),
            "plausible root is mounted but fstab has no root entry",
        )),
        RootCandidateConfidence::Unknown => evidence.push(Evidence::new(
            "ROOT_UNINSPECTED",
            source.clone(),
            "plausible root was discovered but has no mount or root fstab evidence",
        )),
    }
    if let Some(value) = &subvolume {
        evidence.push(
            Evidence::new("BTRFS_SUBVOL", "fstab", "root fstab entry specifies subvol")
                .with_value(value.clone()),
        );
    }

    RootCandidate {
        source,
        filesystem: device.filesystem.clone(),
        subvolume,
        confidence,
        is_catos: Detection::unknown(vec![Evidence::new(
            "ROOT_NOT_INSPECTED",
            "candidate",
            "os-release inspection is deferred until after a read-only mount",
        )]),
        mounted_at: device.mount_point.clone(),
        signals: OsLayoutSignals::default(),
        demotion_reasons,
        evidence,
    }
}

fn esp_candidate(device: &BlockDevice, fstab: &[FstabEntry]) -> EspCandidate {
    let source = device_source(device);
    let gpt_esp_type = matches!(device.partition_role, PartitionRole::Esp);
    let fat_filesystem = matches!(
        device.filesystem.as_deref(),
        Some("vfat" | "fat" | "fat32" | "fat16" | "fat12" | "exfat")
    );
    let plausible_size = device
        .size_bytes()
        .is_some_and(|size| (ESP_MIN_BYTES..=ESP_MAX_BYTES).contains(&size));
    let mounted_at_esp_location = device
        .mount_point
        .as_ref()
        .is_some_and(|mount| is_esp_location(mount.to_string_lossy().as_ref()));
    let fstab_referenced = fstab.iter().any(|entry| {
        is_esp_location(&entry.target) && device_matches_fstab_source(device, &entry.source)
    });
    let signals = EspSignals {
        gpt_esp_type,
        fat_filesystem,
        plausible_size,
        mounted_at_esp_location,
        fstab_referenced,
        has_efi_directory: false,
    };
    let confidence = if gpt_esp_type {
        RootCandidateConfidence::High
    } else if fstab_referenced || mounted_at_esp_location {
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
            Evidence::new(
                "FSTAB_ESP_MATCH",
                "fstab",
                "fstab boot target matches this device",
            )
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

    EspCandidate {
        source,
        confidence,
        signals,
        evidence,
    }
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

fn candidate_ambiguities(roots: &[RootCandidate], esps: &[EspCandidate]) -> Vec<Ambiguity> {
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
            .map(|candidate| candidate.source.clone())
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::model::storage::{DeviceClass, DiskKind};

    fn device(name: &str, filesystem: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: name.to_owned(),
            dev_path: Some(PathBuf::from(format!("/dev/{name}"))),
            major_minor: None,
            parent: "disk".to_owned(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(1),
            size_sectors: Some(1_000_000),
            read_only: false,
            removable: false,
            filesystem: filesystem.map(str::to_owned),
            uuid: Some(format!("{name}-uuid")),
            part_uuid: Some(format!("{name}-partuuid")),
            label: Some(format!("{name}-label")),
            part_label: Some(format!("{name}-partlabel")),
            mount_point: None,
            mounted_before_session: false,
            evidence: vec![],
        }
    }

    fn entry(source: FstabSource, target: &str, fstype: &str, options: Vec<&str>) -> FstabEntry {
        FstabEntry {
            source,
            target: target.to_owned(),
            fstype: fstype.to_owned(),
            options: options.into_iter().map(str::to_owned).collect(),
            dump: 0,
            pass: 0,
            kind: match target {
                "/" | "" => FstabEntryKind::Root,
                "/boot" | "/boot/efi" | "/efi" => FstabEntryKind::Boot,
                _ => FstabEntryKind::OtherLocal,
            },
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }
    }

    #[test]
    fn identifies_single_ext4_root_from_fstab() {
        let root = device("sda2", Some("ext4"));
        let fstab = vec![entry(
            FstabSource::Uuid("sda2-uuid".into()),
            "/",
            "ext4",
            vec!["defaults"],
        )];

        let (roots, _, ambiguities, _) = identify_candidates(&[root], &fstab);

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].confidence, RootCandidateConfidence::High);
        assert!(!roots[0].evidence.is_empty());
        assert!(ambiguities.is_empty());
    }

    #[test]
    fn surfaces_btrfs_root_subvolume_from_fstab() {
        let root = device("nvme0n1p2", Some("btrfs"));
        let fstab = vec![entry(
            FstabSource::Uuid("nvme0n1p2-uuid".into()),
            "/",
            "btrfs",
            vec!["subvol=/@"],
        )];

        let (roots, _, _, _) = identify_candidates(&[root], &fstab);

        assert_eq!(roots[0].subvolume.as_deref(), Some("/@"));
        assert_eq!(roots[0].confidence, RootCandidateConfidence::High);
    }

    #[test]
    fn reports_root_ambiguity_for_equal_confidence() {
        let first = device("sda2", Some("ext4"));
        let second = device("sdb2", Some("xfs"));

        let (roots, _, ambiguities, _) = identify_candidates(&[first, second], &[]);

        assert_eq!(roots.len(), 2);
        assert!(ambiguities.iter().any(|ambiguity| {
            ambiguity.kind == AmbiguityKind::Root
                && ambiguity.candidates == vec!["/dev/sda2", "/dev/sdb2"]
        }));
    }

    #[test]
    fn identifies_esp_from_partition_role() {
        let mut esp = device("sda1", Some("vfat"));
        esp.partition_role = PartitionRole::Esp;

        let (_, esps, ambiguities, _) = identify_candidates(&[esp], &[]);

        assert_eq!(esps.len(), 1);
        assert_eq!(esps[0].confidence, RootCandidateConfidence::High);
        assert!(esps[0].signals.gpt_esp_type);
        assert!(ambiguities.is_empty());
    }

    #[test]
    fn identifies_esp_from_fstab_when_partition_role_is_unknown() {
        let mut esp = device("sda1", Some("vfat"));
        esp.partition_role = PartitionRole::Unknown;
        let fstab = vec![entry(
            FstabSource::Uuid("sda1-uuid".into()),
            "/boot/efi",
            "vfat",
            vec!["defaults"],
        )];

        let (_, esps, _, _) = identify_candidates(&[esp], &fstab);

        assert_eq!(esps[0].confidence, RootCandidateConfidence::Medium);
        assert!(esps[0].signals.fstab_referenced);
    }

    #[test]
    fn refuses_swap_and_vfat_as_root_candidates() {
        let swap = device("sda2", Some("swap"));
        let fat = device("sda1", Some("vfat"));

        let (roots, esps, _, _) = identify_candidates(&[swap, fat], &[]);

        assert!(roots.is_empty());
        assert_eq!(esps.len(), 1);
    }

    #[test]
    fn refuses_luks_device_as_root_candidate() {
        let luks = device("sda2", Some("crypto_LUKS"));

        let (roots, _, _, _) = identify_candidates(&[luks], &[]);

        assert!(roots.is_empty());
    }

    #[test]
    fn handles_empty_device_list() {
        let (roots, esps, ambiguities, warnings) = identify_candidates(&[], &[]);

        assert!(roots.is_empty());
        assert!(esps.is_empty());
        assert!(ambiguities.is_empty());
        assert!(warnings.is_empty());
    }
}
