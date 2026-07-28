//! Shared, read-only installed-system discovery.
//!
//! This module owns facts and never asks an operator a question.  Every
//! temporary mount is read-only and its cleanup result is returned as
//! evidence; terminal interaction belongs to `catos-app`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use catos_process::run_trusted_tool;

use crate::diagnose::block::discover_devices;
use crate::diagnose::candidate::inspect_target;
use crate::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use crate::diagnose::system_root::SystemRoot;
use crate::evidence::Evidence;
use crate::model::{BlockDevice, OsRelease, RootCandidateConfidence};

/// A concrete CatOS root discovered from the candidate's own files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub root_device: PathBuf,
    pub root_fstype: String,
    pub root_uuid: Option<String>,
    pub root_subvolume: Option<String>,
    pub root_subvolume_id: Option<u64>,
    pub filesystem_id: Option<String>,
    pub label: Option<String>,
    pub os_release: OsRelease,
    pub fstab_identity: Option<String>,
    pub currently_mounted: bool,
    pub running_environment_member: bool,
    pub confidence: RootCandidateConfidence,
    pub evidence: Vec<Evidence>,
}

/// A selected candidate held either by borrowing the verified running `/`
/// or by a real readonly/no-replay mount. The owner must call
/// [`TargetSession::cleanup`] and preserve every returned cleanup result.
pub struct TargetSession {
    candidate: TargetCandidate,
    root: PathBuf,
    probe: Option<ReadonlyProbe>,
}

/// A non-root filesystem attached to a selected target (for example its ESP)
/// held on the same explicit readonly cleanup contract as [`TargetSession`].
pub struct ReadonlySession {
    probe: ReadonlyProbe,
}

impl ReadonlySession {
    pub fn open(device: &Path, fstype: &str) -> Result<Self, String> {
        Ok(Self { probe: ReadonlyProbe::mount(device, fstype, None)? })
    }

    pub fn open_with_options(device: &Path, fstype: &str, options: &str) -> Result<Self, String> {
        Ok(Self { probe: ReadonlyProbe::mount_with_options(device, fstype, options)? })
    }

    pub fn root(&self) -> &Path { self.probe.path() }
    pub fn cleanup(mut self) -> ProbeCleanup { self.probe.cleanup() }
}

impl TargetSession {
    pub fn open(candidate: TargetCandidate) -> Result<Self, String> {
        if candidate.running_environment_member {
            verify_running_root_candidate(&candidate)?;
            return Ok(Self { candidate, root: PathBuf::from("/"), probe: None });
        }
        let probe = ReadonlyProbe::mount(
            &candidate.root_device,
            &candidate.root_fstype,
            candidate.root_subvolume.as_deref().map(|value| value.trim_start_matches('/')),
        )?;
        let root = probe.path().to_path_buf();
        Ok(Self { candidate, root, probe: Some(probe) })
    }

    pub fn root(&self) -> &Path { &self.root }
    pub fn candidate(&self) -> &TargetCandidate { &self.candidate }
    pub fn cleanup(mut self) -> Vec<ProbeCleanup> {
        self.probe.take().map(|mut probe| vec![probe.cleanup()]).unwrap_or_default()
    }
}

fn verify_running_root_candidate(candidate: &TargetCandidate) -> Result<(), String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("cannot read current mount identity: {error}"))?;
    verify_running_root_candidate_with(candidate, &mountinfo, same_block_device)
}

fn verify_running_root_candidate_with<F>(candidate: &TargetCandidate, mountinfo: &str, same_device: F) -> Result<(), String>
where
    F: Fn(&Path, &Path) -> bool,
{
    if !candidate.currently_mounted || !candidate.running_environment_member {
        return Err("candidate is not marked as the mounted running root".into());
    }
    let root = crate::mountinfo::parse_all(mountinfo)
        .into_iter()
        .find(|mount| mount.mount_point == Path::new("/"))
        .ok_or_else(|| "current root mount identity is unavailable".to_string())?;
    if !same_device(&candidate.root_device, Path::new(&root.source)) {
        return Err(format!(
            "running-root device identity changed: expected {}, observed {}",
            candidate.root_device.display(), root.source
        ));
    }
    if root.fstype != candidate.root_fstype {
        return Err(format!(
            "running-root filesystem changed: expected {}, observed {}",
            candidate.root_fstype, root.fstype
        ));
    }
    let observed_subvolume = if candidate.root_fstype == "btrfs" {
        normalise_subvolume_path(Path::new(&root.root))
    } else {
        None
    };
    if observed_subvolume != candidate.root_subvolume {
        return Err(format!(
            "running-root subvolume changed: expected {:?}, observed {:?}",
            candidate.root_subvolume, observed_subvolume
        ));
    }
    Ok(())
}

fn same_block_device(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match (std::fs::metadata(left), std::fs::metadata(right)) {
        (Ok(left), Ok(right)) => left.file_type().is_block_device()
            && right.file_type().is_block_device()
            && left.rdev() == right.rdev(),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRejection {
    pub source: String,
    pub reason: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryOptions {
    /// Include Btrfs roots stored below `.snapshots/<id>/snapshot` (or the
    /// equivalent `@snapshots/<id>/snapshot` layout). Normal discovery hides
    /// these historical roots so they cannot create false target ambiguity.
    pub include_dot_snapshots: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// The exact block inventory used to derive `candidates`. Consumers must
    /// reuse it instead of racing a second inventory pass against selection.
    pub inventory: Vec<BlockDevice>,
    pub candidates: Vec<TargetCandidate>,
    pub excluded: Vec<DiscoveryRejection>,
    pub rejected: Vec<DiscoveryRejection>,
    pub cleanup: Vec<ProbeCleanup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCleanup {
    pub mountpoint: PathBuf,
    pub unmounted: bool,
    pub removed: bool,
    pub error: Option<String>,
}

impl ProbeCleanup {
    pub fn is_clean(&self) -> bool {
        self.unmounted && self.removed && self.error.is_none()
    }
}

/// Discover CatOS targets as facts. The current root is inspected directly
/// when mounted from a supported block filesystem; offline roots use temporary
/// readonly/no-replay mounts.
pub fn discover_targets() -> DiscoveryReport {
    discover_targets_with_options(DiscoveryOptions::default())
}

/// Inspect only the current process root. This path never creates a temporary
/// mount and is used by Doctor before considering unrelated offline systems.
pub fn discover_running_root() -> DiscoveryReport {
    let fs = RealFilesystem;
    let (devices, warnings) = discover_devices(&fs);
    let mut report = report_from_inventory(devices, warnings);
    for device in report.inventory.clone() {
        inspect_running_device(&device, &mut report);
    }
    report.candidates.sort_by_key(candidate_key);
    report
}

pub fn discover_targets_with_options(options: DiscoveryOptions) -> DiscoveryReport {
    let fs = RealFilesystem;
    let (devices, warnings) = discover_devices(&fs);
    let mut report = report_from_inventory(devices, warnings);
    for device in report.inventory.clone() {
        inspect_device(&device, options, &mut report);
    }
    report.candidates.sort_by_key(candidate_key);
    report
}

fn report_from_inventory(devices: Vec<BlockDevice>, warnings: Vec<crate::model::Warning>) -> DiscoveryReport {
    let mut report = DiscoveryReport { inventory: devices, ..DiscoveryReport::default() };
    for warning in warnings {
        report.rejected.push(DiscoveryRejection {
            source: "block-inventory".into(), reason: warning.message, evidence: Vec::new(),
        });
    }
    report
}

fn inspect_running_device(device: &BlockDevice, report: &mut DiscoveryReport) -> bool {
    let Some(fstype) = device.filesystem.as_deref() else { return false };
    if !matches!(fstype, "btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs") { return false }
    let Some(path) = device.dev_path.as_ref() else { return false };
    let Some(mount) = device.mounts.iter().find(|mount| mount.mount_point == Path::new("/")) else { return false };
    let subvolume = (fstype == "btrfs").then(|| normalise_subvolume_path(&mount.root)).flatten();
    match inspect_at(device, Path::new("/"), subvolume, None, true, true, "current running root") {
        Some(candidate) => report.candidates.push(candidate),
        None => report.rejected.push(rejected(path, "current running root does not identify as CatOS".into())),
    }
    true
}

fn inspect_device(device: &BlockDevice, options: DiscoveryOptions, report: &mut DiscoveryReport) {
    let Some(fstype) = device.filesystem.as_deref() else { return };
    if !matches!(fstype, "btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs") { return }
    let Some(path) = device.dev_path.as_ref() else { return };
    let is_running_device = inspect_running_device(device, report);
    if is_running_device && fstype != "btrfs" { return }

    if fstype == "btrfs" {
        inspect_btrfs_device(device, options, report);
        return;
    }
    let mut probe = match ReadonlyProbe::mount(path, fstype, None) {
        Ok(probe) => probe,
        Err(reason) => { report.rejected.push(rejected(path, reason)); return; }
    };
    let (currently_mounted, running_environment_member) = candidate_mount_membership(device, None);
    let result = inspect_at(
        device, probe.path(), None, None, currently_mounted,
        running_environment_member, "readonly no-replay temporary mount",
    );
    let cleanup = probe.cleanup();
    let clean = cleanup.is_clean();
    report.cleanup.push(cleanup);
    if !clean { report.rejected.push(rejected(path, "readonly probe cleanup failed".into())); return; }
    match result {
        Some(candidate) => report.candidates.push(candidate),
        None => report.rejected.push(rejected(path, "candidate os-release/layout is not CatOS".into())),
    }
}

fn inspect_btrfs_device(device: &BlockDevice, options: DiscoveryOptions, report: &mut DiscoveryReport) {
    let Some(path) = device.dev_path.as_ref() else { return };
    let mut probe = match ReadonlyProbe::mount_with_options(path, "btrfs", "ro,norecovery,subvolid=5") {
        Ok(probe) => probe,
        Err(reason) => { report.rejected.push(rejected(path, reason)); return; }
    };
    let subvolumes = list_btrfs_subvolumes(probe.path());
    let cleanup = probe.cleanup();
    let clean = cleanup.is_clean();
    report.cleanup.push(cleanup);
    if !clean { report.rejected.push(rejected(path, "readonly probe cleanup failed".into())); return; }
    let subvolumes = match subvolumes {
        Ok(values) => values,
        Err(reason) => { report.rejected.push(rejected(path, reason)); return; }
    };
    for (subvolume_id, subvolume) in subvolumes {
        if is_dot_snapshot_root(&subvolume) && !options.include_dot_snapshots {
            report.excluded.push(DiscoveryRejection {
                source: path.display().to_string(),
                reason: format!("Btrfs snapshot root /{subvolume} is hidden by default"),
                evidence: vec![Evidence::new(
                    "BTRFS_SNAPSHOT_ROOT_EXCLUDED",
                    path.display().to_string(),
                    "historical snapshot roots are excluded from normal target selection",
                ).with_value(format!("/{subvolume}"))],
            });
            continue;
        }
        let subvolume_path = format!("/{subvolume}");
        let (currently_mounted, running_environment_member) =
            candidate_mount_membership(device, Some(&subvolume_path));
        if running_environment_member { continue }
        let mut subprobe = match ReadonlyProbe::mount(path, "btrfs", Some(&subvolume)) {
            Ok(probe) => probe,
            Err(reason) => {
                report.rejected.push(rejected(path, format!("cannot probe subvolume /{subvolume}: {reason}")));
                continue;
            }
        };
        let candidate = inspect_at(
            device, subprobe.path(), Some(subvolume_path), Some(subvolume_id),
            currently_mounted, false, "readonly no-replay Btrfs subvolume mount",
        );
        let cleanup = subprobe.cleanup();
        let clean = cleanup.is_clean();
        report.cleanup.push(cleanup);
        if !clean { report.rejected.push(rejected(path, "readonly subvolume probe cleanup failed".into())); continue; }
        match candidate {
            Some(candidate) => report.candidates.push(candidate),
            None => report.rejected.push(rejected(path, format!("Btrfs subvolume /{subvolume} is not a CatOS root"))),
        }
    }
}

fn normalise_subvolume_path(path: &Path) -> Option<String> {
    let value = path.to_string_lossy();
    let trimmed = value.trim_matches('/');
    (!trimmed.is_empty()).then(|| format!("/{trimmed}"))
}

fn candidate_mount_membership(device: &BlockDevice, candidate_subvolume: Option<&str>) -> (bool, bool) {
    let matches_candidate = |mount: &crate::model::MountObservation| match candidate_subvolume {
        Some(subvolume) => normalise_subvolume_path(&mount.root).as_deref() == Some(subvolume),
        None => mount.root == Path::new("/"),
    };
    let currently_mounted = device.mounts.iter().any(matches_candidate);
    let running_environment_member = device.mounts.iter()
        .any(|mount| mount.mount_point == Path::new("/") && matches_candidate(mount));
    (currently_mounted, running_environment_member)
}


fn is_dot_snapshot_root(path: &str) -> bool {
    let parts = path
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.windows(3).any(|window| {
        matches!(window[0], ".snapshots" | "@snapshots")
            && window[1].chars().all(|character| character.is_ascii_digit())
            && window[2] == "snapshot"
    })
}

fn list_btrfs_subvolumes(root: &Path) -> Result<Vec<(u64, String)>, String> {
    let root = root.to_str().ok_or_else(|| "probe path is not UTF-8".to_string())?;
    let output = run_trusted_tool("btrfs", &["subvolume", "list", "-a", root], Duration::from_secs(10), 64 * 1024)?;
    if !output.success() { return Err(format!("Btrfs subvolume listing failed: {}", String::from_utf8_lossy(&output.stderr).trim())); }
    let values = parse_btrfs_subvolume_list(&String::from_utf8_lossy(&output.stdout));
    if values.is_empty() { return Err("Btrfs filesystem has no discoverable subvolumes".into()) }
    Ok(values)
}

fn parse_btrfs_subvolume_list(body: &str) -> Vec<(u64, String)> {
    body.lines()
        .filter_map(|line| {
            let (_, path) = line.split_once(" path ")?;
            let id = line.strip_prefix("ID ")?.split_whitespace().next()?.parse().ok()?;
            let path = path.trim();
            let path = path.strip_prefix("<FS_TREE>/").unwrap_or(path);
            Some((id, path.to_string()))
        })
        .filter(|(_, path)| !path.is_empty())
        .collect()
}

fn inspect_at(
    device: &BlockDevice,
    root: &Path,
    subvolume: Option<String>,
    subvolume_id: Option<u64>,
    currently_mounted: bool,
    running_environment_member: bool,
    probe_kind: &str,
) -> Option<TargetCandidate> {
    let root_text = root.to_str()?;
    let system_root = SystemRoot::from_user_input(root_text).ok()?;
    let mut warnings = Vec::new();
    let inspection = inspect_target(&RealFilesystem, &system_root, &mut warnings);
    if !inspection.is_catos_target.is_detected() { return None }
    let os_release = inspection.os_release?;
    let fstab_identity = RealFilesystem
        .rooted_read_to_string(root, Path::new("etc/fstab"))
        .ok()
        .map(|body| {
            body.lines()
                .find(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
                .unwrap_or("")
                .to_string()
        });
    let mut evidence = device.evidence.clone();
    evidence.push(Evidence::new(
        "CANDIDATE_OS_RELEASE", root.display().to_string(), "CatOS identity read from candidate root",
    ));
    evidence.push(Evidence::new("PROBE_ROOT", root.display().to_string(), probe_kind));
    if running_environment_member {
        evidence.push(Evidence::new(
            "RUNNING_ROOT_CANDIDATE", root.display().to_string(), "candidate is the current process root",
        ));
    }
    evidence.extend(warnings.into_iter().map(|warning| Evidence::new("CANDIDATE_WARNING", "candidate", warning)));
    Some(TargetCandidate {
        root_device: device.dev_path.clone()?, root_fstype: device.filesystem.clone()?, root_uuid: device.uuid.clone(),
        root_subvolume: subvolume, root_subvolume_id: subvolume_id, filesystem_id: device.uuid.clone(),
        label: device.label.clone(), os_release, fstab_identity, currently_mounted, running_environment_member,
        confidence: RootCandidateConfidence::High, evidence,
    })
}

fn rejected(path: &Path, reason: String) -> DiscoveryRejection {
    DiscoveryRejection { source: path.display().to_string(), reason: reason.clone(), evidence: vec![Evidence::new("CANDIDATE_REJECTED", path.display().to_string(), reason)] }
}
fn candidate_key(candidate: &TargetCandidate) -> (u8, String, String) {
    let confidence = match candidate.confidence { RootCandidateConfidence::High => 0, RootCandidateConfidence::Medium => 1, RootCandidateConfidence::Low => 2, RootCandidateConfidence::Unknown => 3 };
    (confidence, candidate.root_device.display().to_string(), candidate.root_subvolume.clone().unwrap_or_default())
}

struct ReadonlyProbe { path: PathBuf, mounted: bool }
impl ReadonlyProbe {
    fn mount(device: &Path, fstype: &str, subvolume: Option<&str>) -> Result<Self, String> {
        let replay = match fstype { "ext2" | "ext3" | "ext4" => "ro,noload", "xfs" | "btrfs" => "ro,norecovery", _ => "ro" };
        let options = match subvolume { Some(subvolume) => format!("{replay},subvol={subvolume}"), None => replay.into() };
        Self::mount_with_options(device, fstype, &options)
    }
    fn mount_with_options(device: &Path, fstype: &str, options: &str) -> Result<Self, String> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
        let path = std::env::temp_dir().join(format!("catos-target-probe-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).map_err(|e| format!("create probe mountpoint {}: {e}", path.display()))?;
        let device = match device.to_str() { Some(value) => value, None => return Err(probe_start_failure(&path, "device path is not UTF-8")) };
        let mountpoint = match path.to_str() { Some(value) => value, None => return Err(probe_start_failure(&path, "probe path is not UTF-8")) };
        let output = match run_trusted_tool("mount", &["-t", fstype, "-o", options, device, mountpoint], Duration::from_secs(10), 16 * 1024) { Ok(value) => value, Err(error) => return Err(probe_start_failure(&path, &error)) };
        if !output.success() { return Err(probe_start_failure(&path, &format!("readonly no-replay mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()))); }
        Ok(Self { path, mounted: true })
    }
    fn path(&self) -> &Path { &self.path }
    fn cleanup(&mut self) -> ProbeCleanup {
        let mut cleanup = ProbeCleanup { mountpoint: self.path.clone(), unmounted: !self.mounted, removed: false, error: None };
        if self.mounted {
            let Some(mountpoint) = self.path.to_str() else { cleanup.error = Some("probe path is not UTF-8".into()); return cleanup };
            let output = match run_trusted_tool("umount", &[mountpoint], Duration::from_secs(10), 16 * 1024) { Ok(output) => output, Err(error) => { cleanup.error = Some(error); return cleanup } };
            if !output.success() { cleanup.error = Some(String::from_utf8_lossy(&output.stderr).trim().to_string()); return cleanup }
            self.mounted = false;
            cleanup.unmounted = true;
        }
        match std::fs::remove_dir(&self.path) { Ok(()) => cleanup.removed = true, Err(error) => cleanup.error = Some(format!("remove probe mountpoint {}: {error}", self.path.display())) }
        cleanup
    }
}
fn probe_start_failure(path: &Path, reason: &str) -> String {
    let cleanup = std::fs::remove_dir(path);
    match cleanup { Ok(()) => format!("{reason}; probe directory cleanup removed {}", path.display()), Err(error) => format!("{reason}; probe directory cleanup failed for {}: {error}", path.display()) }
}
impl Drop for ReadonlyProbe { fn drop(&mut self) { if self.mounted { eprintln!("catos-target: unreported probe cleanup failure: {:?}", self.cleanup()); } } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordering_is_stable_and_prefers_high_confidence() {
        let base = |path: &str, confidence| TargetCandidate { root_device: PathBuf::from(path), root_fstype: "ext4".into(), root_uuid: None, root_subvolume: None, root_subvolume_id: None, filesystem_id: None, label: None, os_release: OsRelease::default(), fstab_identity: None, currently_mounted: false, running_environment_member: false, confidence, evidence: Vec::new() };
        assert!(candidate_key(&base("/dev/sda2", RootCandidateConfidence::High)) < candidate_key(&base("/dev/sda1", RootCandidateConfidence::Medium)));
    }

    fn mounted_btrfs_device() -> BlockDevice {
        BlockDevice {
            name: "nvme0n1p2".into(), dev_path: Some(PathBuf::from("/dev/nvme0n1p2")),
            major_minor: Some("259:2".into()), parent: "nvme0n1".into(),
            class: crate::model::DeviceClass::Partition, disk_kind: crate::model::DiskKind::Unknown,
            partition_role: crate::model::PartitionRole::LinuxFilesystem, partition_number: Some(2),
            size_sectors: None, read_only: false, removable: false, filesystem: Some("btrfs".into()),
            uuid: Some("fsid".into()), part_uuid: None, label: None, part_label: None,
            mount_point: Some(PathBuf::from("/")),
            mounts: vec![
                crate::model::MountObservation { mount_point: PathBuf::from("/"), root: PathBuf::from("/@"), fstype: "btrfs".into(), read_only: false },
                crate::model::MountObservation { mount_point: PathBuf::from("/home"), root: PathBuf::from("/@home"), fstype: "btrfs".into(), read_only: false },
            ],
            mounted_before_session: true, evidence: Vec::new(),
        }
    }

    #[test]
    fn running_root_borrow_requires_matching_stable_identity() {
        let device = mounted_btrfs_device();
        let mut candidate = TargetCandidate {
            root_device: device.dev_path.clone().unwrap(), root_fstype: "btrfs".into(),
            root_uuid: device.uuid.clone(), root_subvolume: Some("/@".into()), root_subvolume_id: None,
            filesystem_id: device.uuid.clone(), label: None, os_release: OsRelease::default(),
            fstab_identity: None, currently_mounted: true, running_environment_member: true,
            confidence: RootCandidateConfidence::High, evidence: Vec::new(),
        };
        let mountinfo = "36 25 259:2 /@ / ro,relatime - btrfs /dev/nvme0n1p2 ro,subvolid=256,subvol=/@\n";
        let same_fixture_device = |left: &Path, right: &Path| left == right;
        verify_running_root_candidate_with(&candidate, mountinfo, same_fixture_device).unwrap();
        candidate.root_device = PathBuf::from("/dev/other");
        assert!(verify_running_root_candidate_with(&candidate, mountinfo, same_fixture_device).is_err());
        candidate.root_device = PathBuf::from("/dev/nvme0n1p2");
        candidate.root_subvolume = Some("/@other".into());
        assert!(verify_running_root_candidate_with(&candidate, mountinfo, same_fixture_device).is_err());
    }

    #[test]
    fn equal_regular_paths_are_not_block_device_identity() {
        let path = std::env::temp_dir().join(format!("catos-target-regular-file-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a block device").unwrap();
        assert!(!same_block_device(&path, &path));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn btrfs_candidate_mount_membership_is_subvolume_specific() {
        let device = mounted_btrfs_device();
        assert_eq!(candidate_mount_membership(&device, Some("/@")), (true, true));
        assert_eq!(candidate_mount_membership(&device, Some("/@home")), (true, false));
        assert_eq!(candidate_mount_membership(&device, Some("/@snapshots/1/snapshot")), (false, false));
    }

    #[test]
    fn btrfs_all_subvolume_parser_keeps_the_current_root_and_siblings() {
        let listed = parse_btrfs_subvolume_list("ID 256 gen 1 top level 5 path @\nID 257 gen 1 top level 5 path @home\n");
        assert_eq!(listed, vec![(256, "@".into()), (257, "@home".into())]);
    }

    #[test]
    fn probe_start_failure_removes_temporary_directory() {
        let path = std::env::temp_dir().join(format!("catos-target-cleanup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir(&path).unwrap();
        let detail = probe_start_failure(&path, "mount tool unavailable");
        assert!(detail.contains("cleanup removed"));
        assert!(!path.exists());
    }

    #[test]
    fn btrfs_all_subvolume_parser_normalises_nested_fs_tree_prefix() {
        let body = "ID 256 gen 6 top level 5 path @snapshots
ID 257 gen 6 top level 256 path <FS_TREE>/@snapshots/1/snapshot
";
        assert_eq!(
            parse_btrfs_subvolume_list(body),
            vec![
                (256, "@snapshots".to_string()),
                (257, "@snapshots/1/snapshot".to_string()),
            ]
        );
    }

    #[test]
    fn snapshot_roots_are_distinguished_from_normal_subvolumes() {
        for path in [
            ".snapshots/12/snapshot",
            "@/.snapshots/12/snapshot",
            "@snapshots/12/snapshot",
        ] {
            assert!(is_dot_snapshot_root(path), "{path}");
        }
        for path in ["@", "@home", "@snapshots", "snapshot", "@snapshots/cache"] {
            assert!(!is_dot_snapshot_root(path), "{path}");
        }
    }

    #[test]
    fn cleanup_is_clean_only_when_unmounted_removed_and_error_free() {
        let clean = ProbeCleanup {
            mountpoint: PathBuf::from("/tmp/probe"),
            unmounted: true,
            removed: true,
            error: None,
        };
        assert!(clean.is_clean());
        for dirty in [
            ProbeCleanup { unmounted: false, ..clean.clone() },
            ProbeCleanup { removed: false, ..clean.clone() },
            ProbeCleanup { error: Some("busy".into()), ..clean.clone() },
        ] {
            assert!(!dirty.is_clean());
        }
    }
}
