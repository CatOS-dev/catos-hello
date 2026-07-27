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
use crate::diagnose::filesystem::RealFilesystem;
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
    pub filesystem_id: Option<String>,
    pub label: Option<String>,
    pub os_release: OsRelease,
    pub fstab_identity: Option<String>,
    pub currently_mounted: bool,
    pub running_environment_member: bool,
    pub confidence: RootCandidateConfidence,
    pub evidence: Vec<Evidence>,
}

/// A selected candidate held open on a real readonly/no-replay mount.  The
/// owner must call [`TargetSession::cleanup`] and preserve the returned
/// result in its report.
pub struct TargetSession {
    candidate: TargetCandidate,
    probe: ReadonlyProbe,
}

impl TargetSession {
    pub fn open(candidate: TargetCandidate) -> Result<Self, String> {
        let probe = ReadonlyProbe::mount(
            &candidate.root_device,
            &candidate.root_fstype,
            candidate.root_subvolume.as_deref().map(|value| value.trim_start_matches('/')),
        )?;
        Ok(Self { candidate, probe })
    }

    pub fn root(&self) -> &Path { self.probe.path() }
    pub fn candidate(&self) -> &TargetCandidate { &self.candidate }
    pub fn cleanup(mut self) -> ProbeCleanup { self.probe.cleanup() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRejection {
    pub source: String,
    pub reason: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
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

/// Discover installed CatOS targets. Candidate contents are always read from
/// the candidate mount, never from the running host root.
pub fn discover_targets() -> DiscoveryReport {
    let fs = RealFilesystem;
    let (devices, warnings) = discover_devices(&fs);
    let mut report = DiscoveryReport::default();
    for warning in warnings {
        report.rejected.push(DiscoveryRejection {
            source: "block-inventory".into(), reason: warning.message,
            evidence: Vec::new(),
        });
    }
    for device in devices {
        inspect_device(&device, &mut report);
    }
    report.candidates.sort_by(|a, b| candidate_key(a).cmp(&candidate_key(b)));
    report
}

/// The shared inventory used by consumers that need to resolve fstab entries
/// after target selection. It is intentionally the same inventory pass as
/// candidate discovery, not a second `lsblk` implementation.
pub fn discover_inventory() -> Vec<BlockDevice> {
    discover_devices(&RealFilesystem).0
}

fn inspect_device(device: &BlockDevice, report: &mut DiscoveryReport) {
    let Some(fstype) = device.filesystem.as_deref() else { return };
    if !matches!(fstype, "btrfs" | "ext2" | "ext3" | "ext4" | "xfs" | "f2fs") { return }
    let Some(path) = device.dev_path.as_ref() else { return };
    let live_mount = device.mounts.iter().find(|mount| mount.mount_point == Path::new("/"));
    if let Some(mount) = live_mount {
        if fstype != "btrfs" {
            report.excluded.push(excluded(path, "device", "current Live root device", mount.root.display().to_string()));
            return;
        }
    }

    if fstype == "btrfs" {
        inspect_btrfs_device(device, live_mount.map(|mount| mount.root.as_path()), report);
        return;
    }
    let mut probe = match ReadonlyProbe::mount(path, fstype, None) {
        Ok(probe) => probe,
        Err(reason) => { report.rejected.push(rejected(path, reason)); return; }
    };
    let result = inspect_at(device, probe.path(), None, None, "readonly no-replay temporary mount");
    let cleanup = probe.cleanup();
    let clean = cleanup.error.is_none();
    report.cleanup.push(cleanup);
    if !clean { report.rejected.push(rejected(path, "readonly probe cleanup failed".into())); return; }
    match result {
        Some(candidate) if candidate.running_environment_member => report.excluded.push(excluded(path, "subvolume", "current Live root subvolume", candidate.root_subvolume.unwrap_or_else(|| "/".into()))),
        Some(candidate) => report.candidates.push(candidate),
        None => report.rejected.push(rejected(path, "candidate os-release/layout is not CatOS".into())),
    }
}

fn inspect_btrfs_device(device: &BlockDevice, live_subvolume: Option<&Path>, report: &mut DiscoveryReport) {
    let Some(path) = device.dev_path.as_ref() else { return };
    let mut probe = match ReadonlyProbe::mount_with_options(path, "btrfs", "ro,norecovery,subvolid=5") {
        Ok(probe) => probe,
        Err(reason) => { report.rejected.push(rejected(path, reason)); return; }
    };
    let subvolumes = list_btrfs_subvolumes(probe.path());
    let cleanup = probe.cleanup();
    let clean = cleanup.error.is_none();
    report.cleanup.push(cleanup);
    if !clean { report.rejected.push(rejected(path, "readonly probe cleanup failed".into())); return; }
    let subvolumes = match subvolumes { Ok(values) => values, Err(reason) => { report.rejected.push(rejected(path, reason)); return; } };
    for subvolume in subvolumes {
        let mut subprobe = match ReadonlyProbe::mount(path, "btrfs", Some(&subvolume)) {
            Ok(probe) => probe,
            Err(reason) => { report.rejected.push(rejected(path, format!("cannot probe subvolume /{subvolume}: {reason}"))); continue; }
        };
        let live = live_subvolume.map(|value| value.to_string_lossy().trim_start_matches('/').to_string());
        let candidate = inspect_at(device, subprobe.path(), Some(format!("/{subvolume}")), None, "readonly no-replay Btrfs subvolume mount");
        let cleanup = subprobe.cleanup();
        let clean = cleanup.error.is_none();
        report.cleanup.push(cleanup);
        if !clean { report.rejected.push(rejected(path, "readonly subvolume probe cleanup failed".into())); continue; }
        match candidate {
            Some(candidate) if candidate.root_subvolume.as_deref() == live.as_deref().map(|value| format!("/{value}")).as_deref() => report.excluded.push(excluded(path, "subvolume", "current Live root subvolume", candidate.root_subvolume.unwrap_or_else(|| "/".into()))),
            Some(candidate) => report.candidates.push(candidate),
            None => report.rejected.push(rejected(path, format!("Btrfs subvolume /{subvolume} is not a CatOS root"))),
        }
    }
}

fn list_btrfs_subvolumes(root: &Path) -> Result<Vec<String>, String> {
    let root = root.to_str().ok_or_else(|| "probe path is not UTF-8".to_string())?;
    let output = run_trusted_tool("btrfs", &["subvolume", "list", "-a", root], Duration::from_secs(10), 64 * 1024)?;
    if !output.success() { return Err(format!("Btrfs subvolume listing failed: {}", String::from_utf8_lossy(&output.stderr).trim())); }
    let values = parse_btrfs_subvolume_list(&String::from_utf8_lossy(&output.stdout));
    if values.is_empty() { return Err("Btrfs filesystem has no discoverable subvolumes".into()) }
    Ok(values)
}

fn parse_btrfs_subvolume_list(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.split_once(" path ").map(|(_, path)| path.trim().to_string()))
        .filter(|path| !path.is_empty())
        .collect()
}

fn inspect_at(device: &BlockDevice, root: &Path, subvolume: Option<String>, live_root: Option<&Path>, probe_kind: &str) -> Option<TargetCandidate> {
    let root_text = root.to_str()?;
    let system_root = SystemRoot::from_user_input(root_text).ok()?;
    let mut warnings = Vec::new();
    let inspection = inspect_target(&RealFilesystem, &system_root, &mut warnings);
    if !inspection.is_catos_target.is_detected() { return None }
    let os_release = inspection.os_release?;
    let running_environment_member = live_root.is_some_and(|live| live == root);
    let fstab_identity = std::fs::read_to_string(root.join("etc/fstab")).ok().map(|body| body.lines().find(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty()).unwrap_or("").to_string());
    let mut evidence = device.evidence.clone();
    evidence.push(Evidence::new("CANDIDATE_OS_RELEASE", root.display().to_string(), "CatOS identity read from readonly candidate mount"));
    evidence.push(Evidence::new("PROBE_MOUNT", root.display().to_string(), probe_kind));
    evidence.extend(warnings.into_iter().map(|warning| Evidence::new("CANDIDATE_WARNING", "candidate", warning)));
    Some(TargetCandidate {
        root_device: device.dev_path.clone()?, root_fstype: device.filesystem.clone()?, root_uuid: device.uuid.clone(),
        root_subvolume: subvolume, filesystem_id: device.uuid.clone(), label: device.label.clone(), os_release,
        fstab_identity, currently_mounted: !device.mounts.is_empty(), running_environment_member,
        confidence: RootCandidateConfidence::High, evidence,
    })
}

fn excluded(path: &Path, scope: &str, reason: &str, value: String) -> DiscoveryRejection {
    DiscoveryRejection { source: path.display().to_string(), reason: reason.into(), evidence: vec![Evidence::new("LIVE_ROOT_EXCLUDED", path.display().to_string(), format!("excluded {scope}: {reason}")).with_value(value)] }
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
        let device = device.to_str().ok_or_else(|| "device path is not UTF-8".to_string())?;
        let mountpoint = path.to_str().ok_or_else(|| "probe path is not UTF-8".to_string())?;
        let output = run_trusted_tool("mount", &["-t", fstype, "-o", options, device, mountpoint], Duration::from_secs(10), 16 * 1024)?;
        if !output.success() { let cleanup = std::fs::remove_dir(&path).err().map(|e| format!("; failed removing probe directory: {e}")); return Err(format!("readonly no-replay mount failed: {}{}", String::from_utf8_lossy(&output.stderr).trim(), cleanup.unwrap_or_default())); }
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
impl Drop for ReadonlyProbe { fn drop(&mut self) { if self.mounted { eprintln!("catos-target: unreported probe cleanup failure: {:?}", self.cleanup()); } } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordering_is_stable_and_prefers_high_confidence() {
        let base = |path: &str, confidence| TargetCandidate { root_device: PathBuf::from(path), root_fstype: "ext4".into(), root_uuid: None, root_subvolume: None, filesystem_id: None, label: None, os_release: OsRelease::default(), fstab_identity: None, currently_mounted: false, running_environment_member: false, confidence, evidence: Vec::new() };
        assert!(candidate_key(&base("/dev/sda2", RootCandidateConfidence::High)) < candidate_key(&base("/dev/sda1", RootCandidateConfidence::Medium)));
    }

    #[test]
    fn btrfs_all_subvolume_parser_keeps_the_current_root_and_siblings() {
        let listed = parse_btrfs_subvolume_list("ID 256 gen 1 top level 5 path @\nID 257 gen 1 top level 5 path @home\n");
        assert_eq!(listed, vec!["@", "@home"]);
    }
}
