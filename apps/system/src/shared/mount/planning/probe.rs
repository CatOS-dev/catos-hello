//! Short-lived read-only probe mounts for unmounted root/ESP candidates.
//!
//! A probe mount is deliberately not a user-visible target session. It
//! mounts exactly one known filesystem inside a private mount namespace,
//! collects minimal evidence, and cleans up before returning.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::shared::model::evidence::Evidence;
use crate::shared::model::fstab::FstabEntry;
use crate::target::model::{TargetInspection, Warning};
use crate::shared::model::mount::{CleanupReport, MountError, MountErrorKind};
use crate::target::model::{
    BlockDevice, BtrfsSubvolume, BtrfsSubvolumeKind, EspCandidate, RootCandidate,
    RootCandidateConfidence,
};
use crate::shared::mount::plan::build_probe_plan;
use crate::shared::mount::session::{Session, SESSION_ROOT_PARENT};
use crate::shared::parse::fstab::parse_all_with_diagnostics;
use crate::target::diagnose::candidate::identify_candidates;
use crate::target::diagnose::runtime::ProcCaps;
use crate::target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
use crate::target::diagnose::candidate::inspect_target;
use crate::shared::process::run_trusted_tool;
use crate::target::diagnose::system_root::SystemRoot;

static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const MAX_PROBED_DEVICES: usize = 64;
const MAX_BTRFS_SUBVOLUMES: usize = 512;
const MAX_INSPECTED_BTRFS_ROOTS: usize = 64;

#[derive(Default)]
pub struct ProbeCandidates {
    pub roots: Vec<RootCandidate>,
    pub esps: Vec<EspCandidate>,
    pub btrfs_subvolumes: Vec<BtrfsSubvolume>,
    pub warnings: Vec<Warning>,
}

pub struct SelectedTargetProbe {
    pub fstab: Vec<FstabEntry>,
    pub inspection: TargetInspection,
    pub cleanup: CleanupReport,
    pub warnings: Vec<Warning>,
}

/// Inspect one explicitly selected root device. This is the bridge from
/// LiveCD/initramfs device selection to a complete fstab-based mount plan:
/// the selected root is mounted read-only, its own fstab is read through
/// SystemRoot confinement, and the probe is cleaned before returning.
pub fn inspect_selected_root(
    device: &BlockDevice,
    subvolume: Option<&str>,
) -> Result<SelectedTargetProbe, MountError> {
    let source = device
        .dev_path
        .as_ref()
        .and_then(|path| path.to_str())
        .ok_or_else(|| {
            simple_mount_error(
                MountErrorKind::DeviceNotFound,
                "selected root device has no usable /dev path",
                Some(device.name.clone()),
            )
        })?;
    let fstype = device.filesystem.as_deref().ok_or_else(|| {
        simple_mount_error(
            MountErrorKind::UnsupportedFilesystem,
            "selected root device has no identified filesystem",
            Some(source.to_string()),
        )
    })?;
    let selector = match (fstype, subvolume) {
        ("btrfs", Some(path)) => Some(format!("subvol={path}")),
        ("btrfs", None) => None,
        (_, Some(_)) => {
            return Err(simple_mount_error(
                MountErrorKind::InvalidMountOption,
                "--root-subvolume is valid only for btrfs",
                Some(source.to_string()),
            ));
        }
        (_, None) => None,
    };

    let plan = build_probe_plan(
        probe_session_root(&device.name),
        source,
        fstype,
        selector.as_deref(),
    )?;
    let id = plan
        .session_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("selected-root")
        .to_string();
    let mut session = Session::new(id, &plan);
    let snapshot = session.run(&plan)?;
    let target_path = snapshot.target_root.to_str().ok_or_else(|| {
        simple_mount_error(
            MountErrorKind::UnsafeTargetPath,
            "temporary target path is not valid UTF-8",
            Some(snapshot.target_root.display().to_string()),
        )
    })?;
    let target = SystemRoot::from_user_input(target_path).map_err(|error| {
        simple_mount_error(
            MountErrorKind::UnsafeTargetPath,
            &error.to_string(),
            Some(target_path.to_string()),
        )
    })?;
    let fs = RealFilesystem;
    let fstab_result = fs.rooted_read_to_string(target.canonical_path(), Path::new("etc/fstab"));
    let (fstab, diagnostics) = match fstab_result {
        Ok(body) => crate::shared::parse::fstab::parse_all_with_diagnostics(&body),
        Err(crate::shared::error::FsError::NotFound) => (Vec::new(), Vec::new()),
        Err(error) => {
            let cleanup = session.cleanup();
            return Err(MountError {
                cleanup_complete: cleanup.all_clean,
                residual_mounts: cleanup_residual_paths(&cleanup),
                ..simple_mount_error(
                    MountErrorKind::MountFailed,
                    &format!("cannot read selected target fstab: {error}"),
                    Some(target_path.to_string()),
                )
            });
        }
    };
    let mut inspection_warnings = Vec::new();
    let inspection = inspect_target(&fs, &target, &mut inspection_warnings);
    let mut warnings: Vec<Warning> = diagnostics
        .into_iter()
        .map(|diagnostic| {
            Warning::new(
                "FSTAB_PARSE_ERROR",
                format!(
                    "target fstab line {} is invalid ({:?}): {}",
                    diagnostic.line, diagnostic.kind, diagnostic.text
                ),
            )
        })
        .collect();
    warnings.extend(
        inspection_warnings
            .into_iter()
            .map(|message| Warning::new("TARGET_INSPECTION_WARNING", message)),
    );
    let cleanup = session.cleanup();
    if !cleanup.all_clean {
        return Err(MountError {
            kind: MountErrorKind::CleanupIncomplete,
            message: "selected root probe left residual mounts".into(),
            device_or_path: Some(source.to_string()),
            errno: None,
            completed_steps: vec!["selected root inspected".into()],
            cleanup_complete: false,
            residual_mounts: cleanup_residual_paths(&cleanup),
        });
    }

    Ok(SelectedTargetProbe {
        fstab,
        inspection,
        cleanup,
        warnings,
    })
}

fn simple_mount_error(
    kind: MountErrorKind,
    message: &str,
    device_or_path: Option<String>,
) -> MountError {
    MountError {
        kind,
        message: message.to_string(),
        device_or_path,
        errno: None,
        completed_steps: vec![],
        cleanup_complete: true,
        residual_mounts: vec![],
    }
}

fn cleanup_residual_paths(cleanup: &CleanupReport) -> Vec<String> {
    cleanup
        .residual
        .iter()
        .map(|item| item.resource.target.display().to_string())
        .collect()
}

pub fn probe_unmounted_candidates(
    devices: &[BlockDevice],
    fstab: &[FstabEntry],
) -> ProbeCandidates {
    if ProcCaps::from_current_process().cap_sys_admin != Some(true) {
        return ProbeCandidates {
            warnings: vec![Warning::new(
                "CANDIDATE_PROBE_UNAVAILABLE",
                "unmounted candidate inspection requires effective CAP_SYS_ADMIN",
            )],
            ..Default::default()
        };
    }

    let mut report = ProbeCandidates::default();
    for device in devices
        .iter()
        .filter(|device| device.mount_point.is_none())
        .filter(|device| device.dev_path.is_some())
        .take(MAX_PROBED_DEVICES)
    {
        let Some(fstype) = device.filesystem.as_deref() else {
            continue;
        };
        match fstype {
            "btrfs" => probe_btrfs(device, &mut report),
            "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" => probe_simple(device, fstab, &mut report),
            "vfat" | "fat" | "fat32" | "fat16" | "fat12" => {
                probe_simple(device, fstab, &mut report)
            }
            _ => {}
        }
    }
    report
}

fn probe_simple(device: &BlockDevice, fstab: &[FstabEntry], report: &mut ProbeCandidates) {
    let Some(source) = device.dev_path.as_ref().and_then(|path| path.to_str()) else {
        return;
    };
    let Some(fstype) = device.filesystem.as_deref() else {
        return;
    };
    let session_root = probe_session_root(&device.name);
    let plan = match build_probe_plan(session_root, source, fstype, None) {
        Ok(plan) => plan,
        Err(error) => {
            report.warnings.push(Warning::new(
                "PROBE_PLAN_REFUSED",
                format!("cannot probe {source}: {error}"),
            ));
            return;
        }
    };
    let id = plan
        .session_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("probe")
        .to_string();
    let mut session = Session::new(id, &plan);
    let snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            report.warnings.push(Warning::new(
                "PROBE_MOUNT_FAILED",
                format!("cannot inspect {source}: {error}"),
            ));
            return;
        }
    };

    let candidate_fstab = RealFilesystem
        .rooted_read_to_string(&snapshot.target_root, Path::new("etc/fstab"))
        .map(|body| parse_all_with_diagnostics(&body).0)
        .unwrap_or_default();
    let mut mounted = device.clone();
    mounted.mount_point = Some(snapshot.target_root.clone());
    mounted.mounted_before_session = false;
    // Prefer the candidate's own fstab when it is available. This lets
    // root confidence require that the filesystem we mounted is the
    // source of that target's `/` entry, rather than treating any
    // unmounted ext4 data partition as a possible system root.
    let fstab = if candidate_fstab.is_empty() {
        fstab
    } else {
        &candidate_fstab
    };
    let (mut roots, mut esps, _, warnings) = identify_candidates(&[mounted], fstab);
    for candidate in &mut roots {
        candidate.mounted_at = None;
        candidate.evidence.push(Evidence::new(
            "TEMPORARY_READ_ONLY_PROBE",
            source,
            "candidate content inspected through a short-lived read-only mount",
        ));
    }
    for candidate in &mut esps {
        candidate.evidence.push(Evidence::new(
            "TEMPORARY_READ_ONLY_PROBE",
            source,
            "ESP content inspected through a short-lived read-only mount",
        ));
    }
    report.roots.extend(roots);
    report.esps.extend(esps);
    report.warnings.extend(warnings);

    let cleanup = session.cleanup();
    if !cleanup.all_clean {
        report.warnings.push(Warning::new(
            "PROBE_CLEANUP_INCOMPLETE",
            format!("temporary probe for {source} left residual mounts"),
        ));
    }
}

fn probe_btrfs(device: &BlockDevice, report: &mut ProbeCandidates) {
    let Some(source) = device.dev_path.as_ref().and_then(|path| path.to_str()) else {
        return;
    };
    let session_root = probe_session_root(&device.name);
    let plan = match build_probe_plan(session_root, source, "btrfs", Some("subvolid=5")) {
        Ok(plan) => plan,
        Err(error) => {
            report.warnings.push(Warning::new(
                "BTRFS_PROBE_PLAN_REFUSED",
                format!("cannot probe {source}: {error}"),
            ));
            return;
        }
    };
    let id = plan
        .session_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("probe")
        .to_string();
    let mut session = Session::new(id, &plan);
    let snapshot = match session.run(&plan) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            report.warnings.push(Warning::new(
                "BTRFS_PROBE_MOUNT_FAILED",
                format!("cannot inspect {source}: {error}"),
            ));
            return;
        }
    };

    let (mut subvolumes, mut warnings) = enumerate_btrfs_subvolumes(&snapshot.target_root);
    if subvolumes.is_empty() {
        subvolumes = fallback_btrfs_subvolumes(&snapshot.target_root);
    }
    inspect_btrfs_roots(
        device,
        &snapshot.target_root,
        &mut subvolumes,
        &mut report.roots,
    );
    report.btrfs_subvolumes.extend(subvolumes);
    report.warnings.append(&mut warnings);

    let cleanup = session.cleanup();
    if !cleanup.all_clean {
        report.warnings.push(Warning::new(
            "BTRFS_PROBE_CLEANUP_INCOMPLETE",
            format!("temporary btrfs probe for {source} left residual mounts"),
        ));
    }
}

fn enumerate_btrfs_subvolumes(root: &Path) -> (Vec<BtrfsSubvolume>, Vec<Warning>) {
    let mut warnings = Vec::new();
    let Some(root_str) = root.to_str() else {
        return (Vec::new(), warnings);
    };

    let listed = run_trusted_tool(
        "btrfs",
        &["subvolume", "list", root_str],
        Duration::from_secs(4),
        1024 * 1024,
    );
    let readonly = run_trusted_tool(
        "btrfs",
        &["subvolume", "list", "-r", root_str],
        Duration::from_secs(4),
        1024 * 1024,
    );
    let default = run_trusted_tool(
        "btrfs",
        &["subvolume", "get-default", root_str],
        Duration::from_secs(2),
        64 * 1024,
    );

    let mut entries: BTreeMap<String, (Option<u64>, bool)> = BTreeMap::new();
    match listed {
        Ok(output) if output.success() && !output.stdout_truncated => {
            for (id, path) in parse_btrfs_subvolume_list(&output.stdout)
                .into_iter()
                .take(MAX_BTRFS_SUBVOLUMES)
            {
                entries.entry(path).or_insert((id, false));
            }
        }
        Ok(output) => warnings.push(Warning::new(
            "BTRFS_SUBVOLUME_LIST_FAILED",
            format!("{} exited {}", output.path.display(), output.status),
        )),
        Err(error) => warnings.push(Warning::new("BTRFS_TOOL_UNAVAILABLE", error)),
    }

    if let Ok(output) = readonly {
        if output.success() && !output.stdout_truncated {
            for (id, path) in parse_btrfs_subvolume_list(&output.stdout) {
                let entry = entries.entry(path).or_insert((id, false));
                entry.1 = true;
            }
        }
    }

    let default_path = default
        .ok()
        .filter(|output| output.success() && !output.stdout_truncated)
        .and_then(|output| parse_btrfs_default_path(&output.stdout));

    let mut subvolumes = vec![BtrfsSubvolume {
        path: "/".into(),
        id: Some(5),
        name: None,
        kind: BtrfsSubvolumeKind::TopLevel,
        is_default: default_path.as_deref() == Some("/"),
        read_only: false,
        evidence: vec![Evidence::new(
            "BTRFS_TOP_LEVEL",
            root.display().to_string(),
            "filesystem mounted with subvolid=5",
        )],
    }];
    subvolumes.extend(entries.into_iter().map(|(path, (id, read_only))| {
        let normalized = normalize_subvolume_path(&path);
        let name = Path::new(&normalized)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string);
        let snapshot = looks_like_snapshot_path(&normalized);
        BtrfsSubvolume {
            path: normalized.clone(),
            id,
            name,
            kind: if snapshot {
                if read_only {
                    BtrfsSubvolumeKind::ReadOnlySnapshot
                } else {
                    BtrfsSubvolumeKind::SnapshotContainer
                }
            } else {
                BtrfsSubvolumeKind::Unknown
            },
            is_default: default_path.as_deref() == Some(normalized.as_str()),
            read_only,
            evidence: vec![Evidence::new(
                "BTRFS_SUBVOLUME_LIST",
                root.display().to_string(),
                "subvolume reported by btrfs-progs",
            )
            .with_value(normalized)],
        }
    }));
    (subvolumes, warnings)
}

fn inspect_btrfs_roots(
    device: &BlockDevice,
    top_level: &Path,
    subvolumes: &mut [BtrfsSubvolume],
    roots: &mut Vec<RootCandidate>,
) {
    let mut inspected = 0usize;
    for subvolume in subvolumes {
        if inspected >= MAX_INSPECTED_BTRFS_ROOTS {
            break;
        }
        if matches!(
            subvolume.kind,
            BtrfsSubvolumeKind::TopLevel
                | BtrfsSubvolumeKind::ReadOnlySnapshot
                | BtrfsSubvolumeKind::SnapshotContainer
        ) {
            continue;
        }
        let Some(path) = safe_subvolume_join(top_level, &subvolume.path) else {
            continue;
        };
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        inspected += 1;
        let mut mounted = device.clone();
        mounted.mount_point = Some(path);
        mounted.mounted_before_session = false;
        let fstab = RealFilesystem
            .rooted_read_to_string(
                mounted.mount_point.as_ref().unwrap(),
                Path::new("etc/fstab"),
            )
            .map(|body| parse_all_with_diagnostics(&body).0)
            .unwrap_or_default();
        let (mut candidates, _, _, _) = identify_candidates(&[mounted], &fstab);
        let Some(mut candidate) = candidates.pop() else {
            subvolume.kind = BtrfsSubvolumeKind::Data;
            continue;
        };
        candidate.mounted_at = None;
        candidate.subvolume = Some(subvolume.path.clone());
        candidate.evidence.push(Evidence::new(
            "BTRFS_SUBVOLUME_INSPECTED",
            device
                .dev_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| device.name.clone()),
            "subvolume inspected through the top-level read-only probe mount",
        ));
        if candidate.confidence == RootCandidateConfidence::High
            || candidate.confidence == RootCandidateConfidence::Medium
        {
            subvolume.kind = BtrfsSubvolumeKind::RootCandidate;
            roots.push(candidate);
        } else {
            subvolume.kind = BtrfsSubvolumeKind::Data;
        }
    }
}

fn fallback_btrfs_subvolumes(root: &Path) -> Vec<BtrfsSubvolume> {
    let mut paths = BTreeSet::new();
    for name in ["@", "@root", "root"] {
        let path = root.join(name);
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        {
            paths.insert(name.to_string());
        }
    }
    paths
        .into_iter()
        .map(|path| BtrfsSubvolume {
            path: normalize_subvolume_path(&path),
            id: None,
            name: Some(path),
            kind: BtrfsSubvolumeKind::Unknown,
            is_default: false,
            read_only: false,
            evidence: vec![Evidence::new(
                "BTRFS_COMMON_ROOT_NAME",
                root.display().to_string(),
                "common root subvolume name found without btrfs-progs",
            )],
        })
        .collect()
}

fn parse_btrfs_subvolume_list(bytes: &[u8]) -> Vec<(Option<u64>, String)> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| {
            let id = line
                .strip_prefix("ID ")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok());
            let (_, path) = line.split_once(" path ")?;
            if path.is_empty() {
                None
            } else {
                Some((id, path.to_string()))
            }
        })
        .collect()
}

fn parse_btrfs_default_path(bytes: &[u8]) -> Option<String> {
    let body = String::from_utf8_lossy(bytes);
    if body.contains("FS_TREE") {
        return Some("/".into());
    }
    let (_, path) = body.trim().split_once(" path ")?;
    Some(normalize_subvolume_path(path))
}

fn normalize_subvolume_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        format!("/{trimmed}")
    }
}

fn safe_subvolume_join(root: &Path, subvolume: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in Path::new(subvolume).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(root.join(relative))
}

fn looks_like_snapshot_path(path: &str) -> bool {
    path == "/.snapshots"
        || path.starts_with("/.snapshots/")
        || path.contains("/timeshift-btrfs/")
        || path.ends_with("/snapshot")
}

fn probe_session_root(device_name: &str) -> PathBuf {
    let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Path::new(SESSION_ROOT_PARENT).join(format!(
        "probe-{}-{}-{sequence}",
        std::process::id(),
        sanitize_component(device_name)
    ))
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_btrfs_subvolume_list_output() {
        let parsed = parse_btrfs_subvolume_list(
            b"ID 256 gen 10 top level 5 path @\nID 300 gen 11 top level 256 path @/.snapshots/1/snapshot\n",
        );
        assert_eq!(parsed[0], (Some(256), "@".into()));
        assert_eq!(parsed[1].1, "@/.snapshots/1/snapshot");
    }

    #[test]
    fn rejects_subvolume_path_escape() {
        assert!(safe_subvolume_join(Path::new("/probe"), "/@/../host").is_none());
        assert_eq!(
            safe_subvolume_join(Path::new("/probe"), "/@/root"),
            Some(PathBuf::from("/probe/@/root"))
        );
    }

    #[test]
    fn snapshot_paths_are_not_root_candidates() {
        assert!(looks_like_snapshot_path("/@/.snapshots/1/snapshot"));
        assert!(!looks_like_snapshot_path("/@"));
    }

    #[test]
    fn default_path_parser_handles_top_level_and_named_subvolume() {
        assert_eq!(
            parse_btrfs_default_path(b"ID 5 (FS_TREE)"),
            Some("/".into())
        );
        assert_eq!(
            parse_btrfs_default_path(b"ID 256 gen 1 top level 5 path @"),
            Some("/@".into())
        );
    }
}
