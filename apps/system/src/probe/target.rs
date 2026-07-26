//! Target-root inspection. Phase 1 only reads files; it never mounts,
//! discovers block devices, or invokes external tools. Real filesystem access
//! is confined with openat2 `RESOLVE_IN_ROOT` through [`FilesystemProbe`].

use std::path::{Path, PathBuf};

use crate::shared::error::FsError;
use crate::shared::model::capability::CapabilityStatus;
use crate::shared::model::evidence::Evidence;
use crate::shared::model::inspection::{OsRelease, Presence, TargetInspection, ToolPath};
use crate::shared::model::runtime::Detection;
use crate::probe::fs_probe::{FilesystemProbe, MetaData};
use crate::system_root::SystemRoot;

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

pub(crate) fn target_metadata(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    rel: &str,
) -> Result<(PathBuf, MetaData), FsError> {
    let logical = logical_path(root, rel)?;
    let metadata = fs.rooted_metadata(root.canonical_path(), Path::new(rel))?;
    Ok((logical, metadata))
}

pub(crate) fn target_read_to_string(
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
            warnings.push(format!(
                "{} exists but is not a regular file",
                path.display()
            ));
            Presence::Absent
        }
        Err(FsError::NotFound) => Presence::Absent,
        Err(error) => {
            warnings.push(format!(
                "cannot inspect {}: {error}",
                root.join(rel).display()
            ));
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
            warnings.push(format!(
                "cannot inspect {}: {error}",
                root.join(rel).display()
            ));
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

pub(crate) fn probe_target_tool(
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
    [
        ("pacman", "usr/bin/pacman"),
        ("mkinitcpio", "usr/bin/mkinitcpio"),
    ]
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

pub fn host_efivars_path<'a>() -> &'a Path {
    Path::new("/sys/firmware/efi/efivars")
}
