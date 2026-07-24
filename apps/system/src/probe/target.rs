//! Target-root inspection. Phase 1 only reads files; it never mounts,
//! discovers block devices, or invokes external tools. All target paths are
//! constructed via [`SystemRoot::join`] so a `--root /mnt` cannot accidentally
//! read the host's `/etc`.

use std::path::{Path, PathBuf};

use crate::error::FsError;
use crate::model::evidence::Evidence;
use crate::model::inspection::{OsRelease, TargetInspection, ToolPath};
use crate::model::runtime::Detection;
use crate::probe::fs_probe::FilesystemProbe;
use crate::system_root::SystemRoot;

/// Inspect the target root, producing a structured result. Failures to read
/// individual files do NOT abort the inspection; they are recorded in
/// `warnings` (the caller is responsible for collecting them via the
/// `Warnings` accumulator returned alongside the inspection).
pub fn inspect_target(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    warnings: &mut Vec<String>,
) -> TargetInspection {
    let os_release = read_os_release(fs, root, warnings);

    let has_fstab = fs.exists(&root.join("etc/fstab"));
    let has_crypttab = fs.exists(&root.join("etc/crypttab"));
    let has_pacman_db = fs.is_dir(&root.join("var/lib/pacman/local"));
    let has_usr = fs.is_dir(&root.join("usr"));
    let has_boot = fs.is_dir(&root.join("boot"));
    let has_efi = fs.is_dir(&root.join("efi"));
    let has_boot_efi = fs.is_dir(&root.join("boot/efi"));

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

fn read_os_release(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    warnings: &mut Vec<String>,
) -> Option<OsRelease> {
    let path = root.join("etc/os-release");
    let content = match fs.read_to_string(&path) {
        Ok(c) => c,
        Err(FsError::NotFound) => {
            // Try the legacy path.
            let fallback = root.join("usr/lib/os-release");
            match fs.read_to_string(&fallback) {
                Ok(c) => c,
                Err(FsError::NotFound) => return None,
                Err(_) => {
                    warnings.push(format!("os-release present at {fallback:?} but unreadable"));
                    return None;
                }
            }
        }
        Err(FsError::NotUtf8) => {
            warnings.push(format!("{path:?} is not valid UTF-8; os-release skipped"));
            return None;
        }
        Err(FsError::PermissionDenied) => {
            warnings.push(format!(
                "permission denied reading {path:?}; os-release skipped"
            ));
            return None;
        }
        Err(e) => {
            warnings.push(format!("error reading {path:?}: {e}"));
            return None;
        }
    };
    Some(OsRelease::parse(&content))
}

fn classify_catos_target(os_release: &Option<OsRelease>) -> Detection {
    match os_release {
        Some(o) => {
            if o.looks_like_catos() {
                Detection::detected(vec![Evidence::new(
                    "OS_RELEASE_IDENTIFIES_CATOS",
                    "etc/os-release",
                    "target os-release identifies as CatOS (id / id_like / name)",
                )
                .with_value(
                    o.id.clone()
                        .or_else(|| o.id_like.clone())
                        .unwrap_or_default(),
                )])
            } else {
                let mut ev = vec![Evidence::new(
                    "OS_RELEASE_NOT_CATOS",
                    "etc/os-release",
                    "target os-release does not identify as CatOS",
                )];
                if let Some(id) = &o.id {
                    ev.push(
                        Evidence::new(
                            "OS_RELEASE_ID",
                            "etc/os-release",
                            "target identifies as a different distribution",
                        )
                        .with_value(id.clone()),
                    );
                }
                Detection::not_detected(ev)
            }
        }
        None => Detection::unknown(vec![Evidence::new(
            "OS_RELEASE_MISSING",
            "etc/os-release",
            "no os-release readable; cannot classify target",
        )]),
    }
}

/// Tool probes inside the target root. We do NOT search host PATH here; that
/// is reserved for the capability layer (some tools are host-side, others are
/// target-side).
fn probe_target_tools(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Vec<ToolPath> {
    let tools = [
        ("pacman", "usr/bin/pacman"),
        ("mkinitcpio", "usr/bin/mkinitcpio"),
        ("bootloadu", "usr/bin/bootloadu"),
    ];
    tools
        .iter()
        .map(|(name, rel)| {
            let path = root.join(rel);
            let meta = fs.metadata(&path).ok();
            let exists = meta.is_some();
            let executable = meta.map(|m| m.is_executable()).unwrap_or(false);
            ToolPath {
                name: (*name).to_string(),
                path,
                exists,
                executable,
            }
        })
        .collect()
}

/// Helper for capability probing: resolve whether a host-side tool exists on
/// PATH by checking a fixed list of well-known directories. Phase 1 does
/// NOT invoke `which`/`command -v` (no shell, no exec).
pub fn host_tool_exists(fs: &dyn FilesystemProbe, name: &str) -> Option<PathBuf> {
    let dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"];
    for d in dirs {
        let p = Path::new(d).join(name);
        if let Ok(meta) = fs.metadata(&p) {
            if meta.is_executable() {
                return Some(p);
            }
        }
    }
    None
}

/// Host-side EFI vars directory reachable?
pub fn host_efivars_path<'a>() -> &'a Path {
    Path::new("/sys/firmware/efi/efivars")
}
