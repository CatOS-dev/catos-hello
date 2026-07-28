//! Chroot namespace, session-root, and read-only probe lifecycle.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::BlockDevice;
use catos_mount::execute::secure_dir::{create_session_dir, SESSION_ROOT_PARENT};
use catos_mount::plan::session::FstypePolicy;
use catos_process::trusted_tool_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChrootNamespace {
    pub evidence: Vec<String>,
}

/// Enter a private mount namespace before any Chroot probe or execution mount.
pub fn establish_private_namespace() -> Result<ChrootNamespace, String> {
    let setup = catos_mount::execute::namespace::establish_private_namespace()
        .map_err(|error| error.to_string())?;
    Ok(ChrootNamespace {
        evidence: setup.evidence,
    })
}

pub struct ChrootSessionRoot {
    path: PathBuf,
    cleaned: bool,
}

impl ChrootSessionRoot {
    pub fn create() -> Result<Self, String> {
        let parent = Path::new(SESSION_ROOT_PARENT);
        let path = create_session_dir(parent, "chroot").map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cleanup(mut self) -> Result<(), String> {
        let result = remove_empty_session_root(&self.path);
        if result.is_ok() {
            self.cleaned = true;
        }
        result
    }
}

impl Drop for ChrootSessionRoot {
    fn drop(&mut self) {
        if !self.cleaned {
            // Never recurse through a path that may still be a mountpoint.
            let _ = remove_empty_session_root(&self.path);
        }
    }
}

fn remove_empty_session_root(path: &Path) -> Result<(), String> {
    let parent = Path::new(SESSION_ROOT_PARENT);
    if path.parent() != Some(parent) {
        return Err(format!(
            "refusing to remove chroot session {} outside {}",
            path.display(),
            parent.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing to remove symlinked chroot session {}",
            path.display()
        )),
        Ok(metadata) if !metadata.is_dir() => Err(format!(
            "refusing to remove non-directory chroot session {}",
            path.display()
        )),
        Ok(_) => std::fs::remove_dir(path).map_err(|error| {
            format!(
                "cannot remove empty chroot session {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect chroot session {}: {error}",
            path.display()
        )),
    }
}

/// Temporary read-only mount used only by Chroot diagnosis.
pub struct ReadOnlyMountProbe {
    root: Option<ChrootSessionRoot>,
    mounted: bool,
}

impl ReadOnlyMountProbe {
    pub fn open(device: &BlockDevice, options: &[String]) -> Result<Self, String> {
        let root = ChrootSessionRoot::create()?;
        let mount = trusted_tool_path("mount")
            .ok_or_else(|| "mount not found in trusted system directories".to_string())?;
        let readonly_options = read_only_mount_options(device, options)?;
        let status = Command::new(mount)
            .arg("-o")
            .arg(readonly_options.join(","))
            .arg(&device.name)
            .arg(root.path())
            .status()
            .map_err(|error| format!("failed to spawn read-only probe mount: {error}"))?;
        if !status.success() {
            let path = root.path().display().to_string();
            let _ = root.cleanup();
            return Err(format!(
                "read-only probe mount of {} at {path} exited with status {status}",
                device.name
            ));
        }
        Ok(Self {
            root: Some(root),
            mounted: true,
        })
    }

    pub fn path(&self) -> &Path {
        self.root
            .as_ref()
            .expect("read-only probe path requested after cleanup")
            .path()
    }

    pub fn cleanup(&mut self) -> Result<(), String> {
        let Some(root) = self.root.take() else {
            return Ok(());
        };
        if self.mounted {
            let unmount_result = (|| {
                let umount = trusted_tool_path("umount")
                    .ok_or_else(|| "umount not found in trusted system directories".to_string())?;
                let status = Command::new(umount)
                    .arg(root.path())
                    .status()
                    .map_err(|error| format!("failed to spawn read-only probe umount: {error}"))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "read-only probe umount exited with status {status}"
                    ))
                }
            })();
            if let Err(error) = unmount_result {
                self.root = Some(root);
                return Err(error);
            }
            self.mounted = false;
        }
        root.cleanup()
    }
}

impl Drop for ReadOnlyMountProbe {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Compose the mandatory read-only/no-replay policy with probe-specific
/// selectors such as `subvolid=5`.
pub fn read_only_mount_options(
    device: &BlockDevice,
    probe_options: &[String],
) -> Result<Vec<String>, String> {
    let fstype = device
        .fs_type
        .as_deref()
        .ok_or_else(|| format!("device {} has no filesystem type", device.name))?
        .to_ascii_lowercase();
    let mut options = vec!["ro".to_string()];
    match FstypePolicy::for_fstype(&fstype) {
        FstypePolicy::Safe {
            options: no_replay, ..
        } => options.extend(no_replay.into_iter().map(str::to_string)),
        FstypePolicy::Refused { reason, .. } => {
            return Err(format!(
                "filesystem {fstype} on {} is not safe for read-only diagnosis: {reason}",
                device.name
            ))
        }
    }
    for option in probe_options {
        if !options.contains(option) {
            options.push(option.clone());
        }
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch_path(label: &str) -> PathBuf {
        Path::new(SESSION_ROOT_PARENT).join(format!(
            "chroot-session-test-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    #[ignore = "requires root and the trusted /run/catos-system mount namespace"]
    fn empty_session_cleanup_never_recurses() {
        catos_mount::execute::secure_dir::validate_trusted_root_chain().unwrap();
        let path = scratch_path("empty");
        std::fs::create_dir(&path).unwrap();
        remove_empty_session_root(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    #[ignore = "requires root and the trusted /run/catos-system mount namespace"]
    fn nonempty_session_cleanup_is_refused() {
        catos_mount::execute::secure_dir::validate_trusted_root_chain().unwrap();
        let path = scratch_path("nonempty");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sentinel"), b"preserve").unwrap();
        assert!(remove_empty_session_root(&path).is_err());
        assert!(path.join("sentinel").exists());
        std::fs::remove_file(path.join("sentinel")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
}
