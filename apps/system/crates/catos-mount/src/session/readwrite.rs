//! Target read-write mount session. All errors and cleanup data are owned by
//! the Mount capability; applications translate them into their domain model.

use std::path::{Path, PathBuf};

use crate::execute::namespace;
use crate::execute::secure_dir::{create_session_dir, remove_session_dir, SESSION_ROOT_PARENT};
use crate::execute::syscall::{self, mnt_flags, ms_flags};
use crate::model::CleanupSummary;
use crate::session::cleanup::{MountSessionError, MountSessionErrorKind};
use crate::session::BtrfsTopLevelRwSession;

pub enum TargetMountRwSession {
    Btrfs(BtrfsTopLevelRwSession),
    Plain(PlainRwSession),
    Running(RunningRootSession),
}

impl TargetMountRwSession {
    pub fn mount(
        device: &Path,
        fstype: &str,
        running_root: bool,
    ) -> Result<Self, MountSessionError> {
        if fstype == "btrfs" {
            BtrfsTopLevelRwSession::mount(device).map(Self::Btrfs)
        } else if running_root {
            RunningRootSession::enter().map(Self::Running)
        } else {
            PlainRwSession::mount(device, fstype).map(Self::Plain)
        }
    }

    pub fn storage_root(&self) -> &Path {
        match self {
            Self::Btrfs(session) => session.top_level_mount(),
            Self::Plain(session) => &session.mount_root,
            Self::Running(session) => &session.root,
        }
    }

    pub fn target_root(&self) -> PathBuf {
        match self {
            Self::Btrfs(session) => session.top_level_mount().join("@"),
            Self::Plain(session) => session.mount_root.clone(),
            Self::Running(session) => session.root.clone(),
        }
    }

    pub fn cleanup(&mut self) -> CleanupSummary {
        match self {
            Self::Btrfs(session) => session.cleanup().into(),
            Self::Plain(session) => session.cleanup(),
            Self::Running(session) => session.cleanup(),
        }
    }
}

pub struct RunningRootSession {
    root: PathBuf,
}

impl RunningRootSession {
    fn enter() -> Result<Self, MountSessionError> {
        namespace::establish_private_namespace().map_err(|error| MountSessionError {
            kind: MountSessionErrorKind::NamespaceUnavailable,
            message: format!("cannot establish private namespace for running-root repair: {error}"),
            errno: Some(error.errno),
        })?;
        Ok(Self {
            root: PathBuf::from("/"),
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        CleanupSummary {
            all_clean: true,
            ..CleanupSummary::default()
        }
    }
}

pub struct PlainRwSession {
    session_dir: PathBuf,
    mount_root: PathBuf,
    mounted: bool,
}

impl PlainRwSession {
    fn mount(device: &Path, fstype: &str) -> Result<Self, MountSessionError> {
        namespace::establish_private_namespace().map_err(|error| MountSessionError {
            kind: MountSessionErrorKind::NamespaceUnavailable,
            message: format!("cannot establish private mount namespace: {error}"),
            errno: Some(error.errno),
        })?;
        let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "mount-repair-rw")?;
        let mount_root = session_dir.join("root");
        if let Err(error) = std::fs::create_dir(&mount_root) {
            let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
            return Err(MountSessionError {
                kind: MountSessionErrorKind::SessionDirectoryNotSecure,
                message: format!("cannot create plain-root mountpoint: {error}"),
                errno: error.raw_os_error(),
            });
        }
        let Some(source) = device.to_str() else {
            let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
            return Err(MountSessionError {
                kind: MountSessionErrorKind::InvalidDevicePath,
                message: "plain root device path is not UTF-8".into(),
                errno: None,
            });
        };
        if let Err(error) = syscall::mount(
            Some(source),
            &mount_root,
            Some(fstype),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            None,
        ) {
            let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
            return Err(MountSessionError {
                kind: MountSessionErrorKind::MountFailed,
                message: format!("cannot mount plain target root read-write: {error}"),
                errno: Some(error.errno),
            });
        }
        Ok(Self {
            session_dir,
            mount_root,
            mounted: true,
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        let mut summary = CleanupSummary {
            all_clean: true,
            ..CleanupSummary::default()
        };
        if self.mounted {
            match syscall::umount2(&self.mount_root, 0) {
                Ok(()) => {
                    summary
                        .unmounted
                        .push(self.mount_root.display().to_string());
                    self.mounted = false;
                }
                Err(error) => {
                    let _ = syscall::umount2(&self.mount_root, mnt_flags::MNT_DETACH);
                    summary
                        .residual
                        .push(format!("{}: {error}", self.mount_root.display()));
                    summary.all_clean = false;
                }
            }
        }
        if !self.mounted {
            if let Err(error) =
                remove_session_dir(Path::new(SESSION_ROOT_PARENT), &self.session_dir)
            {
                summary.residual.push(error.message);
                summary.all_clean = false;
            }
        }
        summary
    }
}

impl Drop for PlainRwSession {
    fn drop(&mut self) {
        if self.mounted {
            let _ = self.cleanup();
        }
    }
}
