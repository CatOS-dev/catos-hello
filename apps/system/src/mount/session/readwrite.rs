//! Target read-write mount session: the union of the btrfs top-level
//! RW session, a plain (non-btrfs) RW mount, and the running-root
//! no-mount session.
//!
//! The btrfs variant delegates to [`crate::mount::session::BtrfsTopLevelRwSession`],
//! which lives entirely inside the mount capability (no snapshot-engine
//! dependency). The plain and running-root variants are pure mount
//! (private namespace + confined directory + umount).

use std::path::{Path, PathBuf};

use crate::mount::execute::namespace;
use crate::mount::execute::secure_dir::{create_session_dir, remove_session_dir, SESSION_ROOT_PARENT};
use crate::mount::execute::syscall::{self, mnt_flags, ms_flags};
use crate::mount::session::BtrfsTopLevelRwSession;
use crate::snapshot::model::{CleanupSummary, SnapshotError, SnapshotErrorKind};

/// Production CLI entry point for an explicitly selected, unmounted
/// CatOS target. It mounts the storage root in a private session,
/// gathers target-local facts, and records actions only after they
/// have succeeded.
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
    ) -> Result<Self, SnapshotError> {
        if fstype == "btrfs" {
            BtrfsTopLevelRwSession::mount(device)
                .map(Self::Btrfs)
                .map_err(SnapshotError::from)
        } else if running_root {
            RunningRootSession::enter().map(Self::Running)
        } else {
            PlainRwSession::mount(device, fstype).map(Self::Plain)
        }
    }

    pub fn storage_root(&self) -> &Path {
        match self {
            TargetMountRwSession::Btrfs(session) => session.top_level_mount(),
            TargetMountRwSession::Plain(session) => &session.mount_root,
            TargetMountRwSession::Running(session) => &session.root,
        }
    }

    pub fn target_root(&self) -> PathBuf {
        match self {
            TargetMountRwSession::Btrfs(session) => session.top_level_mount().join("@"),
            TargetMountRwSession::Plain(session) => session.mount_root.clone(),
            TargetMountRwSession::Running(session) => session.root.clone(),
        }
    }

    pub fn cleanup(&mut self) -> CleanupSummary {
        match self {
            TargetMountRwSession::Btrfs(session) => session.cleanup().into(),
            TargetMountRwSession::Plain(session) => session.cleanup(),
            TargetMountRwSession::Running(session) => session.cleanup(),
        }
    }
}

/// A writable target mount held exclusively for boot repair. Unlike
/// the CLI apply path, constructing this session never plans or
/// applies fstab/subvolume changes: it only mounts the
/// already-confirmed storage root.
pub struct RunningRootSession {
    root: PathBuf,
}

impl RunningRootSession {
    fn enter() -> Result<Self, SnapshotError> {
        namespace::establish_private_namespace().map_err(|error| {
            SnapshotError::new(
                SnapshotErrorKind::SyscallFailed,
                format!("cannot establish private namespace for running-root repair: {error}"),
            )
        })?;
        Ok(Self {
            root: PathBuf::from("/"),
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
        }
    }
}

pub struct PlainRwSession {
    session_dir: PathBuf,
    mount_root: PathBuf,
    mounted: bool,
}

impl PlainRwSession {
    fn mount(device: &Path, fstype: &str) -> Result<Self, SnapshotError> {
        namespace::establish_private_namespace().map_err(|error| {
            SnapshotError::new(
                SnapshotErrorKind::SyscallFailed,
                format!("cannot establish private mount namespace: {error}"),
            )
        })?;
        let session_dir = create_session_dir(Path::new(SESSION_ROOT_PARENT), "mount-repair-rw")?;
        let mount_root = session_dir.join("root");
        std::fs::create_dir(&mount_root).map_err(|error| {
            SnapshotError::new(
                SnapshotErrorKind::SessionDirectoryNotSecure,
                format!("cannot create plain-root mountpoint: {error}"),
            )
        })?;
        let source = device.to_str().ok_or_else(|| {
            SnapshotError::new(
                SnapshotErrorKind::SyscallFailed,
                "plain root device path is not UTF-8",
            )
        })?;
        if let Err(error) = syscall::mount(
            Some(source),
            &mount_root,
            Some(fstype),
            ms_flags::MS_NOSUID | ms_flags::MS_NODEV,
            None,
        ) {
            let _ = remove_session_dir(Path::new(SESSION_ROOT_PARENT), &session_dir);
            return Err(SnapshotError::new(
                SnapshotErrorKind::SyscallFailed,
                format!("cannot mount plain target root read-write: {error}"),
            ));
        }
        Ok(Self {
            session_dir,
            mount_root,
            mounted: true,
        })
    }

    fn cleanup(&mut self) -> CleanupSummary {
        let mut summary = CleanupSummary {
            unmounted: Vec::new(),
            residual: Vec::new(),
            all_clean: true,
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
                summary.residual.push(error.message.to_string());
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
