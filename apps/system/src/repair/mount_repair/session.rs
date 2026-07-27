//! Low-level read-write mount sessions for mount repair.

use std::path::{Path, PathBuf};

use crate::recovery::RecoveryRwSession;
use crate::shared::model::recovery::{CleanupSummary, RecoveryError, RecoveryErrorKind};
use crate::shared::mount::namespace;
use crate::shared::mount::syscall::{self, ms_flags};


/// Production CLI entry point for an explicitly selected, unmounted CatOS
/// Btrfs target. It mounts the Btrfs top level in a private session, gathers
/// target-local facts, and records actions only after they have succeeded.
pub(super) enum MountRepairRwSession {
    Btrfs(crate::recovery::RecoveryRwSession),
    Plain(PlainRwSession),
    Running(RunningRootSession),
}

impl MountRepairRwSession {
    pub(super) fn mount(device: &Path, fstype: &str, running_root: bool) -> Result<Self, RecoveryError> {
        if fstype == "btrfs" {
            crate::recovery::RecoveryRwSession::mount(device).map(Self::Btrfs)
        } else if running_root {
            RunningRootSession::enter().map(Self::Running)
        } else {
            PlainRwSession::mount(device, fstype).map(Self::Plain)
        }
    }

    pub(super) fn storage_root(&self) -> &Path {
        match self {
            MountRepairRwSession::Btrfs(session) => session.top_level_mount(),
            MountRepairRwSession::Plain(session) => &session.mount_root,
            MountRepairRwSession::Running(session) => &session.root,
        }
    }

    pub(super) fn target_root(&self) -> PathBuf {
        match self {
            MountRepairRwSession::Btrfs(session) => session.top_level_mount().join("@"),
            MountRepairRwSession::Plain(session) => session.mount_root.clone(),
            MountRepairRwSession::Running(session) => session.root.clone(),
        }
    }

    pub(super) fn cleanup(&mut self) -> CleanupSummary {
        match self {
            MountRepairRwSession::Btrfs(session) => session.cleanup(),
            MountRepairRwSession::Plain(session) => session.cleanup(),
            MountRepairRwSession::Running(session) => session.cleanup(),
        }
    }
}

/// A writable target mount held exclusively for boot repair.  Unlike
/// `run_mount_repair_via_cli`, constructing this session never plans or
/// applies fstab/subvolume changes: it only mounts the already-confirmed
pub(super) struct RunningRootSession {
    root: PathBuf,
}

impl RunningRootSession {
    fn enter() -> Result<Self, RecoveryError> {
        namespace::establish_private_namespace().map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
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

pub(super) struct PlainRwSession {
    session_dir: PathBuf,
    mount_root: PathBuf,
    mounted: bool,
}

impl PlainRwSession {
    fn mount(device: &Path, fstype: &str) -> Result<Self, RecoveryError> {
        namespace::establish_private_namespace().map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
                format!("cannot establish private mount namespace: {error}"),
            )
        })?;
        let session_dir = crate::shared::mount::secure_dir::create_session_dir(
            Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
            "mount-repair-rw",
        )?;
        let mount_root = session_dir.join("root");
        std::fs::create_dir(&mount_root).map_err(|error| {
            RecoveryError::new(
                RecoveryErrorKind::SessionDirectoryNotSecure,
                format!("cannot create plain-root mountpoint: {error}"),
            )
        })?;
        let source = device.to_str().ok_or_else(|| {
            RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
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
            let _ = crate::shared::mount::secure_dir::remove_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                &session_dir,
            );
            return Err(RecoveryError::new(
                RecoveryErrorKind::SyscallFailed,
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
                    let _ = syscall::umount2(
                        &self.mount_root,
                        crate::shared::mount::syscall::mnt_flags::MNT_DETACH,
                    );
                    summary
                        .residual
                        .push(format!("{}: {error}", self.mount_root.display()));
                    summary.all_clean = false;
                }
            }
        }
        if !self.mounted {
            if let Err(error) = crate::shared::mount::secure_dir::remove_session_dir(
                Path::new(crate::shared::mount::secure_dir::SESSION_ROOT_PARENT),
                &self.session_dir,
            ) {
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

