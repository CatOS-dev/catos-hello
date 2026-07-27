//! Authorised Chroot effects.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::chroot::model::{
    BlockDevice, ChrootExecutionOutcome, ChrootExecutionReport, ChrootPlan,
};
use crate::chroot::verify::verify_target_root;
use crate::mount::execute::syscall;
use crate::shared::process::trusted_tool_path;
use crate::target::execute::confined::open_rooted_directory_pub;
use crate::target::execute::luks;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChrootPrivilegeEvidence {
    EffectiveUid(u32),
    ExplicitNonRootOverride,
}

#[derive(Debug, Clone, Copy)]
pub struct ChrootAuthorization {
    _private: (),
}

pub fn authorize(evidence: ChrootPrivilegeEvidence) -> Result<ChrootAuthorization, String> {
    match evidence {
        ChrootPrivilegeEvidence::EffectiveUid(0)
        | ChrootPrivilegeEvidence::ExplicitNonRootOverride => {
            Ok(ChrootAuthorization { _private: () })
        }
        ChrootPrivilegeEvidence::EffectiveUid(uid) => Err(format!(
            "effective uid {uid} is not authorised for chroot assembly"
        )),
    }
}

pub trait ChrootEffects {
    fn mount(
        &mut self,
        device: &BlockDevice,
        session_root: &Path,
        mount_point: &str,
        options: &[String],
    ) -> Result<(), String>;
    fn enter(&mut self, root: &Path, use_systemd_chroot: bool) -> Result<(), String>;
    fn unmount_recursive(&mut self, root: &Path) -> Result<(), String>;
}

pub struct SystemChrootEffects;

impl ChrootEffects for SystemChrootEffects {
    fn mount(
        &mut self,
        device: &BlockDevice,
        session_root: &Path,
        mount_point: &str,
        options: &[String],
    ) -> Result<(), String> {
        let directory;
        let target = if mount_point == "/" {
            session_root.to_path_buf()
        } else {
            directory =
                open_rooted_directory_pub(session_root, mount_point, true).map_err(|error| {
                    format!("cannot prepare target mount point {mount_point}: {error}")
                })?;
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        };
        let fstype = device
            .fs_type
            .as_deref()
            .ok_or_else(|| format!("device {} has no filesystem type", device.name))?;
        let data = (!options.is_empty()).then(|| options.join(","));
        syscall::mount(
            Some(&device.name),
            &target,
            Some(fstype),
            0,
            data.as_deref(),
        )
        .map_err(|error| {
            format!(
                "mount of {} at {} failed: {error}",
                device.name, mount_point
            )
        })
    }

    fn enter(&mut self, root: &Path, use_systemd_chroot: bool) -> Result<(), String> {
        let arch_chroot = trusted_tool_path("arch-chroot")
            .ok_or_else(|| "arch-chroot not found in trusted system directories".to_string())?;
        let mut command = Command::new(arch_chroot);
        if use_systemd_chroot {
            command.arg("-S");
        }
        let status = command
            .arg(root)
            .status()
            .map_err(|error| format!("failed to run arch-chroot: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("arch-chroot exited with status {status}"))
        }
    }

    fn unmount_recursive(&mut self, root: &Path) -> Result<(), String> {
        let umount = trusted_tool_path("umount")
            .ok_or_else(|| "umount not found in trusted system directories".to_string())?;
        let status = Command::new(umount)
            .arg("-R")
            .arg(root)
            .status()
            .map_err(|error| format!("failed to spawn umount: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("umount exited with status {status}"))
        }
    }
}

pub fn execute_plan<E: ChrootEffects>(
    plan: &ChrootPlan,
    _authorization: ChrootAuthorization,
    session_root: &Path,
    effects: &mut E,
) -> ChrootExecutionReport {
    let mut mounted_paths = Vec::new();

    if let Err(error) = effects.mount(
        &plan.root.device,
        session_root,
        &plan.root.mount_point,
        &plan.root.options,
    ) {
        return ChrootExecutionReport {
            outcome: ChrootExecutionOutcome::MountFailed,
            cleanup_complete: true,
            failure: Some(error),
            mounted_paths,
        };
    }
    mounted_paths.push(session_root.to_path_buf());

    for mount in &plan.mounts {
        let target = session_root.join(mount.mount_point.trim_start_matches('/'));
        if let Err(error) = effects.mount(
            &mount.device,
            session_root,
            &mount.mount_point,
            &mount.options,
        ) {
            return finish_with_cleanup(
                ChrootExecutionOutcome::MountFailed,
                error,
                session_root,
                mounted_paths,
                effects,
            );
        }
        mounted_paths.push(target);
    }

    let verification = verify_target_root(session_root);
    if !verification.ready {
        return finish_with_cleanup(
            ChrootExecutionOutcome::VerificationFailed,
            verification.reasons.join("; "),
            session_root,
            mounted_paths,
            effects,
        );
    }

    let shell_result = effects.enter(session_root, plan.use_systemd_chroot);
    match shell_result {
        Ok(()) => finish_success(session_root, mounted_paths, effects),
        Err(error) => finish_with_cleanup(
            ChrootExecutionOutcome::ShellFailed,
            error,
            session_root,
            mounted_paths,
            effects,
        ),
    }
}

fn finish_success<E: ChrootEffects>(
    session_root: &Path,
    mounted_paths: Vec<PathBuf>,
    effects: &mut E,
) -> ChrootExecutionReport {
    match effects.unmount_recursive(session_root) {
        Ok(()) => ChrootExecutionReport {
            outcome: ChrootExecutionOutcome::Entered,
            cleanup_complete: true,
            failure: None,
            mounted_paths,
        },
        Err(error) => ChrootExecutionReport {
            outcome: ChrootExecutionOutcome::CleanupIncomplete,
            cleanup_complete: false,
            failure: Some(error),
            mounted_paths,
        },
    }
}

fn finish_with_cleanup<E: ChrootEffects>(
    outcome: ChrootExecutionOutcome,
    failure: String,
    session_root: &Path,
    mounted_paths: Vec<PathBuf>,
    effects: &mut E,
) -> ChrootExecutionReport {
    match effects.unmount_recursive(session_root) {
        Ok(()) => ChrootExecutionReport {
            outcome,
            cleanup_complete: true,
            failure: Some(failure),
            mounted_paths,
        },
        Err(cleanup_error) => ChrootExecutionReport {
            outcome: ChrootExecutionOutcome::CleanupIncomplete,
            cleanup_complete: false,
            failure: Some(format!("{failure}; cleanup failed: {cleanup_error}")),
            mounted_paths,
        },
    }
}

pub struct OpenedLuks {
    uuid: String,
    mapper_path: PathBuf,
    closed: bool,
}

impl OpenedLuks {
    pub fn mapper_path(&self) -> &Path {
        &self.mapper_path
    }

    pub fn close(mut self) -> Result<(), String> {
        let result = luks::close(&self.uuid);
        if result.is_ok() {
            self.closed = true;
        }
        result
    }
}

impl Drop for OpenedLuks {
    fn drop(&mut self) {
        if !self.closed {
            let _ = luks::close(&self.uuid);
        }
    }
}

pub fn open_luks(
    device: &BlockDevice,
    _authorization: ChrootAuthorization,
) -> Result<OpenedLuks, String> {
    let uuid = device
        .uuid
        .clone()
        .ok_or_else(|| format!("LUKS device {} has no UUID", device.name))?;
    let mapper = luks::mapper_name(&uuid)?;
    luks::open(&device.name, Some(&uuid))?;
    Ok(OpenedLuks {
        uuid,
        mapper_path: PathBuf::from("/dev/mapper").join(mapper),
        closed: false,
    })
}
