//! Authorised Chroot effects.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::{
    BlockDevice, ChrootExecutionOutcome, ChrootExecutionReport, ChrootPlan, ChrootRuntimeMount,
};
use crate::verify::verify_assembled_target;
use catos_mount::execute::syscall::{self, ms_flags};
use catos_process::trusted_tool_path;
use catos_target::execute::confined::open_rooted_directory_pub;
use catos_target::execute::luks;

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
    fn mount_runtime(
        &mut self,
        session_root: &Path,
        runtime: ChrootRuntimeMount,
    ) -> Result<(), String>;
    fn read_mountinfo(&mut self) -> Result<String, String>;
    fn enter(&mut self, root: &Path, use_systemd_chroot: bool) -> Result<(), String>;
    fn unmount(&mut self, target: &Path) -> Result<(), String>;
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

    fn mount_runtime(
        &mut self,
        session_root: &Path,
        runtime: ChrootRuntimeMount,
    ) -> Result<(), String> {
        let mount_point = runtime.mount_point();
        let directory =
            open_rooted_directory_pub(session_root, mount_point, true).map_err(|error| {
                format!("cannot prepare runtime mount point {mount_point}: {error}")
            })?;
        let target = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let result = match runtime {
            ChrootRuntimeMount::Proc => syscall::mount(
                Some("proc"),
                &target,
                Some("proc"),
                ms_flags::MS_NOSUID | ms_flags::MS_NOEXEC | ms_flags::MS_NODEV,
                None,
            ),
            ChrootRuntimeMount::Sys => syscall::mount(
                Some("sysfs"),
                &target,
                Some("sysfs"),
                ms_flags::MS_RDONLY
                    | ms_flags::MS_NOSUID
                    | ms_flags::MS_NOEXEC
                    | ms_flags::MS_NODEV,
                None,
            ),
            ChrootRuntimeMount::Dev | ChrootRuntimeMount::Run => {
                syscall::mount(Some(mount_point), &target, None, ms_flags::MS_BIND, None)
            }
        };
        result.map_err(|error| format!("runtime mount {mount_point} failed: {error}"))
    }

    fn read_mountinfo(&mut self) -> Result<String, String> {
        std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|error| format!("cannot read /proc/self/mountinfo: {error}"))
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

    fn unmount(&mut self, target: &Path) -> Result<(), String> {
        let umount = trusted_tool_path("umount")
            .ok_or_else(|| "umount not found in trusted system directories".to_string())?;
        let status = Command::new(umount)
            .arg("--")
            .arg(target)
            .status()
            .map_err(|error| format!("failed to spawn umount for {}: {error}", target.display()))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "umount of {} exited with status {status}",
                target.display()
            ))
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
            residual_paths: Vec::new(),
        };
    }
    mounted_paths.push(session_root.to_path_buf());

    for mount in &plan.mounts {
        let target = target_path(session_root, &mount.mount_point);
        if let Err(error) = effects.mount(
            &mount.device,
            session_root,
            &mount.mount_point,
            &mount.options,
        ) {
            return finish_with_cleanup(
                ChrootExecutionOutcome::MountFailed,
                Some(error),
                mounted_paths,
                effects,
            );
        }
        mounted_paths.push(target);
    }

    for runtime in ChrootRuntimeMount::ALL {
        let target = target_path(session_root, runtime.mount_point());
        if let Err(error) = effects.mount_runtime(session_root, runtime) {
            return finish_with_cleanup(
                ChrootExecutionOutcome::MountFailed,
                Some(error),
                mounted_paths,
                effects,
            );
        }
        mounted_paths.push(target);
    }

    let mountinfo = match effects.read_mountinfo() {
        Ok(mountinfo) => mountinfo,
        Err(error) => {
            return finish_with_cleanup(
                ChrootExecutionOutcome::VerificationFailed,
                Some(error),
                mounted_paths,
                effects,
            );
        }
    };
    let verification = verify_assembled_target(session_root, plan, &mountinfo);
    if !verification.ready {
        return finish_with_cleanup(
            ChrootExecutionOutcome::VerificationFailed,
            Some(verification.reasons.join("; ")),
            mounted_paths,
            effects,
        );
    }

    match effects.enter(session_root, plan.use_systemd_chroot) {
        Ok(()) => finish_with_cleanup(
            ChrootExecutionOutcome::Entered,
            None,
            mounted_paths,
            effects,
        ),
        Err(error) => finish_with_cleanup(
            ChrootExecutionOutcome::ShellFailed,
            Some(error),
            mounted_paths,
            effects,
        ),
    }
}

fn finish_with_cleanup<E: ChrootEffects>(
    outcome: ChrootExecutionOutcome,
    failure: Option<String>,
    mounted_paths: Vec<PathBuf>,
    effects: &mut E,
) -> ChrootExecutionReport {
    let mut residual_paths = Vec::new();
    let mut cleanup_errors = Vec::new();
    for target in mounted_paths.iter().rev() {
        if let Err(error) = effects.unmount(target) {
            residual_paths.push(target.clone());
            cleanup_errors.push(error);
        }
    }
    residual_paths.reverse();

    if cleanup_errors.is_empty() {
        ChrootExecutionReport {
            outcome,
            cleanup_complete: true,
            failure,
            mounted_paths,
            residual_paths,
        }
    } else {
        let cleanup_failure = format!(
            "cleanup failed for {}: {}",
            residual_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            cleanup_errors.join("; ")
        );
        ChrootExecutionReport {
            outcome: ChrootExecutionOutcome::CleanupIncomplete,
            cleanup_complete: false,
            failure: Some(match failure {
                Some(failure) => format!("{failure}; {cleanup_failure}"),
                None => cleanup_failure,
            }),
            mounted_paths,
            residual_paths,
        }
    }
}

fn target_path(root: &Path, mount_point: &str) -> PathBuf {
    if mount_point == "/" {
        root.to_path_buf()
    } else {
        root.join(mount_point.trim_start_matches('/'))
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
