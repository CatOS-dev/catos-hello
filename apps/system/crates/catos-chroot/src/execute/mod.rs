//! Authorised Chroot effects.

use std::io::{BufRead, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::{
    BlockDevice, ChrootExecutionOutcome, ChrootExecutionReport, ChrootPlan, ChrootRuntimeMount,
    ChrootVerification,
};
use crate::verify::verify_assembled_target;
use catos_mount::execute::syscall::{self, ms_flags};
use catos_process::trusted_tool_path;
use catos_target::execute::confined::{
    open_rooted_directory_pub, remove_empty_rooted_directory, rooted_path_kind, RootedPathKind,
};
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
    fn confirm_unverified(&mut self, _verification: &ChrootVerification) -> Result<bool, String> {
        Ok(false)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChrootExecutionPolicy {
    pub allow_unverified: bool,
}

pub struct SystemChrootEffects;

struct PreparedMountpoint<'a> {
    session_root: &'a Path,
    directory: Option<std::os::fd::OwnedFd>,
    created_directories: Vec<String>,
}

impl PreparedMountpoint<'_> {
    fn target(&self) -> PathBuf {
        self.directory.as_ref().map_or_else(
            || self.session_root.to_path_buf(),
            |directory| PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())),
        )
    }

    fn fail(mut self, failure: String) -> String {
        self.directory.take();
        match rollback_created_directories(self.session_root, &self.created_directories) {
            Ok(()) => failure,
            Err(cleanup) => format!("{failure}; mount-point rollback failed: {cleanup}"),
        }
    }
}

fn prepare_mountpoint<'a>(
    session_root: &'a Path,
    mount_point: &str,
) -> Result<PreparedMountpoint<'a>, String> {
    if mount_point == "/" {
        return Ok(PreparedMountpoint {
            session_root,
            directory: None,
            created_directories: Vec::new(),
        });
    }
    let created_directories = missing_rooted_directories(session_root, mount_point)?;
    let directory = match open_rooted_directory_pub(session_root, mount_point, true) {
        Ok(directory) => directory,
        Err(error) => {
            let failure = format!("cannot prepare target mount point {mount_point}: {error}");
            return match rollback_created_directories(session_root, &created_directories) {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(format!("{failure}; mount-point rollback failed: {cleanup}")),
            };
        }
    };
    Ok(PreparedMountpoint {
        session_root,
        directory: Some(directory),
        created_directories,
    })
}

fn missing_rooted_directories(
    session_root: &Path,
    mount_point: &str,
) -> Result<Vec<String>, String> {
    use std::path::Component;

    let path = Path::new(mount_point);
    if !path.is_absolute() {
        return Err(format!("mount point {mount_point:?} is not absolute"));
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(component) => Some(Ok(component.to_string_lossy().into_owned())),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => Some(Err(format!(
                "mount point {mount_point:?} contains a dot, parent, or prefix component"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut missing = false;
    let mut current = String::new();
    let mut created = Vec::new();
    for component in components {
        current.push('/');
        current.push_str(&component);
        if missing {
            created.push(current.clone());
            continue;
        }
        match rooted_path_kind(session_root, &current) {
            Ok(Some(RootedPathKind::Directory)) => {}
            Ok(None) | Err(catos_target::error::FsError::NotFound) => {
                missing = true;
                created.push(current.clone());
            }
            Ok(Some(RootedPathKind::Symlink)) => {
                return Err(format!("mount point component {current} is a symlink"));
            }
            Ok(Some(RootedPathKind::RegularFile | RootedPathKind::Other)) => {
                return Err(format!(
                    "mount point component {current} is not a directory"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect mount point component {current}: {error}"
                ));
            }
        }
    }
    Ok(created)
}

fn rollback_created_directories(
    session_root: &Path,
    created_directories: &[String],
) -> Result<(), String> {
    let mut failures = Vec::new();
    for directory in created_directories.iter().rev() {
        if let Err(error) = remove_empty_rooted_directory(session_root, directory) {
            failures.push(format!("{directory}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

impl ChrootEffects for SystemChrootEffects {
    fn mount(
        &mut self,
        device: &BlockDevice,
        session_root: &Path,
        mount_point: &str,
        options: &[String],
    ) -> Result<(), String> {
        let fstype = device
            .fs_type
            .as_deref()
            .ok_or_else(|| format!("device {} has no filesystem type", device.name))?;
        let prepared = prepare_mountpoint(session_root, mount_point)?;
        let target = prepared.target();
        let data = (!options.is_empty()).then(|| options.join(","));
        match syscall::mount(
            Some(&device.name),
            &target,
            Some(fstype),
            0,
            data.as_deref(),
        ) {
            Ok(()) => Ok(()),
            Err(error) => Err(prepared.fail(format!(
                "mount of {} at {} failed: {error}",
                device.name, mount_point
            ))),
        }
    }

    fn mount_runtime(
        &mut self,
        session_root: &Path,
        runtime: ChrootRuntimeMount,
    ) -> Result<(), String> {
        let mount_point = runtime.mount_point();
        let prepared = prepare_mountpoint(session_root, mount_point)?;
        let target = prepared.target();
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
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                Err(prepared.fail(format!("runtime mount {mount_point} failed: {error}")))
            }
        }
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

    fn confirm_unverified(&mut self, verification: &ChrootVerification) -> Result<bool, String> {
        eprintln!("catos-chroot: warning: target verification did not pass:");
        for reason in &verification.reasons {
            eprintln!("  - {reason}");
        }
        if !std::io::stdin().is_terminal() {
            return Ok(false);
        }
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut input = stdin.lock();
        let mut output = stdout.lock();
        loop {
            write!(output, "Enter the chroot anyway? [y/N] ")
                .map_err(|error| format!("cannot write continuation prompt: {error}"))?;
            output
                .flush()
                .map_err(|error| format!("cannot flush continuation prompt: {error}"))?;
            let mut line = String::new();
            let read = input
                .read_line(&mut line)
                .map_err(|error| format!("cannot read continuation response: {error}"))?;
            if read == 0 {
                return Ok(false);
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "" | "n" | "no" => return Ok(false),
                _ => eprintln!("catos-chroot: enter y or n"),
            }
        }
    }
}

pub fn execute_plan<E: ChrootEffects>(
    plan: &ChrootPlan,
    authorization: ChrootAuthorization,
    session_root: &Path,
    effects: &mut E,
) -> ChrootExecutionReport {
    execute_plan_with_policy(
        plan,
        authorization,
        session_root,
        effects,
        ChrootExecutionPolicy::default(),
    )
}

pub fn execute_plan_with_policy<E: ChrootEffects>(
    plan: &ChrootPlan,
    _authorization: ChrootAuthorization,
    session_root: &Path,
    effects: &mut E,
    policy: ChrootExecutionPolicy,
) -> ChrootExecutionReport {
    let mut mounted_paths = Vec::new();
    let mut warnings = Vec::new();

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
            warnings,
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
                warnings,
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
                warnings,
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
                warnings,
                effects,
            );
        }
    };
    let verification = verify_assembled_target(session_root, plan, &mountinfo);
    if !verification.ready {
        let continue_anyway = if policy.allow_unverified {
            true
        } else {
            match effects.confirm_unverified(&verification) {
                Ok(confirmed) => confirmed,
                Err(error) => {
                    return finish_with_cleanup(
                        ChrootExecutionOutcome::VerificationFailed,
                        Some(error),
                        mounted_paths,
                        warnings,
                        effects,
                    );
                }
            }
        };
        if !continue_anyway {
            return finish_with_cleanup(
                ChrootExecutionOutcome::VerificationFailed,
                Some(verification.reasons.join("; ")),
                mounted_paths,
                warnings,
                effects,
            );
        }
        warnings.push(format!(
            "entered chroot despite failed verification: {}",
            verification.reasons.join("; ")
        ));
    }

    match effects.enter(session_root, plan.use_systemd_chroot) {
        Ok(()) => finish_with_cleanup(
            ChrootExecutionOutcome::Entered,
            None,
            mounted_paths,
            warnings,
            effects,
        ),
        Err(error) => finish_with_cleanup(
            ChrootExecutionOutcome::ShellFailed,
            Some(error),
            mounted_paths,
            warnings,
            effects,
        ),
    }
}

fn finish_with_cleanup<E: ChrootEffects>(
    outcome: ChrootExecutionOutcome,
    failure: Option<String>,
    mounted_paths: Vec<PathBuf>,
    warnings: Vec<String>,
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
            warnings,
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
            warnings,
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

#[cfg(test)]
mod mountpoint_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "catos-chroot-mountpoint-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn failed_mountpoint_preparation_rolls_back_only_new_directories() {
        let root = scratch();
        std::fs::create_dir(root.join("boot")).unwrap();
        let created = missing_rooted_directories(&root, "/boot/efi/vendor").unwrap();
        assert_eq!(created, vec!["/boot/efi", "/boot/efi/vendor"]);
        catos_target::execute::confined::create_rooted_directory(&root, "/boot/efi/vendor")
            .unwrap();

        rollback_created_directories(&root, &created).unwrap();

        assert!(root.join("boot").is_dir());
        assert!(!root.join("boot/efi").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_reports_nonempty_created_directory() {
        let root = scratch();
        catos_target::execute::confined::create_rooted_directory(&root, "/boot/efi").unwrap();
        std::fs::write(root.join("boot/efi/keep"), b"data").unwrap();

        let error =
            rollback_created_directories(&root, &["/boot".into(), "/boot/efi".into()]).unwrap_err();
        assert!(error.contains("refusing to remove non-empty"));
        assert!(root.join("boot/efi/keep").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mountpoint_planning_refuses_intermediate_symlink() {
        let root = scratch();
        let outside = scratch();
        std::os::unix::fs::symlink(&outside, root.join("boot")).unwrap();
        assert!(missing_rooted_directories(&root, "/boot/efi").is_err());
        std::fs::remove_file(root.join("boot")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
