//! Capability detection. Each capability is computed from facts (paths
//! exist, tools resolvable, runtime environment signals) and carries the
//! evidence trail behind it. None of these probes actually performs the
//! operation they describe (no mount, no write, no exec).

use std::path::Path;

use crate::model::capability::{Capability, CapabilityKind, CapabilityStatus};
use crate::model::evidence::Evidence;
use crate::probe::fs_probe::FilesystemProbe;
use crate::probe::target::{host_efivars_path, host_tool_exists};
use crate::system_root::SystemRoot;

/// Compute every phase-1 capability in a canonical order. The order is fixed
/// so JSON output and human output are stable.
pub fn detect_capabilities(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Vec<Capability> {
    vec![
        read_target_root(fs, root),
        read_proc(fs),
        read_sysfs(fs),
        read_block_sysfs(fs),
        access_dev(fs),
        run_external_commands(fs),
        mount_operations_possible(fs),
        write_efivars_possible(fs),
        systemd_available(fs),
        pacman_present_in_target(fs, root),
        mkinitcpio_present_in_target(fs, root),
        bootloadu_present_in_target(fs, root),
        tool_available(fs, CapabilityKind::BtrfsToolAvailable, "btrfs"),
        tool_available(fs, CapabilityKind::CryptsetupAvailable, "cryptsetup"),
        tool_available(fs, CapabilityKind::LsblkAvailable, "lsblk"),
        tool_available(fs, CapabilityKind::MountToolAvailable, "mount"),
    ]
}

fn available(name: CapabilityKind, evidence: Vec<Evidence>) -> Capability {
    Capability {
        name,
        status: CapabilityStatus::Available,
        evidence,
    }
}

fn unavailable(name: CapabilityKind, evidence: Vec<Evidence>) -> Capability {
    Capability {
        name,
        status: CapabilityStatus::Unavailable,
        evidence,
    }
}

fn unknown(name: CapabilityKind, evidence: Vec<Evidence>) -> Capability {
    Capability {
        name,
        status: CapabilityStatus::Unknown,
        evidence,
    }
}

fn read_target_root(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Capability {
    // Reading the os-release file as the litmus test: if we can read one
    // regular file under the target root, the root is readable.
    let probe_path = root.join("etc/os-release");
    match fs.read_to_string(&probe_path) {
        Ok(_) => available(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_READABLE",
                probe_path.display().to_string(),
                "successfully read a file under the target root",
            )],
        ),
        Err(crate::error::FsError::PermissionDenied) => unavailable(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_PERMISSION_DENIED",
                probe_path.display().to_string(),
                "permission denied reading a file under the target root",
            )],
        ),
        Err(crate::error::FsError::NotFound) => {
            // No os-release: still readable, just no os-release installed.
            // Try the directory itself.
            if fs.is_dir(root.as_path()) {
                available(
                    CapabilityKind::ReadTargetRoot,
                    vec![Evidence::new(
                        "TARGET_ROOT_ACCESSIBLE_NO_OS_RELEASE",
                        root.as_str(),
                        "target root is a readable directory (no os-release present)",
                    )],
                )
            } else {
                unknown(
                    CapabilityKind::ReadTargetRoot,
                    vec![Evidence::new(
                        "TARGET_ROOT_STATUS_UNKNOWN",
                        root.as_str(),
                        "target root exists but readability cannot be confirmed",
                    )],
                )
            }
        }
        Err(e) => unknown(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_READ_FAILED",
                probe_path.display().to_string(),
                format!("unexpected error reading target root: {e}"),
            )],
        ),
    }
}

fn read_proc(fs: &dyn FilesystemProbe) -> Capability {
    let p = Path::new("/proc");
    if !fs.is_dir(p) {
        return unknown(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_NOT_MOUNTED",
                "/proc",
                "/proc is not a readable directory; procfs not mounted?",
            )],
        );
    }
    // Confirm we can actually read content, not just stat the dir.
    match fs.read_to_string(Path::new("/proc/self/comm")) {
        Ok(_) => available(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_READABLE",
                "/proc/self/comm",
                "successfully read a procfs entry",
            )],
        ),
        Err(crate::error::FsError::PermissionDenied) => unavailable(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_PERMISSION_DENIED",
                "/proc/self/comm",
                "permission denied reading procfs",
            )],
        ),
        Err(e) => unknown(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_READ_FAILED",
                "/proc/self/comm",
                format!("unexpected error reading procfs: {e}"),
            )],
        ),
    }
}

fn read_sysfs(fs: &dyn FilesystemProbe) -> Capability {
    let p = Path::new("/sys");
    if !fs.is_dir(p) {
        return unknown(
            CapabilityKind::ReadSysfs,
            vec![Evidence::new(
                "SYSFS_NOT_MOUNTED",
                "/sys",
                "/sys is not a readable directory; sysfs not mounted?",
            )],
        );
    }
    available(
        CapabilityKind::ReadSysfs,
        vec![Evidence::new(
            "SYSFS_PRESENT",
            "/sys",
            "/sys directory exists and is readable",
        )],
    )
}

fn read_block_sysfs(fs: &dyn FilesystemProbe) -> Capability {
    let p = Path::new("/sys/class/block");
    if !fs.is_dir(p) {
        return unavailable(
            CapabilityKind::ReadBlockSysfs,
            vec![Evidence::new(
                "BLOCK_SYSFS_MISSING",
                "/sys/class/block",
                "/sys/class/block not present; block device sysfs unavailable",
            )],
        );
    }
    available(
        CapabilityKind::ReadBlockSysfs,
        vec![Evidence::new(
            "BLOCK_SYSFS_PRESENT",
            "/sys/class/block",
            "/sys/class/block exists and is readable",
        )],
    )
}

fn access_dev(fs: &dyn FilesystemProbe) -> Capability {
    let p = Path::new("/dev");
    if !fs.is_dir(p) {
        return unknown(
            CapabilityKind::AccessDev,
            vec![Evidence::new(
                "DEV_NOT_PRESENT",
                "/dev",
                "/dev is not a readable directory",
            )],
        );
    }
    available(
        CapabilityKind::AccessDev,
        vec![Evidence::new(
            "DEV_PRESENT",
            "/dev",
            "/dev directory exists and is readable",
        )],
    )
}

fn run_external_commands(fs: &dyn FilesystemProbe) -> Capability {
    // Phase 1 does NOT spawn anything. We check whether /bin/sh (or /usr/bin/sh)
    // exists with an exec bit; that's a necessary (not sufficient) condition.
    let candidates = [Path::new("/usr/bin/sh"), Path::new("/bin/sh")];
    for c in candidates {
        if let Ok(m) = fs.metadata(c) {
            if m.is_executable() {
                return available(
                    CapabilityKind::RunExternalCommands,
                    vec![Evidence::new(
                        "SHELL_EXECUTABLE",
                        c.display().to_string(),
                        "shell binary exists with exec bit; execve appears available",
                    )],
                );
            }
        }
    }
    unknown(
        CapabilityKind::RunExternalCommands,
        vec![Evidence::new(
            "NO_SHELL_FOUND",
            "/usr/bin/sh, /bin/sh",
            "no executable shell found; cannot determine exec capability",
        )],
    )
}

fn mount_operations_possible(fs: &dyn FilesystemProbe) -> Capability {
    // Plausible if `mount` tool is resolvable AND we are NOT inside an
    // initramfs where /proc/self/mountinfo shows the root as read-only
    // AND there is no global lockdown.
    let mount_tool = host_tool_exists(fs, "mount");
    let mut evidence = Vec::new();
    if let Some(p) = &mount_tool {
        evidence.push(Evidence::new(
            "MOUNT_TOOL_RESOLVED",
            p.display().to_string(),
            "mount(8) tool resolved on host PATH",
        ));
    } else {
        evidence.push(Evidence::new(
            "MOUNT_TOOL_NOT_RESOLVED",
            "host PATH",
            "mount(8) tool not found on host PATH",
        ));
        return unavailable(CapabilityKind::MountOperationsPossible, evidence);
    }

    // Check whether mountinfo shows root as read-only: if so, environment
    // may not allow new mounts (typical of locked-down systems).
    match fs.read_to_string(Path::new("/proc/self/mountinfo")) {
        Ok(mi) => {
            let root_ro = mi.lines().any(|line| {
                line.split_once(" - ").is_some_and(|(l, _)| {
                    let mut parts = l.split_whitespace();
                    let _ = parts.next();
                    let _ = parts.next();
                    let _ = parts.next();
                    let _ = parts.next();
                    let mount_point = parts.next().unwrap_or("");
                    let options = parts.next().unwrap_or("");
                    mount_point == "/" && options.split(',').any(|o| o == "ro")
                })
            });
            if root_ro {
                evidence.push(Evidence::new(
                    "ROOT_MOUNTED_READ_ONLY",
                    "/proc/self/mountinfo",
                    "root is mounted read-only; mount operations may be restricted",
                ));
                // This is environmental context, not a hard no. Mark Unknown:
                // we cannot reliably determine whether the kernel would permit
                // new mounts in this context.
                return unknown(CapabilityKind::MountOperationsPossible, evidence);
            }
            evidence.push(Evidence::new(
                "ROOT_MOUNTED_READ_WRITE",
                "/proc/self/mountinfo",
                "root is mounted read-write; environment appears permissive",
            ));
            available(CapabilityKind::MountOperationsPossible, evidence)
        }
        Err(_) => {
            evidence.push(Evidence::new(
                "MOUNTINFO_UNREADABLE",
                "/proc/self/mountinfo",
                "cannot read mountinfo; cannot assess mount permission state",
            ));
            unknown(CapabilityKind::MountOperationsPossible, evidence)
        }
    }
}

fn write_efivars_possible(fs: &dyn FilesystemProbe) -> Capability {
    let p = host_efivars_path();
    // Phase 1: NEVER write. We only check that efivarfs appears mounted.
    let meta = match fs.metadata(p) {
        Ok(m) => m,
        Err(_) => {
            return unavailable(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_NOT_ACCESSIBLE",
                    p.display().to_string(),
                    "efivarfs path is not accessible; EFI variables not writable",
                )],
            );
        }
    };
    if !meta.is_dir {
        return unavailable(
            CapabilityKind::WriteEfivarsPossible,
            vec![Evidence::new(
                "EFIVARS_NOT_A_DIRECTORY",
                p.display().to_string(),
                "efivarfs path is not a directory",
            )],
        );
    }
    // We can determine "mounted" but not "writable" without trying to write.
    // Phase 1 does not write, so we can only say it looks possible.
    unknown(
        CapabilityKind::WriteEfivarsPossible,
        vec![Evidence::new(
            "EFIVARS_MOUNTED",
            p.display().to_string(),
            "efivarfs appears mounted; writability not probed (phase 1 is read-only)",
        )],
    )
}

fn systemd_available(fs: &dyn FilesystemProbe) -> Capability {
    // Runtime systemd detection: /run/systemd/system/ is the canonical marker.
    if fs.is_dir(Path::new("/run/systemd/system")) {
        available(
            CapabilityKind::SystemdAvailable,
            vec![Evidence::new(
                "SYSTEMD_RUN_DIR_PRESENT",
                "/run/systemd/system",
                "systemd runtime marker directory exists; systemd is PID 1",
            )],
        )
    } else {
        unavailable(
            CapabilityKind::SystemdAvailable,
            vec![Evidence::new(
                "SYSTEMD_RUN_DIR_ABSENT",
                "/run/systemd/system",
                "systemd runtime marker directory missing",
            )],
        )
    }
}

fn pacman_present_in_target(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Capability {
    target_tool_capability(
        fs,
        root,
        CapabilityKind::PacmanPresentInTarget,
        "pacman",
        "usr/bin/pacman",
    )
}

fn mkinitcpio_present_in_target(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Capability {
    target_tool_capability(
        fs,
        root,
        CapabilityKind::MkinitcpioPresentInTarget,
        "mkinitcpio",
        "usr/bin/mkinitcpio",
    )
}

fn bootloadu_present_in_target(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Capability {
    target_tool_capability(
        fs,
        root,
        CapabilityKind::BootloaduPresentInTarget,
        "bootloadu",
        "usr/bin/bootloadu",
    )
}

fn target_tool_capability(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    kind: CapabilityKind,
    name: &str,
    rel: &str,
) -> Capability {
    let path = root.join(rel);
    match fs.metadata(&path) {
        Ok(m) if m.is_file && m.is_executable() => available(
            kind,
            vec![Evidence::new(
                "TARGET_TOOL_EXECUTABLE",
                path.display().to_string(),
                format!("{name} exists in target root and is executable"),
            )],
        ),
        Ok(_) => unavailable(
            kind,
            vec![Evidence::new(
                "TARGET_TOOL_NOT_EXECUTABLE",
                path.display().to_string(),
                format!("{name} exists in target root but is not an executable file"),
            )],
        ),
        Err(crate::error::FsError::NotFound) => unavailable(
            kind,
            vec![Evidence::new(
                "TARGET_TOOL_MISSING",
                path.display().to_string(),
                format!("{name} not found in target root"),
            )],
        ),
        Err(crate::error::FsError::PermissionDenied) => unknown(
            kind,
            vec![Evidence::new(
                "TARGET_TOOL_PERMISSION_DENIED",
                path.display().to_string(),
                format!("permission denied checking {name} in target root"),
            )],
        ),
        Err(e) => unknown(
            kind,
            vec![Evidence::new(
                "TARGET_TOOL_CHECK_FAILED",
                path.display().to_string(),
                format!("unexpected error checking {name}: {e}"),
            )],
        ),
    }
}

fn tool_available(fs: &dyn FilesystemProbe, kind: CapabilityKind, name: &str) -> Capability {
    match host_tool_exists(fs, name) {
        Some(p) => available(
            kind,
            vec![Evidence::new(
                "HOST_TOOL_RESOLVED",
                p.display().to_string(),
                format!("{name} resolved on host PATH"),
            )],
        ),
        None => unavailable(
            kind,
            vec![Evidence::new(
                "HOST_TOOL_MISSING",
                "host PATH",
                format!("{name} not found on host PATH"),
            )],
        ),
    }
}
