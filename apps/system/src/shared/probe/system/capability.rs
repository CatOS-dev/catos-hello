//! Capability detection. Each capability is computed from facts (paths
//! exist, tools resolvable, runtime environment signals) and carries the
//! evidence trail behind it. None of these probes actually performs the
//! operation they describe (no mount, no write, no exec).

use std::path::Path;

use crate::shared::model::capability::{Capability, CapabilityKind, CapabilityStatus};
use crate::shared::model::evidence::Evidence;
use crate::shared::probe::fs_probe::FilesystemProbe;
use crate::shared::probe::target::{
    host_efivars_path, host_tool_exists, probe_target_tool, target_read_to_string,
};
use crate::shared::system_root::SystemRoot;

/// Snapshot of the current process's effective privileges that capability
/// probes need. Captured once at the start of [`detect_capabilities`] so we
/// do not repeat syscalls and so unit tests can inject a fixture.
#[derive(Debug, Clone, Copy)]
pub struct ProcCaps {
    pub euid: u32,
    /// True iff `CAP_SYS_ADMIN` is in the effective set. None when we could
    /// not determine it (e.g. /proc/self/status unreadable).
    pub cap_sys_admin: Option<bool>,
}

impl ProcCaps {
    /// Read from the running process via libc + /proc/self/status.
    pub fn from_current_process() -> Self {
        let euid = unsafe { libc_geteuid() };
        let cap_sys_admin = read_cap_sys_admin();
        ProcCaps {
            euid,
            cap_sys_admin,
        }
    }

    /// Test fixture.
    #[cfg(test)]
    pub fn for_test(euid: u32, cap_sys_admin: Option<bool>) -> Self {
        ProcCaps {
            euid,
            cap_sys_admin,
        }
    }
}

fn read_cap_sys_admin() -> Option<bool> {
    // /proc/self/status is the portable, no-dependency source of CapEff.
    // Layout: "CapEff:\t<hex-mask>". Bit 21 (1 << 21) is CAP_SYS_ADMIN per
    // linux/capability.h.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let trimmed = rest.trim();
            let mask = u64::from_str_radix(trimmed, 16).ok()?;
            const CAP_SYS_ADMIN_BIT: u64 = 1 << 21;
            return Some(mask & CAP_SYS_ADMIN_BIT != 0);
        }
    }
    None
}

/// Tiny libc shim. We avoid pulling `libc` as a crate dep for one symbol;
/// the musl symbol table is stable.
///
/// # Safety
/// `geteuid(2)` is async-signal-safe and takes no arguments.
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

/// Compute every phase-1 capability in a canonical order. The order is fixed
/// so JSON output and human output are stable.
pub fn detect_capabilities(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Vec<Capability> {
    let caps = ProcCaps::from_current_process();
    vec![
        read_target_root(fs, root),
        read_proc(fs),
        read_sysfs(fs),
        read_block_sysfs(fs),
        access_dev(fs),
        shell_available(fs),
        mount_operations_possible(fs, &caps),
        write_efivars_possible(fs, &caps),
        systemd_available(fs),
        pacman_present_in_target(fs, root),
        mkinitcpio_present_in_target(fs, root),
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
    let probe_path = root.join("etc/os-release");
    match target_read_to_string(fs, root, "etc/os-release") {
        Ok(_) => available(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_READABLE",
                probe_path.display().to_string(),
                "successfully read a file under the target root",
            )],
        ),
        Err(crate::shared::error::FsError::PermissionDenied) => unavailable(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_PERMISSION_DENIED",
                probe_path.display().to_string(),
                "permission denied reading a file under the target root",
            )],
        ),
        Err(crate::shared::error::FsError::NotFound) => match fs.metadata(root.canonical_path()) {
            Ok(metadata) if metadata.is_dir => available(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_ACCESSIBLE_NO_OS_RELEASE",
                    root.as_str(),
                    "target root directory is readable (no os-release present)",
                )],
            ),
            Ok(_) => unavailable(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_NOT_DIRECTORY",
                    root.as_str(),
                    "target root is not a directory",
                )],
            ),
            Err(error) => unknown(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_STATUS_UNKNOWN",
                    root.as_str(),
                    format!("target root readability cannot be confirmed: {error}"),
                )],
            ),
        },
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
        Err(crate::shared::error::FsError::PermissionDenied) => unavailable(
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

fn shell_available(fs: &dyn FilesystemProbe) -> Capability {
    // Phase 1 does NOT spawn anything. We probe whether a shell binary
    // exists with the exec bit set. This is a necessary (not sufficient)
    // condition for shell-driven recovery scripts.
    let candidates = [Path::new("/usr/bin/sh"), Path::new("/bin/sh")];
    for c in candidates {
        match fs.metadata(c) {
            Ok(m) if m.is_executable() => {
                return available(
                    CapabilityKind::ShellAvailable,
                    vec![Evidence::new(
                        "SHELL_EXECUTABLE",
                        c.display().to_string(),
                        "shell binary exists with exec bit",
                    )],
                );
            }
            Ok(m) => {
                // exists but not executable
                return unavailable(
                    CapabilityKind::ShellAvailable,
                    vec![Evidence::new(
                        "SHELL_NOT_EXECUTABLE",
                        c.display().to_string(),
                        "shell binary exists but is not executable",
                    )
                    .with_value(format!("mode={:#o}", m.mode))],
                );
            }
            // File-not-found: try next candidate.
            Err(crate::shared::error::FsError::NotFound) => continue,
            // Permission denied / I/O error: cannot decide.
            Err(e) => {
                return unknown(
                    CapabilityKind::ShellAvailable,
                    vec![Evidence::new(
                        "SHELL_STAT_FAILED",
                        c.display().to_string(),
                        format!("unexpected error checking shell: {e}"),
                    )],
                );
            }
        }
    }
    unavailable(
        CapabilityKind::ShellAvailable,
        vec![Evidence::new(
            "NO_SHELL_FOUND",
            "/usr/bin/sh, /bin/sh",
            "no shell binary found in standard locations",
        )],
    )
}

fn mount_operations_possible(fs: &dyn FilesystemProbe, caps: &ProcCaps) -> Capability {
    let mut evidence = Vec::new();

    let mount_tool = host_tool_exists(fs, "mount");
    match &mount_tool {
        Some(p) => evidence.push(Evidence::new(
            "MOUNT_TOOL_RESOLVED",
            p.display().to_string(),
            "mount(8) tool resolved on host PATH",
        )),
        None => {
            evidence.push(Evidence::new(
                "MOUNT_TOOL_NOT_RESOLVED",
                "host PATH",
                "mount(8) tool not found on host PATH",
            ));
            return unavailable(CapabilityKind::MountOperationsPossible, evidence);
        }
    }

    evidence.push(
        Evidence::new("EUID", "geteuid(2)", "effective user id of this process")
            .with_value(caps.euid.to_string()),
    );

    match caps.cap_sys_admin {
        Some(true) => {
            evidence.push(Evidence::new(
                "CAP_SYS_ADMIN_PRESENT",
                "/proc/self/status CapEff",
                "CAP_SYS_ADMIN is in the effective set; mount operations are permitted in the current namespace",
            ));
            available(CapabilityKind::MountOperationsPossible, evidence)
        }
        Some(false) => {
            evidence.push(Evidence::new(
                "CAP_SYS_ADMIN_ABSENT",
                "/proc/self/status CapEff",
                "CAP_SYS_ADMIN is not in the effective set; mount(2) will fail",
            ));
            unavailable(CapabilityKind::MountOperationsPossible, evidence)
        }
        None => {
            evidence.push(Evidence::new(
                "CAP_SYS_ADMIN_UNKNOWN",
                "/proc/self/status",
                "could not read CapEff; cannot determine mount permission",
            ));
            unknown(CapabilityKind::MountOperationsPossible, evidence)
        }
    }
}

fn write_efivars_possible(fs: &dyn FilesystemProbe, caps: &ProcCaps) -> Capability {
    let p = host_efivars_path();
    // Phase 1: NEVER write. We only check that efivarfs appears mounted AND
    // the process holds CAP_SYS_ADMIN, which is required to actually write
    // EFI variables. Writability itself is not probed (would require a
    // write).
    let meta = match fs.metadata(p) {
        Ok(m) => m,
        Err(crate::shared::error::FsError::NotFound) => {
            return unavailable(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_NOT_MOUNTED",
                    p.display().to_string(),
                    "efivarfs path does not exist; efivarfs not mounted?",
                )],
            );
        }
        Err(crate::shared::error::FsError::PermissionDenied) => {
            return unknown(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_PERMISSION_DENIED",
                    p.display().to_string(),
                    "permission denied stat'ing efivarfs; cannot determine state",
                )],
            );
        }
        Err(e) => {
            return unknown(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_STAT_FAILED",
                    p.display().to_string(),
                    format!("unexpected error stat'ing efivarfs: {e}"),
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
                "efivarfs path exists but is not a directory",
            )],
        );
    }
    // efivarfs is mounted. Now require CAP_SYS_ADMIN: writes to efivarfs
    // require it regardless of file permissions. Without it the answer is
    // positively Unavailable, not Unknown.
    match caps.cap_sys_admin {
        Some(false) => unavailable(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new(
                    "EFIVARS_MOUNTED",
                    p.display().to_string(),
                    "efivarfs appears mounted",
                ),
                Evidence::new(
                    "CAP_SYS_ADMIN_ABSENT",
                    "/proc/self/status CapEff",
                    "CAP_SYS_ADMIN not in effective set; writes to efivarfs require it",
                ),
            ],
        ),
        Some(true) => unknown(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new(
                    "EFIVARS_MOUNTED",
                    p.display().to_string(),
                    "efivarfs appears mounted",
                ),
                Evidence::new(
                    "CAP_SYS_ADMIN_PRESENT",
                    "/proc/self/status CapEff",
                    "CAP_SYS_ADMIN in effective set; writability not probed \
                     (phase 1 is read-only)",
                ),
            ],
        ),
        None => unknown(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new(
                    "EFIVARS_MOUNTED",
                    p.display().to_string(),
                    "efivarfs appears mounted",
                ),
                Evidence::new(
                    "CAP_SYS_ADMIN_UNKNOWN",
                    "/proc/self/status",
                    "could not read CapEff; cannot determine efivarfs writability",
                ),
            ],
        ),
    }
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

fn target_tool_capability(
    fs: &dyn FilesystemProbe,
    root: &SystemRoot,
    kind: CapabilityKind,
    name: &str,
    rel: &str,
) -> Capability {
    let tool = probe_target_tool(fs, root, name, rel);
    Capability {
        name: kind,
        status: tool.status,
        evidence: tool.evidence,
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

#[cfg(test)]
mod tests {
    //! Capability fixture tests. These guard against the specific
    //! regressions the phase-1 review caught:
    //!   * `mount_operations_possible` returning Available to unprivileged
    //!     users;
    //!   * target tools reported missing when actually permission denied;
    //!   * efivars reported Available without CAP_SYS_ADMIN;
    //!   * shell presence treated as "can run external commands".
    //!
    //! Every test injects both a fake filesystem AND a fake ProcCaps so
    //! nothing depends on the host's actual privilege state.

    use super::*;
    use crate::shared::model::capability::CapabilityStatus;
    use crate::shared::probe::fs_probe::{FixtureFilesystem, MetaData};
    use crate::shared::system_root::SystemRoot;

    fn root() -> SystemRoot {
        SystemRoot::from_absolute_unchecked("/").unwrap()
    }

    fn exec_meta() -> MetaData {
        MetaData {
            ino: 0,
            dev: 0,
            mode: 0o755,
            is_dir: false,
            is_file: true,
            is_symlink: false,
        }
    }
    fn nonexec_meta() -> MetaData {
        MetaData {
            ino: 0,
            dev: 0,
            mode: 0o644,
            is_dir: false,
            is_file: true,
            is_symlink: false,
        }
    }
    fn dir_meta() -> MetaData {
        MetaData {
            ino: 0,
            dev: 0,
            mode: 0o755,
            is_dir: true,
            is_file: false,
            is_symlink: false,
        }
    }

    /// mount(8) available but CAP_SYS_ADMIN absent: unavailable regardless
    /// of EUID.
    #[test]
    fn mount_unavailable_for_unprivileged_user() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/mount", "")
            .with_meta("/usr/bin/mount", exec_meta())
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
            )
            .with_meta("/proc/self/mountinfo", nonexec_meta());
        let caps = ProcCaps::for_test(1000, Some(false));
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"CAP_SYS_ADMIN_ABSENT"));
    }

    /// mount(8) available, root rw, root + CAP_SYS_ADMIN: Available.
    #[test]
    fn mount_available_for_privileged_process() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/mount", "")
            .with_meta("/usr/bin/mount", exec_meta())
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
            )
            .with_meta("/proc/self/mountinfo", nonexec_meta());
        let caps = ProcCaps::for_test(0, Some(true));
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Available);
    }

    #[test]
    fn mount_available_for_nonroot_process_with_effective_capability() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/mount", "")
            .with_meta("/usr/bin/mount", exec_meta());
        let caps = ProcCaps::for_test(1000, Some(true));
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Available);
    }

    /// Root but CAP_SYS_ADMIN unknown (e.g. /proc/self/status unreadable):
    /// Unknown, not a guess.
    #[test]
    fn mount_unknown_when_caps_unreadable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/mount", "")
            .with_meta("/usr/bin/mount", exec_meta())
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
            )
            .with_meta("/proc/self/mountinfo", nonexec_meta());
        let caps = ProcCaps::for_test(0, None);
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unknown);
    }

    /// mount(8) missing on PATH: hard Unavailable regardless of privileges.
    #[test]
    fn mount_unavailable_when_tool_missing() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin");
        let caps = ProcCaps::for_test(0, Some(true));
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
    }

    /// Current root writability does not determine whether mount(2) is
    /// permitted in the current namespace.
    #[test]
    fn mount_available_even_when_current_root_is_readonly() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/mount", "")
            .with_meta("/usr/bin/mount", exec_meta())
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "1 0 8:1 / / ro,relatime - ext4 /dev/sda1 ro\n",
            )
            .with_meta("/proc/self/mountinfo", nonexec_meta());
        let caps = ProcCaps::for_test(0, Some(true));
        let cap = mount_operations_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Available);
    }

    /// pacman in target as an executable file: Available.
    #[test]
    fn pacman_present_in_target_executable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/pacman", "")
            .with_meta("/usr/bin/pacman", exec_meta());
        let cap = pacman_present_in_target(&fs, &root());
        assert_eq!(cap.status, CapabilityStatus::Available);
        assert_eq!(cap.name, CapabilityKind::PacmanPresentInTarget);
    }

    /// pacman in target as a non-executable file: Unavailable, evidence
    /// records "not executable".
    #[test]
    fn pacman_present_but_not_executable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/pacman", "")
            .with_meta("/usr/bin/pacman", nonexec_meta());
        let cap = pacman_present_in_target(&fs, &root());
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"TARGET_TOOL_NOT_EXECUTABLE"));
    }

    /// pacman missing in target: hard Unavailable with TARGET_TOOL_MISSING.
    #[test]
    fn pacman_missing_in_target() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin");
        let cap = pacman_present_in_target(&fs, &root());
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"TARGET_TOOL_MISSING"));
    }

    /// Permission denied stat'ing pacman: Unknown, not Absent. This is
    /// critical: a doctor tool that reports "pacman missing" when the truth
    /// is "permission denied" would mislead recovery.
    #[test]
    fn pacman_permission_denied_is_unknown() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .unreadable_dir("/usr/bin");
        let cap = pacman_present_in_target(&fs, &root());
        assert_eq!(cap.status, CapabilityStatus::Unknown);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"TARGET_TOOL_PERMISSION_DENIED"));
    }

    /// mkinitcpio probe uses the same code path as pacman; smoke-test
    /// that it defaults to Unavailable when missing.
    #[test]
    fn mkinitcpio_default_unavailable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin");
        assert_eq!(
            mkinitcpio_present_in_target(&fs, &root()).status,
            CapabilityStatus::Unavailable
        );
    }

    /// efivars path missing: hard Unavailable.
    #[test]
    fn efivars_unavailable_when_not_mounted() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/sys")
            .dir("/sys/firmware");
        let caps = ProcCaps::for_test(0, Some(true));
        let cap = write_efivars_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"EFIVARS_NOT_MOUNTED"));
    }

    /// efivars mounted but process lacks CAP_SYS_ADMIN: Unavailable.
    #[test]
    fn efivars_unavailable_without_cap_sys_admin() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/sys")
            .dir("/sys/firmware")
            .dir("/sys/firmware/efi")
            .dir("/sys/firmware/efi/efivars")
            .with_meta("/sys/firmware/efi/efivars", dir_meta());
        let caps = ProcCaps::for_test(1000, Some(false));
        let cap = write_efivars_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"CAP_SYS_ADMIN_ABSENT"));
    }

    /// efivars mounted + CAP_SYS_ADMIN: Unknown (we don't probe writability
    /// in phase 1).
    #[test]
    fn efivars_unknown_when_cap_sys_admin_present() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/sys")
            .dir("/sys/firmware")
            .dir("/sys/firmware/efi")
            .dir("/sys/firmware/efi/efivars")
            .with_meta("/sys/firmware/efi/efivars", dir_meta());
        let caps = ProcCaps::for_test(0, Some(true));
        let cap = write_efivars_possible(&fs, &caps);
        assert_eq!(cap.status, CapabilityStatus::Unknown);
    }

    /// Shell at /usr/bin/sh, executable: Available.
    #[test]
    fn shell_available_at_usr_bin() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/sh", "")
            .with_meta("/usr/bin/sh", exec_meta());
        let cap = shell_available(&fs);
        assert_eq!(cap.status, CapabilityStatus::Available);
        assert_eq!(cap.name, CapabilityKind::ShellAvailable);
    }

    /// Shell exists but is not executable: Unavailable (not Unknown, because
    /// we positively observed the file).
    #[test]
    fn shell_present_but_not_executable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .file("/usr/bin/sh", "")
            .with_meta("/usr/bin/sh", nonexec_meta())
            .dir("/bin");
        let cap = shell_available(&fs);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
    }

    /// No shell in standard locations: Unavailable with NO_SHELL_FOUND.
    #[test]
    fn shell_missing_is_unavailable() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/usr")
            .dir("/usr/bin")
            .dir("/bin");
        let cap = shell_available(&fs);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
        let codes: Vec<&str> = cap.evidence.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"NO_SHELL_FOUND"));
    }

    /// systemd run dir present: Available.
    #[test]
    fn systemd_available_via_run_dir() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/run")
            .dir("/run/systemd")
            .dir("/run/systemd/system")
            .with_meta("/run/systemd/system", dir_meta());
        let cap = systemd_available(&fs);
        assert_eq!(cap.status, CapabilityStatus::Available);
    }

    /// systemd run dir absent: Unavailable.
    #[test]
    fn systemd_unavailable_when_run_dir_absent() {
        let fs = FixtureFilesystem::new().dir("/").dir("/run");
        let cap = systemd_available(&fs);
        assert_eq!(cap.status, CapabilityStatus::Unavailable);
    }
}
