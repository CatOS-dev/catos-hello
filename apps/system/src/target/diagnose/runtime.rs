//! Runtime + capability detection (migrated from `shared::probe::system`).

use std::path::Path;

use crate::shared::error::FsError;
use crate::target::diagnose::filesystem::FilesystemProbe;
use crate::target::diagnose::system_root::SystemRoot;
use crate::target::model::{
    Capability, CapabilityKind, CapabilityStatus, Detection, DetectionStatus, RuntimeFacts,
};
use crate::shared::model::evidence::Evidence;

/// Re-export so callers can keep using the same flat name.
pub use crate::target::model::PrimaryRuntimeMode;

pub fn detect_runtime(fs: &dyn FilesystemProbe) -> RuntimeFacts {
    RuntimeFacts {
        is_initramfs: detect_initramfs(fs),
        is_chroot: detect_chroot(fs),
        is_live_environment: detect_live(fs),
        is_snapshot_boot: detect_snapshot_boot(fs),
        has_systemd: detect_systemd(fs),
        root_is_read_only: detect_root_read_only(fs),
    }
}

fn detect_initramfs(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();
    let initrd_release = Path::new("/etc/initrd-release");
    if fs.exists(initrd_release) {
        evidence.push(Evidence::new(
            "INITRD_RELEASE_PRESENT",
            "/etc/initrd-release",
            "initramfs marker file exists; canonical signal",
        ));
        return Detection::detected(evidence);
    }
    evidence.push(Evidence::new(
        "INITRD_RELEASE_ABSENT",
        "/etc/initrd-release",
        "initramfs marker file missing",
    ));
    if fs.is_dir(Path::new("/run/initramfs")) {
        evidence.push(Evidence::new(
            "INITRAMFS_RUN_DIR_PRESENT",
            "/run/initramfs",
            "initramfs run directory exists but marker file does not; ambiguous",
        ));
        return Detection::unknown(evidence);
    }
    Detection::not_detected(evidence)
}

fn detect_chroot(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();

    let root_meta = fs.metadata(Path::new("/"));
    let pid1_meta = fs.metadata(Path::new("/proc/1/root"));

    let (root_meta, pid1_meta) = match (root_meta, pid1_meta) {
        (Ok(r), Ok(p)) => (r, p),
        (Err(_), Err(_)) => {
            evidence.push(Evidence::new(
                "ROOT_AND_PROC_1_ROOT_UNREADABLE",
                "/ and /proc/1/root",
                "cannot stat either path; cannot determine chroot status",
            ));
            return Detection::unknown(evidence);
        }
        (Err(_), Ok(_)) => {
            evidence.push(Evidence::new(
                "ROOT_UNREADABLE",
                "/",
                "cannot stat current root; cannot determine chroot status",
            ));
            return Detection::unknown(evidence);
        }
        (Ok(_), Err(_)) => {
            evidence.push(Evidence::new(
                "PROC_1_ROOT_UNREADABLE",
                "/proc/1/root",
                "cannot stat PID 1 root (proc not mounted or no permission); cannot determine chroot status",
            ));
            return Detection::unknown(evidence);
        }
    };

    if root_meta.dev == pid1_meta.dev && root_meta.ino == pid1_meta.ino {
        evidence.push(
            Evidence::new(
                "ROOT_MATCHES_PROC_1_ROOT",
                "/ vs /proc/1/root",
                "current root shares dev/ino with PID 1 root; not in a chroot",
            )
            .with_value(format!("dev={:#x} ino={}", root_meta.dev, root_meta.ino)),
        );
        return Detection::not_detected(evidence);
    }

    evidence.push(
        Evidence::new(
            "ROOT_DIFFERS_FROM_PROC_1_ROOT",
            "/ vs /proc/1/root",
            "current root has different dev/ino than PID 1 root",
        )
        .with_value(format!(
            "root dev={:#x} ino={}; pid1 dev={:#x} ino={}",
            root_meta.dev, root_meta.ino, pid1_meta.dev, pid1_meta.ino
        )),
    );

    if has_container_markers(fs, &mut evidence) {
        evidence.push(Evidence::new(
            "CONTAINER_MARKERS_PRESENT",
            "/.dockerenv, /run/.containerenv, /proc/1/cgroup",
            "container markers detected; cannot reliably distinguish chroot from container runtime",
        ));
        return Detection::unknown(evidence);
    }

    evidence.push(Evidence::new(
        "CONTAINER_MARKERS_ABSENT",
        "/.dockerenv, /run/.containerenv, /proc/1/cgroup",
        "no container markers found; chroot is the most plausible explanation",
    ));
    Detection::detected(evidence)
}

fn has_container_markers(fs: &dyn FilesystemProbe, evidence: &mut Vec<Evidence>) -> bool {
    let mut hit = false;
    if fs.exists(Path::new("/.dockerenv")) {
        evidence.push(Evidence::new(
            "DOCKERENV_PRESENT",
            "/.dockerenv",
            "Docker container marker file exists",
        ));
        hit = true;
    }
    if fs.exists(Path::new("/run/.containerenv")) {
        evidence.push(Evidence::new(
            "CONTAINERENV_PRESENT",
            "/run/.containerenv",
            "Podman/containerenv marker file exists",
        ));
        hit = true;
    }
    if let Ok(cgroup) = fs.read_to_string(Path::new("/proc/1/cgroup")) {
        let lower = cgroup.to_ascii_lowercase();
        let markers = ["docker", "lxc", "kubepods", "containerd", "machined"];
        let found: Vec<&str> = markers
            .iter()
            .copied()
            .filter(|m| lower.contains(m))
            .collect();
        if !found.is_empty() {
            evidence.push(
                Evidence::new(
                    "CGROUP_CONTAINER_MARKER",
                    "/proc/1/cgroup",
                    "PID 1 cgroup contains container runtime marker",
                )
                .with_value(found.join(",")),
            );
            hit = true;
        }
    }
    hit
}

fn detect_live(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();

    if fs.is_dir(Path::new("/run/archiso")) {
        evidence.push(Evidence::new(
            "ARCHISO_RUN_DIR_PRESENT",
            "/run/archiso",
            "ArchISO/CatOS live run directory exists; canonical signal",
        ));
        return Detection::detected(evidence);
    }
    evidence.push(Evidence::new(
        "ARCHISO_RUN_DIR_ABSENT",
        "/run/archiso",
        "ArchISO/CatOS live run directory not present",
    ));

    let cmdline_path = Path::new("/proc/cmdline");
    match fs.read_to_string(cmdline_path) {
        Ok(cmdline) => {
            let trimmed = cmdline.trim();
            let lower = trimmed.to_ascii_lowercase();
            if lower.contains("archiso") {
                evidence.push(
                    Evidence::new(
                        "ARCHISO_CMDLINE_PRESENT",
                        "/proc/cmdline",
                        "kernel cmdline contains an archiso parameter",
                    )
                    .with_value(trimmed.to_string()),
                );
                return Detection::detected(evidence);
            }
            evidence.push(
                Evidence::new(
                    "CMDLINE_NO_ARCHISO",
                    "/proc/cmdline",
                    "kernel cmdline has no archiso parameter",
                )
                .with_value(trimmed.to_string()),
            );
            Detection::not_detected(evidence)
        }
        Err(FsError::NotFound) => {
            evidence.push(Evidence::new(
                "CMDLINE_FILE_MISSING",
                "/proc/cmdline",
                "/proc/cmdline does not exist; procfs not mounted. Cannot rule out Live environment without this evidence.",
            ));
            Detection::unknown(evidence)
        }
        Err(_) => {
            evidence.push(Evidence::new(
                "CMDLINE_UNREADABLE",
                "/proc/cmdline",
                "/proc/cmdline exists but could not be read (permission or I/O). Cannot rule out Live environment without this evidence.",
            ));
            Detection::unknown(evidence)
        }
    }
}

fn detect_snapshot_boot(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();

    let mountinfo = match fs.read_to_string(Path::new("/proc/self/mountinfo")) {
        Ok(s) => s,
        Err(_) => {
            evidence.push(Evidence::new(
                "MOUNTINFO_UNREADABLE",
                "/proc/self/mountinfo",
                "cannot read mountinfo; cannot determine snapshot status",
            ));
            return Detection::unknown(evidence);
        }
    };

    let Some(root_mount) = parse_root_mount(&mountinfo) else {
        evidence.push(Evidence::new(
            "ROOT_MOUNT_NOT_FOUND",
            "/proc/self/mountinfo",
            "could not identify the root mount entry",
        ));
        return Detection::unknown(evidence);
    };

    evidence.push(
        Evidence::new(
            "ROOT_MOUNT_INFO",
            "/proc/self/mountinfo",
            "root filesystem mount information",
        )
        .with_value(format!(
            "fstype={} options={}",
            root_mount.fstype, root_mount.options
        )),
    );

    if root_mount.fstype != "btrfs" {
        evidence.push(Evidence::new(
            "ROOT_NOT_BTRFS",
            "/proc/self/mountinfo",
            "root is not on btrfs; btrfs snapshot boot ruled out",
        ));
        return Detection::not_detected(evidence);
    }

    let mut found_snapshot_subvol = false;
    let mut found_any_subvol = false;
    for opt in root_mount
        .options
        .split(',')
        .chain(root_mount.super_opts.split(','))
    {
        if let Some(v) = opt.strip_prefix("subvol=") {
            found_any_subvol = true;
            if v.contains("snapshot") || v.contains(".snapshots") {
                found_snapshot_subvol = true;
                evidence.push(
                    Evidence::new(
                        "BTRFS_SNAPSHOT_SUBVOL",
                        "/proc/self/mountinfo",
                        "root subvolume path contains a snapshot marker",
                    )
                    .with_value(v.to_string()),
                );
            }
        }
    }

    if found_snapshot_subvol {
        return Detection::detected(evidence);
    }
    if found_any_subvol {
        evidence.push(Evidence::new(
            "BTRFS_SUBVOL_NO_SNAPSHOT_MARKER",
            "/proc/self/mountinfo",
            "root is btrfs with a subvol option but no snapshot path; cannot reliably classify",
        ));
        return Detection::unknown(evidence);
    }
    evidence.push(Evidence::new(
        "BTRFS_NO_SUBVOL_OPTION",
        "/proc/self/mountinfo",
        "root is btrfs without subvol option; cannot classify snapshot status",
    ));
    Detection::unknown(evidence)
}

fn detect_systemd(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();
    let marker = Path::new("/run/systemd/system");
    match fs.metadata(marker) {
        Ok(m) if m.is_dir => {
            evidence.push(Evidence::new(
                "SYSTEMD_RUN_DIR_PRESENT",
                "/run/systemd/system",
                "systemd runtime marker directory exists; systemd is PID 1",
            ));
            Detection::detected(evidence)
        }
        Ok(_) => {
            evidence.push(Evidence::new(
                "SYSTEMD_RUN_DIR_NOT_A_DIRECTORY",
                "/run/systemd/system",
                "marker path exists but is not a directory; not running systemd",
            ));
            Detection::not_detected(evidence)
        }
        Err(FsError::NotFound) => {
            evidence.push(Evidence::new(
                "SYSTEMD_RUN_DIR_ABSENT",
                "/run/systemd/system",
                "systemd runtime marker directory missing",
            ));
            Detection::not_detected(evidence)
        }
        Err(_) => {
            evidence.push(Evidence::new(
                "SYSTEMD_RUN_DIR_UNREADABLE",
                "/run/systemd/system",
                "marker path exists but stat returned an error (permission / I/O); cannot determine systemd runtime status",
            ));
            Detection::unknown(evidence)
        }
    }
}

fn detect_root_read_only(fs: &dyn FilesystemProbe) -> Detection {
    let mut evidence = Vec::new();

    let mountinfo = match fs.read_to_string(Path::new("/proc/self/mountinfo")) {
        Ok(s) => s,
        Err(_) => {
            evidence.push(Evidence::new(
                "MOUNTINFO_UNREADABLE",
                "/proc/self/mountinfo",
                "cannot read mountinfo; cannot determine root write status",
            ));
            return Detection::unknown(evidence);
        }
    };

    let Some(root_mount) = parse_root_mount(&mountinfo) else {
        evidence.push(Evidence::new(
            "ROOT_MOUNT_NOT_FOUND",
            "/proc/self/mountinfo",
            "could not identify the root mount entry",
        ));
        return Detection::unknown(evidence);
    };

    let is_ro = root_mount.options.split(',').any(|o| o == "ro");
    evidence.push(
        Evidence::new(
            "ROOT_MOUNT_OPTIONS",
            "/proc/self/mountinfo",
            "root mount options observed",
        )
        .with_value(root_mount.options.clone()),
    );
    if is_ro {
        Detection::detected(evidence)
    } else {
        Detection::not_detected(evidence)
    }
}

#[derive(Debug, Clone)]
struct RootMount {
    options: String,
    fstype: String,
    super_opts: String,
}

fn parse_root_mount(mountinfo: &str) -> Option<RootMount> {
    for raw in mountinfo.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let mut left_parts = left.split_whitespace();
        let _id = left_parts.next()?;
        let _parent = left_parts.next()?;
        let _dev = left_parts.next()?;
        let _root_in_fs = left_parts.next()?;
        let mount_point = left_parts.next()?;
        let options = left_parts.next()?;
        if mount_point != "/" {
            continue;
        }
        let mut right_parts = right.split_whitespace();
        let fstype = right_parts.next().unwrap_or("").to_string();
        let _source = right_parts.next().unwrap_or("").to_string();
        let super_opts = right_parts.next().unwrap_or("").to_string();
        return Some(RootMount {
            options: options.to_string(),
            fstype,
            super_opts,
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Capability detection (migrated from probe/system/capability.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ProcCaps {
    pub euid: u32,
    pub cap_sys_admin: Option<bool>,
}

impl ProcCaps {
    pub fn from_current_process() -> Self {
        let euid = unsafe { libc_geteuid() };
        let cap_sys_admin = read_cap_sys_admin();
        ProcCaps { euid, cap_sys_admin }
    }

    #[cfg(test)]
    pub fn for_test(euid: u32, cap_sys_admin: Option<bool>) -> Self {
        ProcCaps { euid, cap_sys_admin }
    }
}

fn read_cap_sys_admin() -> Option<bool> {
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

unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

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

fn read_target_root(fs: &dyn FilesystemProbe, root: &SystemRoot) -> Capability {
    let probe_path = root.join("etc/os-release");
    match crate::target::diagnose::candidate::target_read_to_string(fs, root, "etc/os-release") {
        Ok(_) => Capability::available(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_READABLE",
                probe_path.display().to_string(),
                "successfully read a file under the target root",
            )],
        ),
        Err(FsError::PermissionDenied) => Capability::unavailable(
            CapabilityKind::ReadTargetRoot,
            vec![Evidence::new(
                "TARGET_ROOT_PERMISSION_DENIED",
                probe_path.display().to_string(),
                "permission denied reading a file under the target root",
            )],
        ),
        Err(FsError::NotFound) => match fs.metadata(root.canonical_path()) {
            Ok(metadata) if metadata.is_dir => Capability::available(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_ACCESSIBLE_NO_OS_RELEASE",
                    root.as_str(),
                    "target root directory is readable (no os-release present)",
                )],
            ),
            Ok(_) => Capability::unavailable(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_NOT_DIRECTORY",
                    root.as_str(),
                    "target root is not a directory",
                )],
            ),
            Err(error) => Capability::unknown(
                CapabilityKind::ReadTargetRoot,
                vec![Evidence::new(
                    "TARGET_ROOT_STATUS_UNKNOWN",
                    root.as_str(),
                    format!("target root readability cannot be confirmed: {error}"),
                )],
            ),
        },
        Err(e) => Capability::unknown(
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
        return Capability::unknown(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_NOT_MOUNTED",
                "/proc",
                "/proc is not a readable directory; procfs not mounted?",
            )],
        );
    }
    match fs.read_to_string(Path::new("/proc/self/comm")) {
        Ok(_) => Capability::available(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_READABLE",
                "/proc/self/comm",
                "successfully read a procfs entry",
            )],
        ),
        Err(FsError::PermissionDenied) => Capability::unavailable(
            CapabilityKind::ReadProc,
            vec![Evidence::new(
                "PROC_PERMISSION_DENIED",
                "/proc/self/comm",
                "permission denied reading procfs",
            )],
        ),
        Err(e) => Capability::unknown(
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
        return Capability::unknown(
            CapabilityKind::ReadSysfs,
            vec![Evidence::new(
                "SYSFS_NOT_MOUNTED",
                "/sys",
                "/sys is not a readable directory; sysfs not mounted?",
            )],
        );
    }
    Capability::available(
        CapabilityKind::ReadSysfs,
        vec![Evidence::new("SYSFS_PRESENT", "/sys", "/sys directory exists and is readable")],
    )
}

fn read_block_sysfs(fs: &dyn FilesystemProbe) -> Capability {
    let p = Path::new("/sys/class/block");
    if !fs.is_dir(p) {
        return Capability::unavailable(
            CapabilityKind::ReadBlockSysfs,
            vec![Evidence::new(
                "BLOCK_SYSFS_MISSING",
                "/sys/class/block",
                "/sys/class/block not present; block device sysfs unavailable",
            )],
        );
    }
    Capability::available(
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
        return Capability::unknown(
            CapabilityKind::AccessDev,
            vec![Evidence::new("DEV_NOT_PRESENT", "/dev", "/dev is not a readable directory")],
        );
    }
    Capability::available(
        CapabilityKind::AccessDev,
        vec![Evidence::new("DEV_PRESENT", "/dev", "/dev directory exists and is readable")],
    )
}

fn shell_available(fs: &dyn FilesystemProbe) -> Capability {
    let candidates = [Path::new("/usr/bin/sh"), Path::new("/bin/sh")];
    for c in candidates {
        match fs.metadata(c) {
            Ok(m) if m.is_executable() => {
                return Capability::available(
                    CapabilityKind::ShellAvailable,
                    vec![Evidence::new(
                        "SHELL_EXECUTABLE",
                        c.display().to_string(),
                        "shell binary exists with exec bit",
                    )],
                );
            }
            Ok(m) => {
                return Capability::unavailable(
                    CapabilityKind::ShellAvailable,
                    vec![Evidence::new(
                        "SHELL_NOT_EXECUTABLE",
                        c.display().to_string(),
                        "shell binary exists but is not executable",
                    )
                    .with_value(format!("mode={:#o}", m.mode))],
                );
            }
            Err(FsError::NotFound) => continue,
            Err(e) => {
                return Capability::unknown(
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
    Capability::unavailable(
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

    let mount_tool = crate::target::diagnose::candidate::host_tool_exists(fs, "mount");
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
            return Capability::unavailable(CapabilityKind::MountOperationsPossible, evidence);
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
            Capability::available(CapabilityKind::MountOperationsPossible, evidence)
        }
        Some(false) => {
            evidence.push(Evidence::new(
                "CAP_SYS_ADMIN_ABSENT",
                "/proc/self/status CapEff",
                "CAP_SYS_ADMIN is not in the effective set; mount(2) will fail",
            ));
            Capability::unavailable(CapabilityKind::MountOperationsPossible, evidence)
        }
        None => {
            evidence.push(Evidence::new(
                "CAP_SYS_ADMIN_UNKNOWN",
                "/proc/self/status",
                "could not read CapEff; cannot determine mount permission",
            ));
            Capability::unknown(CapabilityKind::MountOperationsPossible, evidence)
        }
    }
}

fn write_efivars_possible(fs: &dyn FilesystemProbe, caps: &ProcCaps) -> Capability {
    let p = crate::target::diagnose::candidate::host_efivars_path();
    let meta = match fs.metadata(p) {
        Ok(m) => m,
        Err(FsError::NotFound) => {
            return Capability::unavailable(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_NOT_MOUNTED",
                    p.display().to_string(),
                    "efivarfs path does not exist; efivarfs not mounted?",
                )],
            );
        }
        Err(FsError::PermissionDenied) => {
            return Capability::unknown(
                CapabilityKind::WriteEfivarsPossible,
                vec![Evidence::new(
                    "EFIVARS_PERMISSION_DENIED",
                    p.display().to_string(),
                    "permission denied stat'ing efivarfs; cannot determine state",
                )],
            );
        }
        Err(e) => {
            return Capability::unknown(
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
        return Capability::unavailable(
            CapabilityKind::WriteEfivarsPossible,
            vec![Evidence::new(
                "EFIVARS_NOT_A_DIRECTORY",
                p.display().to_string(),
                "efivarfs path exists but is not a directory",
            )],
        );
    }
    match caps.cap_sys_admin {
        Some(false) => Capability::unavailable(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new("EFIVARS_MOUNTED", p.display().to_string(), "efivarfs appears mounted"),
                Evidence::new(
                    "CAP_SYS_ADMIN_ABSENT",
                    "/proc/self/status CapEff",
                    "CAP_SYS_ADMIN not in effective set; writes to efivarfs require it",
                ),
            ],
        ),
        Some(true) => Capability::unknown(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new("EFIVARS_MOUNTED", p.display().to_string(), "efivarfs appears mounted"),
                Evidence::new(
                    "CAP_SYS_ADMIN_PRESENT",
                    "/proc/self/status CapEff",
                    "CAP_SYS_ADMIN in effective set; writability not probed (phase 1 is read-only)",
                ),
            ],
        ),
        None => Capability::unknown(
            CapabilityKind::WriteEfivarsPossible,
            vec![
                Evidence::new("EFIVARS_MOUNTED", p.display().to_string(), "efivarfs appears mounted"),
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
    if fs.is_dir(Path::new("/run/systemd/system")) {
        Capability::available(
            CapabilityKind::SystemdAvailable,
            vec![Evidence::new(
                "SYSTEMD_RUN_DIR_PRESENT",
                "/run/systemd/system",
                "systemd runtime marker directory exists; systemd is PID 1",
            )],
        )
    } else {
        Capability::unavailable(
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
    target_tool_capability(fs, root, CapabilityKind::PacmanPresentInTarget, "pacman", "usr/bin/pacman")
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
    let tool = crate::target::diagnose::candidate::probe_target_tool(fs, root, name, rel);
    Capability {
        name: kind,
        status: tool.status,
        evidence: tool.evidence,
    }
}

fn tool_available(fs: &dyn FilesystemProbe, kind: CapabilityKind, name: &str) -> Capability {
    match crate::target::diagnose::candidate::host_tool_exists(fs, name) {
        Some(p) => Capability::available(
            kind,
            vec![Evidence::new(
                "HOST_TOOL_RESOLVED",
                p.display().to_string(),
                format!("{name} resolved on host PATH"),
            )],
        ),
        None => Capability::unavailable(
            kind,
            vec![Evidence::new(
                "HOST_TOOL_MISSING",
                "host PATH",
                format!("{name} not found on host PATH"),
            )],
        ),
    }
}

// (capability helpers above intentionally unused by some callers)
#[allow(unused_imports)]
use crate::target::model::{Capability as _Capability, CapabilityKind as _CapabilityKind, CapabilityStatus as _CapabilityStatus};
