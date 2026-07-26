//! Runtime detection: build [`RuntimeFacts`] from evidence. Every detector
//! is independent and reads through the [`FilesystemProbe`] trait so fixtures
//! drive unit tests without touching the host's `/proc`.

use std::path::Path;

use crate::shared::error::FsError;
use crate::model::evidence::Evidence;
use crate::model::runtime::{Detection, RuntimeFacts};
use crate::probe::fs_probe::FilesystemProbe;

/// Top-level entry: run every detector and assemble the facts.
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

/// initramfs detection. `/etc/initrd-release` is the canonical marker: it
/// exists inside the initramfs and disappears after `pivot_root`/`switch_root`.
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
    // `/run/initramfs/` exists on a normally-booted system as the leftover
    // of the initramfs's /run, so it is NOT definitive on its own.
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

/// chroot detection via dev/ino comparison of `/` vs `/proc/1/root`.
///
/// Conservative rule (per spec): if we cannot reliably distinguish chroot
/// from a container, return Unknown rather than guessing Detected.
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
                "cannot stat PID 1 root (proc not mounted or no permission); \
                 cannot determine chroot status",
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

    // Distinguish chroot from container. Container engines leave tell-tale
    // files; if any are present we cannot reliably claim chroot.
    if has_container_markers(fs, &mut evidence) {
        evidence.push(Evidence::new(
            "CONTAINER_MARKERS_PRESENT",
            "/.dockerenv, /run/.containerenv, /proc/1/cgroup",
            "container markers detected; cannot reliably distinguish chroot \
             from container runtime",
        ));
        return Detection::unknown(evidence);
    }

    // No container markers AND dev/ino differs: chroot is the most likely
    // explanation. The evidence trail records the alternative explanations.
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

/// Live environment detection (ArchISO / CatOS live). Root read-only alone
/// is NOT sufficient evidence, per spec. Insufficient evidence (e.g.
/// `/proc/cmdline` unreadable) MUST yield Unknown, not NotDetected: we have
/// no positive evidence either way.
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
                "/proc/cmdline does not exist; procfs not mounted. \
                 Cannot rule out Live environment without this evidence.",
            ));
            Detection::unknown(evidence)
        }
        Err(_) => {
            evidence.push(Evidence::new(
                "CMDLINE_UNREADABLE",
                "/proc/cmdline",
                "/proc/cmdline exists but could not be read (permission or I/O). \
                 Cannot rule out Live environment without this evidence.",
            ));
            Detection::unknown(evidence)
        }
    }
}

/// Snapshot-boot detection. Phase 1 only reads mountinfo; never invokes
/// `btrfs` and never auto-detects subvolumes.
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
    // subvol= lives in super_opts on btrfs, not in mount options.
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
        // btrfs with subvol= but not a snapshot path: we cannot rule out
        // snapshot boot, so do not claim NotDetected.
        evidence.push(Evidence::new(
            "BTRFS_SUBVOL_NO_SNAPSHOT_MARKER",
            "/proc/self/mountinfo",
            "root is btrfs with a subvol option but no snapshot path; \
             cannot reliably classify",
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

/// Runtime systemd detection (target-side systemd is a separate capability).
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
                "marker path exists but stat returned an error (permission / I/O); \
                 cannot determine systemd runtime status",
            ));
            Detection::unknown(evidence)
        }
    }
}

/// Root read-only detection via mountinfo options.
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
    /// Per-mount options (e.g. `rw,relatime,noexec`).
    options: String,
    /// Filesystem type (`btrfs`, `ext4`, ...).
    fstype: String,
    /// Super-block options (e.g. `subvol=@/.snapshots/42/snapshot,subvolid=...`).
    /// On btrfs this is where `subvol=` actually lives, not in `options`.
    super_opts: String,
}

/// Parse `/proc/self/mountinfo` and return the entry for mount point `/`.
/// The format (per `proc_pid_mountinfo(5)`) is:
///   `mount_id parent_id major:minor root mount_point options ... - fstype source super_opts`
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::runtime::DetectionStatus;
    use crate::probe::fs_probe::{FixtureFilesystem, MetaData};

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
    fn file_meta() -> MetaData {
        MetaData {
            ino: 0,
            dev: 0,
            mode: 0o644,
            is_dir: false,
            is_file: true,
            is_symlink: false,
        }
    }

    #[test]
    fn initramfs_detected_via_initrd_release() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/etc")
            .file("/etc/initrd-release", "")
            .with_meta("/etc/initrd-release", file_meta());
        let d = detect_initramfs(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn initramfs_unknown_when_only_run_dir() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/run")
            .dir("/run/initramfs")
            .with_meta("/run/initramfs", dir_meta());
        let d = detect_initramfs(&fs);
        assert_eq!(d.status, DetectionStatus::Unknown);
    }

    #[test]
    fn initramfs_not_detected_on_clean_system() {
        let fs = FixtureFilesystem::new().dir("/").dir("/etc");
        let d = detect_initramfs(&fs);
        assert_eq!(d.status, DetectionStatus::NotDetected);
    }

    #[test]
    fn chroot_not_detected_when_root_matches_pid1() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .with_meta(
                "/",
                MetaData {
                    ino: 100,
                    dev: 50,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            )
            .symlink("/proc/1/root", "/")
            .with_meta(
                // The resolve() follows the symlink to "/", then looks up
                // metas for "/". Same dev/ino as the root above.
                "/",
                MetaData {
                    ino: 100,
                    dev: 50,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            );
        let d = detect_chroot(&fs);
        assert_eq!(d.status, DetectionStatus::NotDetected);
    }

    #[test]
    fn chroot_detected_when_root_differs_and_no_container_markers() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .with_meta(
                "/",
                MetaData {
                    ino: 100,
                    dev: 50,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            )
            .dir("/proc")
            .dir("/proc/1")
            .symlink("/proc/1/root", "/host-root")
            .dir("/host-root")
            .with_meta(
                "/host-root",
                MetaData {
                    ino: 999,
                    dev: 99,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            );
        let d = detect_chroot(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn chroot_unknown_when_container_markers_present() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .with_meta(
                "/",
                MetaData {
                    ino: 100,
                    dev: 50,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            )
            .dir("/proc")
            .dir("/proc/1")
            .symlink("/proc/1/root", "/host-root")
            .dir("/host-root")
            .with_meta(
                "/host-root",
                MetaData {
                    ino: 999,
                    dev: 99,
                    mode: 0o755,
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                },
            )
            // Container marker
            .file("/.dockerenv", "");
        let d = detect_chroot(&fs);
        assert_eq!(d.status, DetectionStatus::Unknown);
    }

    #[test]
    fn chroot_unknown_when_proc_unavailable() {
        // No /proc at all
        let fs = FixtureFilesystem::new().dir("/");
        let d = detect_chroot(&fs);
        assert_eq!(d.status, DetectionStatus::Unknown);
    }

    #[test]
    fn live_detected_via_archiso_run_dir() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/run")
            .dir("/run/archiso")
            .with_meta("/run/archiso", dir_meta());
        let d = detect_live(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn live_detected_via_cmdline_archiso() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .file("/proc/cmdline", "archisolabel=CATOS boot=live")
            .with_meta("/proc/cmdline", file_meta());
        let d = detect_live(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn live_not_detected_on_normal_system() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .file(
                "/proc/cmdline",
                "BOOT_IMAGE=/vmlinuz-linux root=UUID=... rw",
            )
            .with_meta("/proc/cmdline", file_meta());
        let d = detect_live(&fs);
        assert_eq!(d.status, DetectionStatus::NotDetected);
    }

    #[test]
    fn snapshot_detected_via_subvol_with_snapshot_path() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "23 1 0:36 /@/.snapshots/42/snapshot / rw,relatime - btrfs /dev/sda2 subvol=@/.snapshots/42/snapshot\n",
            )
            .with_meta("/proc/self/mountinfo", file_meta());
        let d = detect_snapshot_boot(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn snapshot_unknown_when_btrfs_without_snapshot_path() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "23 1 0:36 /@ / rw,relatime - btrfs /dev/sda2 subvol=@\n",
            )
            .with_meta("/proc/self/mountinfo", file_meta());
        let d = detect_snapshot_boot(&fs);
        assert_eq!(d.status, DetectionStatus::Unknown);
    }

    #[test]
    fn snapshot_not_detected_when_not_btrfs() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "23 1 0:36 / / rw,relatime - ext4 /dev/sda2 rw\n",
            )
            .with_meta("/proc/self/mountinfo", file_meta());
        let d = detect_snapshot_boot(&fs);
        assert_eq!(d.status, DetectionStatus::NotDetected);
    }

    #[test]
    fn root_read_only_detected_via_mount_options() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/proc")
            .dir("/proc/self")
            .file(
                "/proc/self/mountinfo",
                "23 1 0:36 / / ro,relatime - ext4 /dev/sda2 ro\n",
            )
            .with_meta("/proc/self/mountinfo", file_meta());
        let d = detect_root_read_only(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn systemd_detected_via_run_dir() {
        let fs = FixtureFilesystem::new()
            .dir("/")
            .dir("/run")
            .dir("/run/systemd")
            .dir("/run/systemd/system")
            .with_meta("/run/systemd/system", dir_meta());
        let d = detect_systemd(&fs);
        assert_eq!(d.status, DetectionStatus::Detected);
    }

    #[test]
    fn no_panic_when_proc_missing() {
        // Empty fixture: only `/`. Every detector should return Unknown
        // rather than panic.
        let fs = FixtureFilesystem::new().dir("/");
        let facts = detect_runtime(&fs);
        // Every Detection should be Unknown or NotDetected, never Detected
        // (we have no positive evidence of anything).
        for d in [
            &facts.is_initramfs,
            &facts.is_chroot,
            &facts.is_live_environment,
            &facts.is_snapshot_boot,
            &facts.has_systemd,
            &facts.root_is_read_only,
        ] {
            assert_ne!(d.status, DetectionStatus::Detected, "unexpected Detected");
        }
    }
}
