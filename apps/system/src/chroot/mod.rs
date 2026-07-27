//! `catos-chroot` entry point. A Rust reimplementation of the
//! canonical CachyOS chroot helper.
//!
//! Flow:
//! 1. Verify root (unless `--skip-root-check`).
//! 2. Enumerate partitions via `lsblk`.
//! 3. Prompt the operator to pick a root partition.
//! 4. Open LUKS if the chosen device is encrypted.
//! 5. Mount the root (with subvolid if btrfs) at a temp directory.
//! 6. Walk the target's `/etc/fstab` to auto-mount standard
//!    partitions (boot, esp, home, ...) unless `--no-auto-mount`.
//! 7. Loop offering to mount extra partitions on demand.
//! 8. `arch-chroot` into the assembled tree.
//! 9. Cleanly unmount and close LUKS in reverse order.
//!
//! Argument contract:
//!
//! ```text
//! catos-chroot [--skip-root-check] [--no-auto-mount]
//!              [--no-systemd-chroot] [--show-btrfs-dot-snapshots]
//! catos-chroot -h | --help | -V | --version
//! ```
//!
//! `--no-systemd-chroot` switches the final `arch-chroot -S <root>`
//! invocation to plain `arch-chroot <root>`.
//!
//! ZFS support is intentionally absent: CatOS does not ship ZFS by
//! default and pulling the zfs-utils runtime into the chroot
//! companion would balloon the trusted tool surface. LUKS + btrfs +
//! plain ext4/xfs/f2fs cover every CatOS install.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::chroot::block_device::{list_block_devices, mount_device, umount_path, BlockDevice};
use crate::chroot::btrfs::list_subvolumes;
use crate::chroot::fstab::{read as read_fstab, FsTabEntry};
use crate::shared::error::exit_code;
use crate::shared::process::trusted_tool_path;
use crate::target::execute::luks;

pub mod block_device;
pub mod btrfs;
pub mod fstab;

/// Parsed `catos-chroot` arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChrootOptions {
    pub skip_root_check: bool,
    pub no_auto_mount: bool,
    pub no_systemd_chroot: bool,
    pub show_btrfs_dot_snapshots: bool,
}

fn parse_argv(argv: &[String]) -> Result<ChrootOptions, String> {
    let mut opts = ChrootOptions::default();
    for arg in argv {
        match arg.as_str() {
            "--skip-root-check" => opts.skip_root_check = true,
            "--no-auto-mount" => opts.no_auto_mount = true,
            "--no-systemd-chroot" => opts.no_systemd_chroot = true,
            "--show-btrfs-dot-snapshots" => opts.show_btrfs_dot_snapshots = true,
            other => {
                return Err(format!(
                    "unknown option {other:?}; expected --skip-root-check, --no-auto-mount, --no-systemd-chroot, --show-btrfs-dot-snapshots"
                ))
            }
        }
    }
    Ok(opts)
}

/// Entry point invoked from `entry::invocation_dispatch`. `--help` /
/// `--version` have already been handled by the top-level dispatcher.
pub fn run(argv: &[String]) -> i32 {
    let opts = match parse_argv(argv) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("catos-chroot: argument error: {message}");
            return exit_code::ARG_ERROR;
        }
    };

    if !opts.skip_root_check && !is_effective_root() {
        eprintln!(
            "catos-chroot: must be run as root; pass --skip-root-check to override (not recommended)"
        );
        return exit_code::PERMISSION_DENIED;
    }

    // ---- discover block devices --------------------------------------
    let mut devices = match list_block_devices() {
        Ok(devices) if devices.is_empty() => {
            eprintln!("catos-chroot: no usable block devices found");
            return exit_code::PROBE_FAILED;
        }
        Ok(devices) => devices,
        Err(message) => {
            eprintln!("catos-chroot: {message}");
            return exit_code::PROBE_FAILED;
        }
    };

    let mut opened_luks: Vec<BlockDevice> = Vec::new();
    let mut mounted_ids: HashSet<String> = HashSet::new();

    // ---- pick root ---------------------------------------------------
    let mut root_device = match prompt_select_device("root", &devices, false) {
        Some(device) => device,
        None => {
            eprintln!("catos-chroot: no root partition selected");
            return exit_code::ARG_ERROR;
        }
    };

    if root_device.is_crypto_luks() {
        if let Err(message) = luks::open(&root_device.name, root_device.uuid.as_deref()) {
            eprintln!("catos-chroot: {message}");
            return exit_code::PROBE_FAILED;
        }
        opened_luks.push(root_device.clone());
        devices = match list_block_devices() {
            Ok(devices) => devices,
            Err(message) => {
                eprintln!("catos-chroot: {message}");
                let _ = cleanup(&opened_luks, &[]);
                return exit_code::PROBE_FAILED;
            }
        };
        root_device = match prompt_select_device("root (decrypted)", &devices, false) {
            Some(device) => device,
            None => {
                eprintln!("catos-chroot: no decrypted root partition selected");
                let _ = cleanup(&opened_luks, &[]);
                return exit_code::ARG_ERROR;
            }
        };
    }

    // ---- assemble the root mountpoint --------------------------------
    let root_mount = match TempMount::new("catos-chroot-root") {
        Ok(mount) => mount,
        Err(message) => {
            eprintln!("catos-chroot: {message}");
            let _ = cleanup(&opened_luks, &[]);
            return exit_code::PROBE_FAILED;
        }
    };

    let mut extra_mounts: Vec<PathBuf> = Vec::new();
    let mut subvolume_mount_option: Option<String> = None;

    if root_device.is_btrfs() {
        let subvolumes = match list_subvolumes(&root_device, opts.show_btrfs_dot_snapshots) {
            Ok(subvolumes) => subvolumes,
            Err(message) => {
                eprintln!("catos-chroot: {message}");
                let _ = cleanup(&opened_luks, &[]);
                return exit_code::PROBE_FAILED;
            }
        };
        let selected = match prompt_select_subvolume(&root_device.name, &subvolumes) {
            Some(sub) => sub,
            None => {
                eprintln!("catos-chroot: no subvolume selected");
                let _ = cleanup(&opened_luks, &[]);
                return exit_code::ARG_ERROR;
            }
        };
        subvolume_mount_option = Some(format!("subvolid={}", selected.id));
    }

    let options_ref = subvolume_mount_option.as_deref();
    let status = match mount_device(&root_device, &root_mount.path, options_ref) {
        Ok(status) => status,
        Err(message) => {
            eprintln!("catos-chroot: {message}");
            let _ = cleanup(&opened_luks, &extra_mounts);
            return exit_code::PROBE_FAILED;
        }
    };
    if !status.success() {
        eprintln!("catos-chroot: mount of root {} failed with status {status}", root_device.name);
        let _ = cleanup(&opened_luks, &extra_mounts);
        return exit_code::PROBE_FAILED;
    }
    mounted_ids.insert(root_device.id());

    // ---- auto-mount from /etc/fstab ----------------------------------
    if !opts.no_auto_mount {
        let fstab_path = root_mount.path.join("etc/fstab");
        if !fstab_path.exists() {
            eprintln!(
                "catos-chroot: warning: no /etc/fstab in target; skipping auto-mount (is this a valid root?)"
            );
        } else {
            let entries = read_fstab(&fstab_path);
            for entry in &entries {
                if entry.vfs_type == "swap" {
                    continue;
                }
                let Some(device) = devices.iter().find(|d| d.matches_spec(&entry.fs_spec)) else {
                    eprintln!(
                        "catos-chroot: warning: fstab device {} not found; skipping",
                        entry.fs_spec
                    );
                    continue;
                };
                if mounted_ids.contains(&device.id()) {
                    continue;
                }
                let Some(relative) = entry.mountpoint.strip_prefix('/') else {
                    continue;
                };
                let target = root_mount.path.join(relative);
                if let Err(error) = std::fs::create_dir_all(&target) {
                    eprintln!(
                        "catos-chroot: warning: cannot create mountpoint {}: {error}",
                        target.display()
                    );
                    continue;
                }
                let status = match mount_device(device, &target, fstab_btrfs_option(entry)) {
                    Ok(status) => status,
                    Err(error) => {
                        eprintln!("catos-chroot: warning: {error}");
                        continue;
                    }
                };
                if status.success() {
                    mounted_ids.insert(device.id());
                    extra_mounts.push(target);
                } else {
                    eprintln!(
                        "catos-chroot: warning: mount of {} at {} failed with status {status}",
                        device.name,
                        target.display()
                    );
                }
            }
        }
    }

    // ---- interactive additional partitions ---------------------------
    loop {
        if !prompt_yes_no("Mount an additional partition?", false) {
            break;
        }
        let mountpoint_input = match prompt_mount_point() {
            Some(mp) => mp,
            None => continue,
        };
        if mountpoint_input.eq_ignore_ascii_case("skip") {
            continue;
        }
        let Some(device) = prompt_select_device(&mountpoint_input, &devices, true) else {
            continue;
        };
        if mounted_ids.contains(&device.id()) {
            eprintln!("catos-chroot: {} already mounted; skipping", device.name);
            continue;
        }
        let target = root_mount.path.join(mountpoint_input.trim_start_matches('/'));
        if let Err(error) = std::fs::create_dir_all(&target) {
            eprintln!(
                "catos-chroot: warning: cannot create mountpoint {}: {error}",
                target.display()
            );
            continue;
        }
        let status = match mount_device(&device, &target, None) {
            Ok(status) => status,
            Err(error) => {
                eprintln!("catos-chroot: warning: {error}");
                continue;
            }
        };
        if status.success() {
            mounted_ids.insert(device.id());
            extra_mounts.push(target);
        } else {
            eprintln!(
                "catos-chroot: warning: mount of {} failed with status {status}",
                device.name
            );
        }
    }

    // ---- arch-chroot -------------------------------------------------
    let arch_chroot = match trusted_tool_path("arch-chroot") {
        Some(path) => path,
        None => {
            eprintln!("catos-chroot: arch-chroot not found in trusted system directories");
            let _ = cleanup_with_root(&opened_luks, &root_mount.path, &extra_mounts);
            return exit_code::PROBE_FAILED;
        }
    };
    let mut command = Command::new(&arch_chroot);
    if !opts.no_systemd_chroot {
        command.arg("-S");
    }
    command.arg(&root_mount.path);
    let chroot_status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("catos-chroot: failed to run arch-chroot: {error}");
            let _ = cleanup_with_root(&opened_luks, &root_mount.path, &extra_mounts);
            return exit_code::PROBE_FAILED;
        }
    };

    let _ = cleanup_with_root(&opened_luks, &root_mount.path, &extra_mounts);
    if !chroot_status.success() {
        eprintln!("catos-chroot: arch-chroot exited with status {chroot_status}");
        return exit_code::PROBE_FAILED;
    }
    exit_code::SUCCESS
}

/// Print the per-invocation help. Called from `entry::print_help` when
/// `catos-chroot --help` is used.
pub fn print_help() {
    let version = crate::PROGRAM_VERSION;
    print!(
        "catos-chroot {version} - CatOS interactive chroot helper\n\nUSAGE:\n    catos-chroot [OPTIONS]\n\nDESCRIPTION:\n    Lists block devices, mounts the selected root (plus any LUKS or\n    Btrfs subvolume layer), mounts the standard fstab partitions,\n    then drops you into an arch-chroot shell.\n\nOPTIONS:\n    --skip-root-check          Run without effective UID 0 (dangerous).\n    --no-auto-mount            Do not auto-mount partitions from /etc/fstab.\n    --no-systemd-chroot        Drop the -S flag passed to arch-chroot.\n    --show-btrfs-dot-snapshots Include .snapshots/* subvolumes in the picker.\n    -h, --help                 Show this help message and exit.\n    -V, --version              Print program version and exit.\n\nEXIT CODES:\n    0   Shell exited cleanly.\n    2   Argument error or no selection made.\n    4   Not running as root.\n    5   A required external command failed or is missing.\n"
    );
}

/// True when the process effective UID is 0. Uses `geteuid(2)` via
/// libc so it works in containers without /proc.
fn is_effective_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Build the `-o subvolid=...` option string from an fstab entry, if
/// any. Recognises both `subvolid=` and `subvol=` forms written by
/// genfstab.
fn fstab_btrfs_option(entry: &FsTabEntry) -> Option<&str> {
    entry
        .mount_options
        .iter()
        .find(|opt| opt.starts_with("subvolid=") || opt.starts_with("subvol="))
        .map(String::as_str)
}

/// Close LUKS devices opened during this run. The root mount and
/// extra mounts are expected to already be torn down (or never
/// created) by the caller; this only reverses the crypto layer.
fn cleanup(opened_luks: &[BlockDevice], _extra_mounts: &[PathBuf]) -> Result<(), String> {
    for device in opened_luks {
        let Some(uuid) = device.uuid.as_deref() else {
            eprintln!(
                "catos-chroot: warning: cannot close LUKS device {} without UUID",
                device.name
            );
            continue;
        };
        if let Err(error) = luks::close(uuid) {
            eprintln!("catos-chroot: warning: {error}");
        }
    }
    Ok(())
}

/// Tear down an assembled root tree: recursive umount on the root
/// mountpoint, then close every LUKS device.
fn cleanup_with_root(
    opened_luks: &[BlockDevice],
    root_mount: &Path,
    extra_mounts: &[PathBuf],
) -> Result<(), String> {
    let _ = extra_mounts; // recursive umount on root already covers them.
    if let Err(error) = umount_path(root_mount, true) {
        eprintln!("catos-chroot: warning: {error}");
    }
    cleanup(opened_luks, &[])
}

// ----------------------------------------------------------------------
// Interactive prompts. Kept tiny on purpose: this is a recovery tool,
// not a TUI. Every prompt has a clear default and refuses to loop
// forever on malformed input.
// ----------------------------------------------------------------------

fn prompt_select_device(
    role: &str,
    devices: &[BlockDevice],
    allow_skip: bool,
) -> Option<BlockDevice> {
    if devices.is_empty() {
        eprintln!("catos-chroot: no devices available to pick {role} from");
        return None;
    }
    println!("\nAvailable devices for {role}:");
    let offset = if allow_skip { 1 } else { 0 };
    if allow_skip {
        println!("  0: Skip");
    }
    for (index, device) in devices.iter().enumerate() {
        println!("  {}: {device}", index + offset);
    }
    let upper = devices.len() - 1 + offset;
    loop {
        print!("catos-chroot: pick device [0-{upper}] (default 0): ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        let trimmed = line.trim();
        let index = if trimmed.is_empty() {
            0
        } else {
            match trimmed.parse::<usize>() {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("catos-chroot: not a number: {trimmed:?}");
                    continue;
                }
            }
        };
        if allow_skip && index == 0 {
            return None;
        }
        let candidate = if allow_skip { index - 1 } else { index };
        if let Some(device) = devices.get(candidate) {
            return Some(device.clone());
        }
        eprintln!("catos-chroot: index out of range");
    }
}

fn prompt_select_subvolume(
    device_name: &str,
    subvolumes: &[crate::chroot::btrfs::Subvolume],
) -> Option<crate::chroot::btrfs::Subvolume> {
    println!("\nBtrfs subvolumes on {device_name}:");
    for (index, sub) in subvolumes.iter().enumerate() {
        println!("  {index}: {sub}");
    }
    let upper = subvolumes.len() - 1;
    loop {
        print!("catos-chroot: pick subvolume [0-{upper}] (default 0): ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        let trimmed = line.trim();
        let index = if trimmed.is_empty() {
            0
        } else {
            match trimmed.parse::<usize>() {
                Ok(value) => value,
                Err(_) => {
                    eprintln!("catos-chroot: not a number: {trimmed:?}");
                    continue;
                }
            }
        };
        if let Some(sub) = subvolumes.get(index) {
            return Some(sub.clone());
        }
        eprintln!("catos-chroot: index out of range");
    }
}

fn prompt_mount_point() -> Option<String> {
    print!("catos-chroot: mount point (e.g. /boot) or 'skip' to cancel: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with('/') && !trimmed.eq_ignore_ascii_case("skip") {
        eprintln!("catos-chroot: mount point must start with /");
        return None;
    }
    Some(trimmed)
}

fn prompt_yes_no(prompt: &str, default: bool) -> bool {
    print!("catos-chroot: {prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let trimmed = line.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return default;
    }
    matches!(trimmed.as_str(), "y" | "yes")
}

/// Owned temporary mountpoint. The directory is removed on drop;
/// failure to remove is non-fatal.
struct TempMount {
    path: PathBuf,
}

impl TempMount {
    fn new(prefix: &str) -> Result<Self, String> {
        let mut counter = 0;
        loop {
            counter += 1;
            let candidate = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
                counter
            ));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return Ok(TempMount { path: candidate }),
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists && counter < 8 =>
                {
                    continue;
                }
                Err(error) => return Err(format!("failed to create tempdir: {error}")),
            }
        }
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        // Best-effort: if umount -R did not tear the directory down we
        // still try to rmdir; if that also fails the operator will see
        // the warning.
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chroot::fstab::FsTabEntry;

    #[test]
    fn parse_known_flags() {
        let opts = parse_argv(&[
            "--skip-root-check".to_string(),
            "--no-auto-mount".to_string(),
            "--no-systemd-chroot".to_string(),
            "--show-btrfs-dot-snapshots".to_string(),
        ])
        .expect("all known flags");
        assert!(opts.skip_root_check);
        assert!(opts.no_auto_mount);
        assert!(opts.no_systemd_chroot);
        assert!(opts.show_btrfs_dot_snapshots);
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        let err = parse_argv(&["--nope".to_string()]).expect_err("unknown flag");
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn empty_argv_is_default() {
        let opts = parse_argv(&[]).expect("empty argv");
        assert_eq!(opts, ChrootOptions::default());
    }

    #[test]
    fn fstab_btrfs_option_picks_subvolid_first() {
        let entry = FsTabEntry {
            fs_spec: "UUID=x".into(),
            mountpoint: "/".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["rw".into(), "subvolid=256".into(), "relatime".into()],
        };
        assert_eq!(fstab_btrfs_option(&entry), Some("subvolid=256"));
    }

    #[test]
    fn fstab_btrfs_option_falls_back_to_subvol_name() {
        let entry = FsTabEntry {
            fs_spec: "UUID=x".into(),
            mountpoint: "/".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["rw".into(), "subvol=@".into()],
        };
        assert_eq!(fstab_btrfs_option(&entry), Some("subvol=@"));
    }

    #[test]
    fn fstab_btrfs_option_is_none_for_plain_ext4() {
        let entry = FsTabEntry {
            fs_spec: "UUID=x".into(),
            mountpoint: "/".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["rw".into(), "relatime".into()],
        };
        assert!(fstab_btrfs_option(&entry).is_none());
    }
}
