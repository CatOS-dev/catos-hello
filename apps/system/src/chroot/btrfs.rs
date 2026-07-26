//! Btrfs subvolume enumeration for `catos-chroot`.
//!
//! Subvolume discovery mounts the device at a private temporary
//! mountpoint, runs `btrfs subvolume list -t`, then unmounts. The
//! temp mount is created via `tempfile::TempDir` semantics: a unique
//! directory under `std::env::temp_dir()` that is removed on drop.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::chroot::block_device::{mount_device, umount_path, BlockDevice};
use crate::process::run_trusted_tool;

const BTRFS_TIMEOUT: Duration = Duration::from_secs(30);
const BTRFS_MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Subvolume {
    pub id: u64,
    pub name: String,
}

impl std::fmt::Display for Subvolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.id, self.name)
    }
}

/// A temporary mountpoint that is created on construction and removed
/// on drop. Failure to clean up is logged to stderr but does not
/// propagate: a stray empty directory under /tmp is harmless and the
/// chroot flow must not abort during cleanup.
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
            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(TempMount { path: candidate }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && counter < 8 => {
                    continue;
                }
                Err(error) => return Err(format!("failed to create tempdir: {error}")),
            }
        }
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir(&self.path) {
            eprintln!("catos-chroot: warning: failed to remove {}: {error}", self.path.display());
        }
    }
}

/// Enumerate btrfs subvolumes on `device`. The result always begins
/// with the root subvolume (id 5, name "/") so a single-subvolume
/// filesystem is selectable. `.snapshots` subvolumes are filtered
/// out unless `include_dot_snapshots` is true.
pub fn list_subvolumes(
    device: &BlockDevice,
    include_dot_snapshots: bool,
) -> Result<Vec<Subvolume>, String> {
    let temp = TempMount::new(&format!("catos-chroot-btrfs-{}", slug(device)))?;
    let mount_point = &temp.path;

    let status = mount_device(device, mount_point, None)?;
    if !status.success() {
        return Err(format!(
            "mount failed for btrfs scan with status {status}: {}",
            device.name
        ));
    }

    let output = run_trusted_tool(
        "btrfs",
        &["subvolume", "list", "-t", &mount_point.to_string_lossy()],
        BTRFS_TIMEOUT,
        BTRFS_MAX_OUTPUT,
    );

    // Always attempt unmount before returning, even on error.
    let _ = umount_path(mount_point, false);

    let output = output?;
    if !output.success() {
        return Err(format!(
            "btrfs subvolume list failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_subvolume_table(&stdout, include_dot_snapshots))
}

/// Parse the tabular output of `btrfs subvolume list -t`. The first
/// two lines are headers; remaining rows are `<id> <gen> <top level>
/// <path>`. We only consume id and path.
fn parse_subvolume_table(stdout: &str, include_dot_snapshots: bool) -> Vec<Subvolume> {
    let mut subvolumes = Vec::new();
    // The root subvolume (id 5) is implicit and never appears in
    // `subvolume list` output. Prepend it so a single-subvolume
    // filesystem is still selectable.
    subvolumes.push(Subvolume { id: 5, name: "/".to_string() });

    for line in stdout.lines().skip(2) {
        let mut parts = line.split_whitespace();
        let Some(id_str) = parts.next() else { continue };
        let Ok(id) = id_str.parse::<u64>() else { continue };
        // Skip `gen` and `top level` columns to reach the path.
        let path = parts.nth(2).unwrap_or("");
        if path.is_empty() {
            continue;
        }
        if !include_dot_snapshots && path.starts_with(".snapshots") {
            continue;
        }
        subvolumes.push(Subvolume { id, name: path.to_string() });
    }
    subvolumes
}

/// Reduce `device.uuid` (or its name fallback) to a filesystem-safe
/// slug so it can appear in a temp directory name.
fn slug(device: &BlockDevice) -> String {
    device
        .id()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_subvolume_is_always_present() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n";
        let subvols = parse_subvolume_table(out, false);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].id, 5);
        assert_eq!(subvols[0].name, "/");
    }

    #[test]
    fn skips_header_and_dot_snapshots_by_default() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n\
                   256  10  5  @\n\
                   257  11  5  @home\n\
                   258  12  5  .snapshots/1/snapshot\n";
        let subvols = parse_subvolume_table(out, false);
        assert_eq!(subvols.len(), 3);
        assert_eq!(subvols[0].name, "/");
        assert_eq!(subvols[1].id, 256);
        assert_eq!(subvols[1].name, "@");
        assert_eq!(subvols[2].name, "@home");
    }

    #[test]
    fn includes_dot_snapshots_when_requested() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n\
                   258  12  5  .snapshots/1/snapshot\n";
        let subvols = parse_subvolume_table(out, true);
        assert_eq!(subvols.len(), 2);
        assert_eq!(subvols[1].name, ".snapshots/1/snapshot");
    }

    #[test]
    fn malformed_rows_are_dropped() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n\
                   notanumber  10  5  @\n\
                   256  10  5  @\n";
        let subvols = parse_subvolume_table(out, false);
        assert_eq!(subvols.len(), 2);
        assert_eq!(subvols[1].id, 256);
    }
}
