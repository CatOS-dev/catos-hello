//! Read-only Btrfs subvolume diagnosis for Chroot.

use std::time::Duration;

use crate::model::{BlockDevice, Subvolume};
use crate::session::ReadOnlyMountProbe;
use catos_process::run_trusted_tool;

const BTRFS_TIMEOUT: Duration = Duration::from_secs(30);
const BTRFS_MAX_OUTPUT: usize = 1024 * 1024;

pub fn list_subvolumes(
    device: &BlockDevice,
    include_dot_snapshots: bool,
) -> Result<Vec<Subvolume>, String> {
    let mut probe = ReadOnlyMountProbe::open(device, &["subvolid=5".into()])?;
    let mount_point = probe.path().to_string_lossy().into_owned();
    let output_result = run_trusted_tool(
        "btrfs",
        &["subvolume", "list", "-t", &mount_point],
        BTRFS_TIMEOUT,
        BTRFS_MAX_OUTPUT,
    );
    let cleanup_result = probe.cleanup();

    let output = match output_result {
        Ok(output) => output,
        Err(error) => {
            return Err(match cleanup_result {
                Ok(()) => error,
                Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
            })
        }
    };
    if !output.success() {
        let error = format!(
            "btrfs subvolume list failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Err(match cleanup_result {
            Ok(()) => error,
            Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
        });
    }
    cleanup_result?;
    Ok(parse_subvolume_table(
        &String::from_utf8_lossy(&output.stdout),
        include_dot_snapshots,
    ))
}

pub fn parse_subvolume_table(stdout: &str, include_dot_snapshots: bool) -> Vec<Subvolume> {
    let mut subvolumes = vec![Subvolume {
        id: 5,
        name: "/".into(),
    }];
    for line in stdout.lines().skip(2) {
        let mut parts = line.split_whitespace();
        let Some(id) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let path = parts.nth(2).unwrap_or("");
        if path.is_empty() || (!include_dot_snapshots && path.starts_with(".snapshots")) {
            continue;
        }
        subvolumes.push(Subvolume {
            id,
            name: path.into(),
        });
    }
    subvolumes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_subvolume_is_always_present() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n";
        let subvols = parse_subvolume_table(out, false);
        assert_eq!(
            subvols,
            [Subvolume {
                id: 5,
                name: "/".into()
            }]
        );
    }

    #[test]
    fn dot_snapshots_are_filtered_by_policy() {
        let out = "ID  gen  top level  path\n--  ---  ---------  ----\n\
                   256  10  5  @\n\
                   258  12  5  .snapshots/1/snapshot\n";
        assert_eq!(parse_subvolume_table(out, false).len(), 2);
        assert_eq!(parse_subvolume_table(out, true).len(), 3);
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
