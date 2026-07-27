//! Minimal `/etc/fstab` parser for `catos-chroot`.
//!
//! Only the fields the chroot auto-mount logic consults are decoded:
//! `fs_spec`, `mountpoint`, `vfs_type`. `mount_options` and the
//! numeric dump/pass fields are kept as raw strings so btrfs
//! `subvolid=` / `subvol=` options can be matched when needed. The
//! parser is deliberately line-oriented and forgiving: malformed rows
//! are skipped with a warning, never fatal — chroot is a recovery
//! tool and a half-broken fstab should not prevent entering the
//! target.

use crate::chroot::model::{BlockDevice, FsTabEntry, Subvolume};
use crate::chroot::session::ReadOnlyMountProbe;
use crate::shared::error::FsError;
use crate::target::execute::confined::{read_rooted_file, rooted_regular_file_size};

pub fn read_from_device(
    device: &BlockDevice,
    subvolume: Option<&Subvolume>,
) -> Result<Vec<FsTabEntry>, String> {
    let options = subvolume
        .map(|subvolume| vec![format!("subvolid={}", subvolume.id)])
        .unwrap_or_default();
    let mut probe = ReadOnlyMountProbe::open(device, &options)?;
    let entries_result = (|| match rooted_regular_file_size(probe.path(), "/etc/fstab") {
        Ok(Some(_)) => {
            let bytes = read_rooted_file(probe.path(), "/etc/fstab")
                .map_err(|error| format!("cannot read target /etc/fstab: {error}"))?;
            let contents = String::from_utf8(bytes)
                .map_err(|error| format!("target /etc/fstab is not UTF-8: {error}"))?;
            Ok(parse(&contents))
        }
        Ok(None) | Err(FsError::NotFound) => Ok(Vec::new()),
        Err(error) => Err(format!("cannot inspect target /etc/fstab: {error}")),
    })();
    let cleanup_result = probe.cleanup();

    match (entries_result, cleanup_result) {
        (Ok(entries), Ok(())) => Ok(entries),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(format!("probe cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cleanup failed: {cleanup_error}"))
        }
    }
}

/// Parse the textual contents of a fstab. Public so unit tests can
/// drive it with fixtures.
pub fn parse(contents: &str) -> Vec<FsTabEntry> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // The two trailing numeric fields (dump, pass) are optional
        // in practice; mount(8) accepts lines without them. We do not
        // need their values.
        entries.push(FsTabEntry {
            fs_spec: parts[0].to_string(),
            mountpoint: parts[1].to_string(),
            vfs_type: parts[2].to_string(),
            mount_options: parts
                .get(3)
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_list() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let contents = "# header\n\n  \nUUID=abc / ext4 rw,relatime 0 1\n";
        let entries = parse(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fs_spec, "UUID=abc");
    }

    #[test]
    fn options_are_split_on_comma() {
        let entries = parse("UUID=abc / ext4 rw,relatime 0 1\n");
        assert_eq!(entries[0].mount_options, vec!["rw", "relatime"]);
    }

    #[test]
    fn options_are_optional() {
        let entries = parse("UUID=abc / ext4\n");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].mount_options.is_empty());
    }

    #[test]
    fn swap_entries_are_preserved_for_caller_to_filter() {
        // Caller filters on vfs_type == "swap"; the parser keeps the
        // row intact so the policy lives in one place.
        let entries = parse("UUID=swap /none swap defaults 0 0\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vfs_type, "swap");
    }

    #[test]
    fn malformed_short_rows_are_dropped() {
        let entries = parse("one two\nUUID=abc / ext4 rw 0 1\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fs_spec, "UUID=abc");
    }
}
