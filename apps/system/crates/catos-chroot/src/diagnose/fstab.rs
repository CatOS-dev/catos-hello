//! Minimal `/etc/fstab` parser for `catos-chroot`.
//!
//! Only the fields the chroot auto-mount logic consults are decoded:
//! `fs_spec`, `mountpoint`, `vfs_type`. `mount_options` and the
//! numeric dump/pass fields are validated by the shared target parser.
//! Production reads fail closed on malformed rows or a missing root entry;
//! the small tolerant `parse` helper remains only for legacy parser tests.

use crate::model::{BlockDevice, FsTabEntry, Subvolume};
use crate::session::ReadOnlyMountProbe;
use catos_target::execute::confined::{read_rooted_file, rooted_regular_file_size};
use catos_target::fstab::{self, FstabSource};
use catos_target::FsError;

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
            parse_strict(&contents)
        }
        Ok(None) | Err(FsError::NotFound) => {
            Err("target /etc/fstab is missing; refusing incomplete chroot mount plan".into())
        }
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

pub fn parse_strict(contents: &str) -> Result<Vec<FsTabEntry>, String> {
    let (entries, diagnostics) = fstab::parse_all_with_diagnostics(contents);
    if !diagnostics.is_empty() {
        let details = diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "line {} ({:?}): {}",
                    diagnostic.line, diagnostic.kind, diagnostic.text
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "target /etc/fstab contains malformed entries: {details}"
        ));
    }

    let entries = entries
        .into_iter()
        .map(|entry| FsTabEntry {
            fs_spec: source_as_spec(entry.source),
            mountpoint: entry.target,
            vfs_type: entry.fstype,
            mount_options: entry.options,
        })
        .collect::<Vec<_>>();
    if !entries.iter().any(|entry| entry.mountpoint == "/") {
        return Err("target /etc/fstab has no root entry".into());
    }
    Ok(entries)
}

fn source_as_spec(source: FstabSource) -> String {
    match source {
        FstabSource::Uuid(value) => format!("UUID={value}"),
        FstabSource::PartUuid(value) => format!("PARTUUID={value}"),
        FstabSource::Label(value) => format!("LABEL={value}"),
        FstabSource::PartLabel(value) => format!("PARTLABEL={value}"),
        FstabSource::Path(value) | FstabSource::Pseudo(value) => value,
    }
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

    #[test]
    fn strict_parser_rejects_malformed_rows() {
        let error = parse_strict("one two\nUUID=abc / ext4 rw 0 1\n").unwrap_err();
        assert!(error.contains("line 1"));
    }

    #[test]
    fn strict_parser_requires_root_entry() {
        let error = parse_strict("UUID=boot /boot ext4 defaults 0 2\n").unwrap_err();
        assert!(error.contains("root entry"));
    }
}
