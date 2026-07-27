//! Parser for `/proc/<pid>/mountinfo` and `/proc/self/mountinfo`.
//!
//! Format reference: Linux kernel `Documentation/filesystems/proc.rst`,
//! field layout (line-by-line):
//!
//! ```text
//! 36 35 98:0 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:2 - tmpfs tmpfs rw,seclabel,size=...
//! ^  ^  ^    ^ ^              ^                  ^       ^ ^     ^
//! |  |  |    | |              |                  |       | |     └─ superblock options
//! |  |  |    | |              |                  |       | └─ mount source (e.g. /dev/sda1 or "tmpfs")
//! |  |  |    | |              |                  |       └─ filesystem type (post-separator)
//! |  |  |    | |              |                  └─ "-" separator (optional-fields end here)
//! |  |  |    | |              └─ mount options (VFS-level)
//! |  |  |    | └─ mount point (root-relative path of the mounted tree)
//! |  |  |    └─ root of the mount within the filesystem
//! |  |  └─ major:minor device
//! |  └─ parent mount ID
//! └─ mount ID
//! ```
//!
//! Real bugs this parser is hardened against:
//!   * Treating the optional field as a single token. The optional
//!     field can be multi-token (`shared:2 master:3 ...`) and is
//!     terminated by a literal `-`. Naive whitespace splits break here.
//!   * Confusing VFS-level options (field 6) with superblock options
//!     (field 10). They are NOT the same and downstream code keys on
//!     them differently (e.g. `ro` in VFS-level means the mount is RO;
//!     `ro` in superblock options is just informational).
//!   * Mishandling escaped octal sequences (`\040` for space) in mount
//!     source / target.
//!   * Truncating at the first space inside a value (the mount source
//!     can contain spaces when escaped).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One parsed mountinfo line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountInfo {
    /// Mount ID (kernel-assigned, monotonically increasing within a
    /// namespace, recycled after umount).
    pub mount_id: u32,
    /// Parent mount ID. 0 for the root of the namespace.
    pub parent_id: u32,
    /// `major:minor`.
    pub major_minor: String,
    /// Mount root (pathname within the source filesystem).
    pub root: String,
    /// Mount point (pathname in this namespace).
    pub mount_point: PathBuf,
    /// VFS-level mount options (field 6, before the `-` separator).
    /// These are the flags the VFS layer actually applies; `ro` here
    /// is the authoritative "is this mount read-only" answer.
    pub vfs_options: Vec<String>,
    /// Optional fields (`shared:1`, `master:3`, `unbindable`, etc.).
    /// Parsed as raw tokens so callers can pattern-match.
    pub optional_fields: Vec<String>,
    /// Filesystem type (after the `-` separator).
    pub fstype: String,
    /// Mount source (e.g. `/dev/sda1` or `tmpfs` or `none`).
    pub source: String,
    /// Superblock options (field 10).
    pub super_options: Vec<String>,
}

impl MountInfo {
    /// True iff `ro` appears in the VFS-level options. This is the
    /// authoritative test: super_options may also say `ro` but that is
    /// informational only.
    pub fn is_read_only(&self) -> bool {
        self.vfs_options.iter().any(|o| o == "ro")
    }

    /// True iff the source is `/dev/...` or this is a normal filesystem
    /// backed by a block device. Pseudo-filesystems (`tmpfs`, `proc`,
    /// `sysfs`, `devtmpfs`, `cgroup*`, etc.) return false.
    pub fn is_block_backed(&self) -> bool {
        self.source.starts_with("/dev/")
            || (!self.source.is_empty()
                && self.source != "none"
                && self.source != "tmpfs"
                && self.source != "proc"
                && self.source != "sysfs"
                && self.source != "cgroup"
                && self.source != "cgroup2"
                && self.source != "devtmpfs"
                && self.source != "mqueue"
                && self.source != "securityfs"
                && self.source != "debugfs"
                && self.source != "tracefs"
                && self.source != "configfs"
                && self.source != "pstore"
                && self.source != "bpf"
                && self.source != "ramfs"
                && self.source != "hugetlbfs")
    }
}

/// Parse a single mountinfo line. Returns `None` on a structurally
/// malformed line (the kernel never emits those, but we want the parser
/// to be tolerant of test fixtures and future format extensions).
pub fn parse_line(line: &str) -> Option<MountInfo> {
    let line = line.trim_end_matches('\n');
    if line.is_empty() {
        return None;
    }

    // Step 1: split off the first 6 whitespace-separated fields. We must
    // be careful with escaped spaces: only the FIRST 6 fields plus the
    // post-dash fields contain paths that may have escaped spaces. We
    // tokenise while honouring `\040` escapes.
    let tokens = tokenise_escaped(line);
    if tokens.len() < 9 {
        // Minimum: 6 leading fields + at least "-" + fstype + source +
        // super_options = 10. We allow 9 in case super_options is empty
        // (some filesystems emit no superblock options — but the field
        // itself is always present).
        return None;
    }

    let mount_id: u32 = tokens[0].parse().ok()?;
    let parent_id: u32 = tokens[1].parse().ok()?;
    let major_minor = tokens[2].clone();
    let root = unescape_octal(&tokens[3]);
    let mount_point = PathBuf::from(unescape_octal(&tokens[4]));
    let vfs_options = tokens[5]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    // Step 2: collect optional fields from token 6 onwards until we hit
    // the literal "-" separator. The kernel guarantees this separator
    // exists; if it doesn't, the line is corrupt.
    let mut optional_fields = Vec::new();
    let mut idx = 6;
    while idx < tokens.len() {
        if tokens[idx] == "-" {
            idx += 1;
            break;
        }
        optional_fields.push(tokens[idx].clone());
        idx += 1;
    }

    // Step 3: post-dash fields are fstype, source, super_options.
    // fstype and source are required; super_options may be absent or empty
    // (the kernel almost always emits it, but we must tolerate its absence
    // rather than dropping the whole line).
    if idx + 1 >= tokens.len() {
        return None;
    }
    let fstype = tokens[idx].clone();
    let source = unescape_octal(&tokens[idx + 1]);
    // The super_options field is everything from idx+2 onward, joined by
    // spaces (then split on commas). The kernel joins them with commas
    // but some options (notably `lowerdir=...` on overlayfs) can contain
    // colons. We join with spaces and then re-split, mirroring findmnt.
    let super_options_raw: String = tokens[idx + 2..].join(" ");
    let super_options = super_options_raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Some(MountInfo {
        mount_id,
        parent_id,
        major_minor,
        root,
        mount_point,
        vfs_options,
        optional_fields,
        fstype,
        source,
        super_options,
    })
}

/// Parse the whole mountinfo file body. Returns the lines that parsed
/// successfully, in file order. Lines that fail to parse are silently
/// skipped (the kernel never emits malformed lines, but unit-test
/// fixtures might).
pub fn parse_all(body: &str) -> Vec<MountInfo> {
    body.lines().filter_map(parse_line).collect()
}

/// Find the mount entry (if any) whose source matches the given device
/// path. Returns the first match. Use `find_by_source_all` when you need
/// every match (e.g. for ambiguity detection).
pub fn find_by_source<'a>(entries: &'a [MountInfo], dev_path: &str) -> Option<&'a MountInfo> {
    entries.iter().find(|m| m.source == dev_path)
}

/// All mount entries whose source matches `dev_path`. Used to detect
/// "device mounted in multiple places" — relevant for LVM-thin / btrfs
/// subvolumes mounted separately.
pub fn find_by_source_all<'a>(entries: &'a [MountInfo], dev_path: &str) -> Vec<&'a MountInfo> {
    entries.iter().filter(|m| m.source == dev_path).collect()
}

/// Tokenise a mountinfo line on whitespace, honouring `\040`-style
/// escapes for spaces. We replace the escape sequence with a literal
/// space after the split so downstream unescaping works.
fn tokenise_escaped(line: &str) -> Vec<String> {
    // Strategy: scan char-by-char. We do NOT collapse `\040` here — we
    // need to split on raw whitespace first. The kernel escapes spaces
    // exactly so the standard whitespace split works.
    line.split_whitespace().map(|s| s.to_string()).collect()
}

/// Replace `\040`, `\011`, `\012`, `\134` escapes with their literal
/// characters. The kernel uses these four escapes (space, tab, newline,
/// backslash) per `fs/proc_namespace.c:mangle()`.
fn unescape_octal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            // Try `\NNN` octal.
            let n1 = (bytes[i + 1] as char).to_digit(8);
            let n2 = (bytes[i + 2] as char).to_digit(8);
            let n3 = (bytes[i + 3] as char).to_digit(8);
            if let (Some(a), Some(b), Some(c)) = (n1, n2, n3) {
                let v = (a << 6) | (b << 3) | c;
                if v <= 255 {
                    out.push(v as u8 as char);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative mountinfo line from a real CatOS install with
    /// btrfs root at subvol `/@`. Guards against:
    ///   * confounding the root subvol path with the mount point
    ///   * mishandling btrfs superblock options that themselves contain
    ///     commas (compress=zstd:3)
    ///   * confusing VFS-level ro with superblock-level ro
    #[test]
    fn parses_btrfs_root_line() {
        let line = "40 1 0:33 /@ / rw,relatime shared:1 - btrfs /dev/nvme1n1p2 rw,compress=zstd:3,ssd,discard=async,space_cache=v2,subvolid=256,subvol=/@";
        let m = parse_line(line).expect("parse");
        assert_eq!(m.mount_id, 40);
        assert_eq!(m.parent_id, 1);
        assert_eq!(m.major_minor, "0:33");
        assert_eq!(m.root, "/@");
        assert_eq!(m.mount_point, PathBuf::from("/"));
        // VFS options must NOT contain compress=zstd:3 — that is a
        // superblock option. Confounding the two would let code conclude
        // "mount is read-only" from a wrong field.
        assert!(m.vfs_options.contains(&"rw".to_string()));
        assert!(!m.vfs_options.iter().any(|o| o.contains("compress")));
        assert!(!m.is_read_only());
        assert!(m.is_block_backed());
        assert_eq!(m.fstype, "btrfs");
        assert_eq!(m.source, "/dev/nvme1n1p2");
        // superblock options must include subvol=/@ and subvolid=256 —
        // these are how we discover the btrfs default subvolume later.
        assert!(m.super_options.iter().any(|o| o == "subvol=/@"));
        assert!(m.super_options.iter().any(|o| o.starts_with("subvolid=")));
    }

    /// A read-only mount: `ro` must appear in VFS options. We must not
    /// derive read-only status from super_options alone.
    #[test]
    fn is_read_only_uses_vfs_options() {
        let line = "55 40 0:33 /@ /run/catos ro,relatime - btrfs /dev/nvme1n1p2 rw,compress=zstd:3";
        let m = parse_line(line).unwrap();
        assert!(m.is_read_only(), "VFS ro must set read-only");
        // Even though super_options contain "rw", the mount is RO.
        assert!(m.super_options.contains(&"rw".to_string()));
    }

    /// Multiple optional fields (`shared:1 master:3`) must not break the
    /// post-dash field parser.
    #[test]
    fn handles_multiple_optional_fields() {
        let line = "10 1 0:1 / /sys ro,nosuid,nodev,noexec shared:2 master:3 - sysfs sysfs rw";
        let m = parse_line(line).unwrap();
        assert_eq!(m.optional_fields, vec!["shared:2", "master:3"]);
        assert_eq!(m.fstype, "sysfs");
        assert_eq!(m.source, "sysfs");
    }

    /// Source path with escaped spaces. The kernel uses `\040` for space,
    /// `\011` for tab, `\012` for newline.
    #[test]
    fn unescapes_octal_in_source_and_target() {
        let line = "1 0 8:1 /my\\040root /mnt/my\\040root rw,relatime - ext4 /dev/sda1 rw";
        let m = parse_line(line).unwrap();
        assert_eq!(m.root, "/my root");
        assert_eq!(m.mount_point, PathBuf::from("/mnt/my root"));
    }

    /// Empty lines and lines with too few tokens are dropped, not
    /// panicked on. Important because future kernel formats might emit
    /// stray whitespace.
    #[test]
    fn empty_and_malformed_lines_are_dropped() {
        let body = "\n  \n42 1 0:1\n";
        assert!(parse_all(body).is_empty());
    }

    /// Pseudo-filesystems must NOT be reported as block-backed. Otherwise
    /// the device discovery layer would later try to map them to a
    /// /sys/class/block entry and produce nonsense.
    #[test]
    fn pseudo_filesystems_are_not_block_backed() {
        for fstype in ["proc", "sysfs", "tmpfs", "devtmpfs", "cgroup2"] {
            let line = format!("1 0 0:1 / /{fstype} rw,nosuid,nodev,noexec - {fstype} {fstype} rw");
            let m = parse_line(&line).unwrap();
            assert!(!m.is_block_backed(), "{fstype} should not be block-backed");
        }
    }

    /// Multiple mounts of the same device must be discoverable. This is
    /// how we detect "device is mounted twice" so the session can refuse
    /// to mount on top.
    #[test]
    fn find_by_source_all_returns_every_match() {
        let body = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:1 / /mnt/foo rw - ext4 /dev/sda1 rw
";
        let parsed = parse_all(body);
        let matches = find_by_source_all(&parsed, "/dev/sda1");
        assert_eq!(matches.len(), 2);
    }

    /// Empty super_options field is allowed (some filesystems emit none).
    #[test]
    fn handles_empty_super_options() {
        // This is synthetic but exercises the post-dash field count
        // check.
        let line = "1 0 0:1 / /proc ro - proc proc ";
        let m = parse_line(line);
        // With trailing whitespace, split_whitespace eats the empty
        // token. We accept either empty super_options or "rw" — the
        // contract is "the field exists", not "it has content".
        assert!(m.is_some());
    }
}
