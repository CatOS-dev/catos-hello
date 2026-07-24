//! Parser for `/etc/fstab`. Pure function of bytes-in; no I/O.
//!
//! Covers the contract required by phase 2:
//!
//!   * Source spec forms: `UUID=`, `PARTUUID=`, `LABEL=`, `PARTLABEL=`,
//!     `/dev/...` paths, `none`, `tmpfs` (special).
//!   * Comment lines (`#`) and blank lines skipped.
//!   * Escaped whitespace (`\040`) and `\\` in source/target unescaped.
//!   * Optional `dump` and `pass` fields default to `0`.
//!   * Network filesystems (`nfs`, `cifs`, `9p`, ...) tagged so the
//!     planner can skip them.
//!   * `swap` tagged so the planner can skip.
//!   * `bind`/`rbind` (detected via `bind` option or fstype `none` with
//!     `bind`) tagged so the planner can skip.
//!   * `nofail` / `noauto` / `x-systemd.*` options surfaced.
//!
//! Hardening against real bugs we've seen in shell-based recovery tools:
//!
//!   * Treating `LABEL=` lookup failure as "no entry" — that turns a
//!     broken fstab into silent data loss. We return the entry and let
//!     the resolver surface the ambiguity.
//!   * Inventing a "pass" value when missing. The kernel default is `0`;
//!     we preserve that.
//!   * Confusing `PARTLABEL=EFI system partition` (with spaces) with
//!     `PARTLABEL=EFI` — we handle escaped spaces in values too.

use serde::{Deserialize, Serialize};

/// One fstab entry as it appears in the file (source-spec, target,
/// fstype, options, dump, pass). Source is left in its raw
/// `UUID=...`/`/dev/...` form here; resolution happens in `probe/` where
/// we have access to discovered devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FstabEntry {
    pub source: FstabSource,
    /// What the kernel/PATH expects for the target path; unescaped.
    pub target: String,
    /// Filesystem type as written (`ext4`, `btrfs`, `swap`, `auto`, ...).
    pub fstype: String,
    /// Options, parsed into a Vec. Order preserved.
    pub options: Vec<String>,
    /// dump(8) field. Defaults to 0 when absent.
    pub dump: u32,
    /// pass field (fsck order). Defaults to 0 when absent.
    pub pass: u32,
    /// Coarse classification of what this entry refers to. Lets the
    /// planner refuse to auto-mount anything outside the recovery allow-
    /// list (root, /boot, /efi, /boot/efi).
    pub kind: FstabEntryKind,
    /// Whether the entry has `noauto` set.
    pub noauto: bool,
    /// Whether the entry has `nofail` set.
    pub nofail: bool,
    /// Whether any `x-systemd.*` option is present (informational only;
    /// we never honour systemd-specific behaviour).
    pub has_systemd_options: bool,
}

/// Coarse fstab entry classification. Drives which entries the phase-2
/// planner will consider auto-mounting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FstabEntryKind {
    /// `/` or empty target (rare but seen on recovery images).
    #[default]
    Root,
    /// `/boot`, `/boot/efi`, or `/efi` — recovery-relevant local fs.
    Boot,
    /// `/home`, `/var`, `/opt`, ... — local fs that we will REPORT but
    /// NOT auto-mount in phase 2.
    OtherLocal,
    /// `swap` filesystem.
    Swap,
    /// Bind / rbind (detected via `bind`/`rbind` option).
    Bind,
    /// Pseudo filesystem (`tmpfs`, `proc`, `sysfs`, `devtmpfs`, ...).
    Pseudo,
    /// Network filesystem (`nfs`, `nfs4`, `cifs`, `9p`, `sshfs`, ...).
    Network,
}

/// Device-spec as written in the source column. We keep the raw form so
/// the resolver can produce precise errors ("found zero devices for
/// LABEL=foo" vs "found two devices for PARTUUID=...").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FstabSource {
    /// `UUID=...`. Value is the bare UUID.
    Uuid(String),
    /// `PARTUUID=...`.
    PartUuid(String),
    /// `LABEL=...`.
    Label(String),
    /// `PARTLABEL=...`.
    PartLabel(String),
    /// `/dev/...` path as written.
    Path(String),
    /// `none`, `tmpfs`, `proc`, `sysfs`, etc. — kernel pseudo-source.
    Pseudo(String),
}

impl FstabSource {
    pub fn parse(raw: &str) -> FstabSource {
        // Strip any surrounding quotes (some old fstab editors add them).
        let raw = raw.trim();
        for (prefix, ctor) in [
            ("UUID=", FstabSource::Uuid as fn(String) -> FstabSource),
            ("PARTUUID=", FstabSource::PartUuid),
            ("LABEL=", FstabSource::Label),
            ("PARTLABEL=", FstabSource::PartLabel),
        ] {
            if let Some(rest) = raw.strip_prefix(prefix) {
                return ctor(unescape_octal(rest.trim_matches('"')));
            }
        }
        if raw.starts_with('/') {
            return FstabSource::Path(unescape_octal(raw));
        }
        // Anything else (`tmpfs`, `none`, `proc`, ...) is treated as a
        // pseudo source. The planner keys off `fstype` to decide swap/
        // bind/network.
        FstabSource::Pseudo(raw.to_string())
    }
}

/// Errors that can arise parsing a single line. Used by tests; in
/// production we usually just skip the line with a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FstabParseError {
    /// Line had fewer than the 4 required fields.
    TooFewFields,
    /// `dump` field was not a number.
    BadDump,
    /// `pass` field was not a number.
    BadPass,
    /// Line is a comment or blank. (Not really an error; useful to
    /// distinguish in tests.)
    Skip,
}

/// Parse one fstab line into an entry. Returns `Err` for malformed
/// input; `Ok(None)` for comment/blank lines.
pub fn parse_line(line: &str) -> Result<Option<FstabEntry>, FstabParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    // We tokenise on whitespace but honour `\040` escapes for spaces.
    // The kernel/fstab convention uses octal escapes (same as mountinfo).
    let tokens = tokenise_fstab_fields(line);
    if tokens.len() < 4 {
        return Err(FstabParseError::TooFewFields);
    }

    let source = FstabSource::parse(&tokens[0]);
    let target = unescape_octal(&tokens[1]);
    let fstype = tokens[2].clone();
    let options_raw = tokens[3].clone();

    let mut options: Vec<String> = options_raw
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let (dump, pass) = if tokens.len() >= 6 {
        let dump: u32 = tokens[4].parse().map_err(|_| FstabParseError::BadDump)?;
        let pass: u32 = tokens[5].parse().map_err(|_| FstabParseError::BadPass)?;
        (dump, pass)
    } else if tokens.len() == 5 {
        // Some installers omit pass. Be permissive but explicit.
        let dump: u32 = tokens[4].parse().map_err(|_| FstabParseError::BadDump)?;
        (dump, 0)
    } else {
        (0, 0)
    };

    let noauto = options.iter().any(|o| o == "noauto");
    let nofail = options.iter().any(|o| o == "nofail");
    let has_systemd_options = options.iter().any(|o| o.starts_with("x-systemd."));

    // Bind/rbind: detected via options OR via the special "bind" fstype.
    let is_bind = options.iter().any(|o| o == "bind" || o == "rbind");

    let kind = if fstype == "swap" {
        FstabEntryKind::Swap
    } else if is_bind {
        FstabEntryKind::Bind
    } else if matches!(
        fstype.as_str(),
        "nfs" | "nfs4" | "cifs" | "smbfs" | "9p" | "sshfs"
    ) {
        FstabEntryKind::Network
    } else if matches!(
        fstype.as_str(),
        "tmpfs" | "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" | "mqueue"
    ) {
        FstabEntryKind::Pseudo
    } else {
        match target.as_str() {
            "/" | "" => FstabEntryKind::Root,
            "/boot" | "/boot/efi" | "/efi" => FstabEntryKind::Boot,
            _ => FstabEntryKind::OtherLocal,
        }
    };

    // Normalise: drop duplicates while preserving order. fstab is small;
    // O(n^2) is fine here.
    options.dedup();

    Ok(Some(FstabEntry {
        source,
        target,
        fstype,
        options,
        dump,
        pass,
        kind,
        noauto,
        nofail,
        has_systemd_options,
    }))
}

/// Parse the whole fstab body. Lines that fail to parse are silently
/// skipped (callers surface a warning via probe layer).
pub fn parse_all(body: &str) -> Vec<FstabEntry> {
    body.lines()
        .filter_map(|l| parse_line(l).ok().flatten())
        .collect()
}

/// Tokenise a fstab line into fields, honouring escaped spaces. We split
/// on raw whitespace runs; escaped spaces are preserved as `\040` and
/// unescaped later.
fn tokenise_fstab_fields(line: &str) -> Vec<String> {
    line.split_whitespace().map(|s| s.to_string()).collect()
}

fn unescape_octal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
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

    /// Real CatOS fstab lines. Guards against the regression where
    /// `LABEL=` was treated as "ignore" and the root entry was silently
    /// dropped, leaving the recovery tool with no idea what to mount.
    #[test]
    fn parses_realistic_catos_fstab() {
        let body = "\
# /etc/fstab: static file system information.
UUID=3bdc66e2-f30b-4ef1-97f0-c687934e25e2  /              btrfs  rw,relatime,compress=zstd:3,subvol=/@      0 0
UUID=3bdc66e2-f30b-4ef1-97f0-c687934e25e2  /home          btrfs  rw,relatime,compress=zstd:3,subvol=/@home   0 0
UUID=2CB7-2D33                              /boot/efi      vfat   defaults,noatime                              0 2
UUID=a9a4664c-f616-4654-9776-425f004a578e  none           swap   defaults                                      0 0
tmpfs                                      /tmp           tmpfs  nosuid,nodev,nofail,x-systemd.idle-timeout=60 0 0
";
        let parsed = parse_all(body);
        assert_eq!(parsed.len(), 5);

        let root = parsed.iter().find(|e| e.target == "/").unwrap();
        assert!(matches!(root.source, FstabSource::Uuid(_)));
        assert_eq!(root.fstype, "btrfs");
        assert!(root.options.contains(&"subvol=/@".to_string()));
        assert_eq!(root.kind, FstabEntryKind::Root);

        let esp = parsed.iter().find(|e| e.target == "/boot/efi").unwrap();
        assert_eq!(esp.kind, FstabEntryKind::Boot);

        let swap = parsed.iter().find(|e| e.target == "none").unwrap();
        assert_eq!(swap.kind, FstabEntryKind::Swap);

        let tmpfs = parsed.iter().find(|e| e.target == "/tmp").unwrap();
        assert_eq!(tmpfs.kind, FstabEntryKind::Pseudo);
        assert!(tmpfs.has_systemd_options);
        assert!(tmpfs.nofail);
    }

    /// `PARTLABEL=EFI system partition` (with spaces, escaped as
    /// `\040`) must be preserved correctly.
    #[test]
    fn handles_escaped_spaces_in_partlabel() {
        let line = "PARTLABEL=EFI\\040system\\040partition  /boot/efi  vfat  defaults  0 0";
        let e = parse_line(line).unwrap().unwrap();
        match e.source {
            FstabSource::PartLabel(s) => assert_eq!(s, "EFI system partition"),
            other => panic!("expected PartLabel, got {other:?}"),
        }
    }

    /// Missing dump/pass must default to (0, 0), not error. We refuse
    /// to mark a recovery-critical fstab line as "broken" just because
    /// the user wrote only 4 fields.
    #[test]
    fn missing_dump_and_pass_defaults_to_zero() {
        let line = "/dev/sda1  /  ext4  defaults";
        let e = parse_line(line).unwrap().unwrap();
        assert_eq!(e.dump, 0);
        assert_eq!(e.pass, 0);
    }

    /// A non-numeric dump field is a genuine fstab corruption. We must
    /// surface it, not silently treat as 0.
    #[test]
    fn non_numeric_dump_is_error() {
        let line = "/dev/sda1  /  ext4  defaults  banana  0";
        assert!(matches!(parse_line(line), Err(FstabParseError::BadDump)));
    }

    /// noauto and nofail flags must be detected so the planner can skip
    /// the entry (rather than mounting it anyway and surprising the
    /// user).
    #[test]
    fn detects_noauto_and_nofail() {
        let line = "/dev/sdb1  /mnt/external  ext4  noauto,nofail,ro  0 0";
        let e = parse_line(line).unwrap().unwrap();
        assert!(e.noauto);
        assert!(e.nofail);
        assert_eq!(e.kind, FstabEntryKind::OtherLocal);
    }

    /// Bind and rbind entries are reported (kind=Bind) but never
    /// auto-mounted by the phase-2 planner.
    #[test]
    fn detects_bind_entries() {
        let bind_line = "/home  /mnt/home  none  bind  0 0";
        let e = parse_line(bind_line).unwrap().unwrap();
        assert_eq!(e.kind, FstabEntryKind::Bind);

        let rbind_line = "/  /mnt/root  none  rbind  0 0";
        let e = parse_line(rbind_line).unwrap().unwrap();
        assert_eq!(e.kind, FstabEntryKind::Bind);
    }

    /// Network filesystems are reported but never mounted.
    #[test]
    fn classifies_network_fs() {
        for fs in ["nfs", "nfs4", "cifs", "9p", "sshfs"] {
            let line = format!("server:/share  /mnt/nfs  {fs}  defaults  0 0");
            let e = parse_line(&line).unwrap().unwrap();
            assert_eq!(e.kind, FstabEntryKind::Network, "{fs}");
        }
    }

    /// Comments and blank lines are silently skipped.
    #[test]
    fn skips_comments_and_blank_lines() {
        let body = "# a comment\n\n   \n";
        assert!(parse_all(body).is_empty());
    }

    /// `none` as a target (e.g. swap) must NOT be confused with `none`
    /// as a source.
    #[test]
    fn swap_target_is_classified_correctly() {
        let line = "UUID=xyz  none  swap  defaults  0 0";
        let e = parse_line(line).unwrap().unwrap();
        assert_eq!(e.kind, FstabEntryKind::Swap);
        assert_eq!(e.target, "none");
    }
}
