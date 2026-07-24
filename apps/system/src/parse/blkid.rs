//! Supplement-only parser for blkid-derived filesystem signatures.
//!
//! Pure function of bytes-in; no I/O. Sysfs remains the PRIMARY source of
//! structural device data (major:minor, size, ro, partition number, parent).
//! This parser only fills in the on-disk signature fields blkid computes:
//! filesystem type, UUID, LABEL, PARTUUID, PARTLABEL, partition table type.
//!
//! Two input formats are supported, both produced by util-linux blkid and
//! by udevd's built-in signature probe:
//!
//!   1. **udev key=value** (`/run/udev/data/b<major>:<minor>` or
//!      `blkid -p -o udev`): one `KEY=VALUE` per line, no quoting.
//!      This is the reliable machine-readable format and the one we prefer.
//!      Keys are namespaced (`ID_FS_TYPE`, `ID_PART_ENTRY_TYPE`, ...).
//!
//!   2. **human format** (`blkid /dev/sda1` with no `-o`): a single line
//!      starting with the device path followed by space-separated
//!      `KEY="VALUE"` tokens. Keys are the short forms (`UUID`, `TYPE`,
//!      `LABEL`, ...).
//!
//! Hardening against real bugs seen in shell-based recovery tools:
//!
//!   * Trusting `LABEL=` alone to identify a root filesystem. Labels are
//!     NOT unique; two disks can both say `LABEL=root`. We surface LABEL
//!     as a signal, never as an identity.
//!   * Confusing `ID_FS_UUID` (filesystem UUID) with `ID_PART_ENTRY_UUID`
//!     (GPT partition UUID). These are different namespaces and must never
//!     be merged into one field.
//!   * Treating an absent blkid entry as "no filesystem". blkid may simply
//!     not have probed this device. The probe layer distinguishes "blkid
//!     did not report" (all fields None) from "blkid reported no signature"
//!     (USAGE=raid or USAGE=crypto with no FS TYPE) via [`BlkidInfo::present`].

use serde::{Deserialize, Serialize};

/// GPT partition-type GUIDs we classify for phase-2 ESP / boot detection.
/// Anything else falls through as `GptOther(<raw>)` so we never lose data.
const GPT_ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const GPT_BIOS_BOOT: &str = "21686148-6449-6e6f-744e-656564454649";

/// Result of parsing one blkid record. Every field is optional because
/// blkid may report a partial picture (e.g. a swap partition has TYPE but
/// no LABEL; a bare LUKS has USAGE=crypto but no FS TYPE).
///
/// `present` distinguishes "parser saw real signature data" from "parser
/// got an empty/garbage record". Callers MUST check `present` before
/// interpreting any other field as authoritative.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlkidInfo {
    /// True iff at least one recognised key was found. When false, every
    /// other field is `None`/empty and the record should be treated as
    /// "blkid has nothing to say about this device" — NOT as "device has
    /// no filesystem".
    pub present: bool,
    /// `ID_FS_TYPE` / `TYPE`. Filesystem type string exactly as blkid
    /// reports it (`ext4`, `btrfs`, `vfat`, `swap`, `crypto_LUKS`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    /// `ID_FS_UUID` / `UUID`. Filesystem UUID. Distinct from part_uuid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_uuid: Option<String>,
    /// `ID_FS_LABEL` / `LABEL`. Filesystem label. NOT unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_label: Option<String>,
    /// `ID_FS_USAGE` / `USAGE`. Coarse usage class (`filesystem`, `raid`,
    /// `crypto`, `other`). Lets the planner refuse crypto/raid without
    /// enumerating every type string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_usage: Option<String>,
    /// `ID_PART_ENTRY_UUID` / `PARTUUID`. GPT partition UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_uuid: Option<String>,
    /// `ID_PART_ENTRY_NAME` / `PARTLABEL`. GPT partition name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_label: Option<String>,
    /// `ID_PART_ENTRY_TYPE` raw (lowercased GUID for GPT, hex byte for MBR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_type_raw: Option<String>,
    /// `ID_PART_ENTRY_NUMBER`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_number: Option<u32>,
    /// `ID_PART_TABLE_TYPE` (`gpt` / `dos` / `msdos`). Disk-level only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_table_type: Option<String>,
}

impl BlkidInfo {
    /// Classified GPT partition role, derived from `part_type_raw`. Returns
    /// `None` when there is no partition-type data. The probe layer uses
    /// this to populate [`BlockDevice::partition_role`] without duplicating
    /// the GUID table.
    pub fn gpt_role(&self) -> Option<&'static str> {
        let raw = self.part_type_raw.as_ref()?;
        // blkid lowercases GUIDs; normalise defensively.
        if raw.eq_ignore_ascii_case(GPT_ESP_TYPE) {
            return Some("esp");
        }
        if raw.eq_ignore_ascii_case(GPT_BIOS_BOOT) {
            return Some("bios_boot");
        }
        None
    }
}

/// Parse a body in **udev key=value** format (`/run/udev/data/bM:N` or
/// `blkid -p -o udev`). Lines we do not recognise are silently ignored;
/// the udev database carries many unrelated keys (`DEVPATH=`, `SYSCONFIG=`,
/// ...) that we must not choke on.
pub fn parse_udev(body: &str) -> BlkidInfo {
    let mut info = BlkidInfo::default();
    for line in body.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "ID_FS_TYPE" => info.fs_type = Some(value.to_string()),
            "ID_FS_UUID" => info.fs_uuid = Some(value.to_string()),
            "ID_FS_LABEL" => info.fs_label = Some(value.to_string()),
            "ID_FS_USAGE" => info.fs_usage = Some(value.to_string()),
            "ID_PART_ENTRY_UUID" => info.part_uuid = Some(value.to_string()),
            "ID_PART_ENTRY_NAME" => info.part_label = Some(value.to_string()),
            "ID_PART_ENTRY_TYPE" => info.part_type_raw = Some(value.to_ascii_lowercase()),
            "ID_PART_ENTRY_NUMBER" => info.part_number = value.parse().ok(),
            "ID_PART_TABLE_TYPE" => info.part_table_type = Some(value.to_string()),
            // We deliberately ignore the *_ENC variants (url-encoded forms)
            // and all unrelated keys.
            _ => {}
        }
    }
    info.present = has_any_signal(&info);
    info
}

/// Parse a body in **human format** (`blkid /dev/sdX` with no `-o`).
/// Each non-empty line begins with `/dev/NAME:` optionally followed by
/// space-separated `KEY="VALUE"` tokens.
///
/// Returns a map from device name (`sda1`, no `/dev/` prefix) to its info.
/// A line with a device path but no keys means "blkid saw the device but
/// found no signature" — recorded as `present=true` with all fields `None`.
pub fn parse_human(body: &str) -> Vec<(String, BlkidInfo)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((dev_part, rest)) = line.split_once(':') else {
            continue;
        };
        let name = dev_part
            .trim()
            .strip_prefix("/dev/")
            .unwrap_or(dev_part.trim())
            .to_string();
        let mut info = BlkidInfo::default();
        for token in rest.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            // Strip surrounding double quotes.
            let v = value.trim_matches('"');
            match key {
                "TYPE" => info.fs_type = Some(v.to_string()),
                "UUID" => info.fs_uuid = Some(v.to_string()),
                "LABEL" => info.fs_label = Some(v.to_string()),
                "USAGE" => info.fs_usage = Some(v.to_string()),
                "PARTUUID" => info.part_uuid = Some(v.to_string()),
                "PARTLABEL" => info.part_label = Some(v.to_string()),
                "PART_ENTRY_TYPE" => info.part_type_raw = Some(v.to_ascii_lowercase()),
                _ => {}
            }
        }
        // Any entry we produce means blkid saw the device. `present=true`
        // with all-signal-fields-None is the "blkid probed and found no
        // signature" case — distinct from "blkid never probed" (which
        // produces no entry at all, so this code path is never reached).
        info.present = true;
        out.push((name, info));
    }
    out
}

fn has_any_signal(info: &BlkidInfo) -> bool {
    info.fs_type.is_some()
        || info.fs_uuid.is_some()
        || info.fs_label.is_some()
        || info.fs_usage.is_some()
        || info.part_uuid.is_some()
        || info.part_label.is_some()
        || info.part_type_raw.is_some()
        || info.part_table_type.is_some()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic `/run/udev/data/b259:1` content for a CatOS ESP partition
    /// (FAT32, GPT type ESP). Guards against confusing ID_FS_UUID with
    /// ID_PART_ENTRY_UUID.
    #[test]
    fn parses_udev_esp_record() {
        let body = "ID_FS_TYPE=vfat\n\
                    ID_FS_UUID=2CB7-2D33\n\
                    ID_FS_UUID_ENC=2CB7-2D33\n\
                    ID_FS_LABEL=EFI\n\
                    ID_FS_LABEL_ENC=EFI\n\
                    ID_FS_VERSION=FAT32\n\
                    ID_FS_USAGE=filesystem\n\
                    ID_PART_ENTRY_SCHEME=gpt\n\
                    ID_PART_ENTRY_TYPE=c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n\
                    ID_PART_ENTRY_NUMBER=1\n\
                    ID_PART_ENTRY_OFFSET=2048\n\
                    ID_PART_ENTRY_UUID=11111111-2222-3333-4444-555555555555\n\
                    ID_PART_ENTRY_NAME=EFI\\x20system\\x20partition\n\
                    DEVPATH=/devices/.../sda1\n";
        let info = parse_udev(body);
        assert!(info.present);
        assert_eq!(info.fs_type.as_deref(), Some("vfat"));
        assert_eq!(info.fs_uuid.as_deref(), Some("2CB7-2D33"));
        assert_eq!(info.fs_label.as_deref(), Some("EFI"));
        assert_eq!(info.fs_usage.as_deref(), Some("filesystem"));
        // PART_ENTRY_UUID is distinct from FS_UUID.
        assert_eq!(
            info.part_uuid.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(info.part_number, Some(1));
        assert_eq!(info.gpt_role(), Some("esp"));
    }

    /// A btrfs root partition must classify fs_type but NOT as ESP.
    #[test]
    fn parses_udev_btrfs_root() {
        let body = "ID_FS_TYPE=btrfs\n\
                    ID_FS_UUID=3bdc66e2-f30b-4ef1-97f0-c687934e25e2\n\
                    ID_FS_USAGE=filesystem\n\
                    ID_PART_ENTRY_TYPE=0fc63daf-8483-4772-8e79-3d69d8477de4\n";
        let info = parse_udev(body);
        assert!(info.present);
        assert_eq!(info.fs_type.as_deref(), Some("btrfs"));
        assert_eq!(info.gpt_role(), None); // Linux filesystem GUID, not ESP.
    }

    /// An empty or unrelated udev record must report present=false so the
    /// probe layer can distinguish "blkid said nothing" from "blkid said
    /// no filesystem".
    #[test]
    fn empty_udev_record_is_not_present() {
        let body = "DEVPATH=/devices/.../sda\nE: TAGS=:systemd:\n";
        let info = parse_udev(body);
        assert!(!info.present);
    }

    /// LUKS: USAGE=crypto, no FS_TYPE. The planner must be able to detect
    /// this and refuse rather than try to mount a LUKS device raw.
    #[test]
    fn detects_luks_via_usage() {
        let body = "ID_FS_TYPE=crypto_LUKS\nID_FS_UUID=abc-123\nID_FS_USAGE=crypto\n";
        let info = parse_udev(body);
        assert_eq!(info.fs_usage.as_deref(), Some("crypto"));
        assert_eq!(info.fs_type.as_deref(), Some("crypto_LUKS"));
    }

    /// Human-format blkid output. Guards against mishandling the quoted
    /// values and the `/dev/` prefix.
    #[test]
    fn parses_human_format_single_device() {
        let body = "/dev/sda2: UUID=\"3bdc66e2-f30b-4ef1-97f0-c687934e25e2\" BLOCK_SIZE=\"4096\" TYPE=\"btrfs\" PARTUUID=\"a9a4664c-f616-4654-9776-425f004a578e\"";
        let parsed = parse_human(body);
        assert_eq!(parsed.len(), 1);
        let (name, info) = &parsed[0];
        assert_eq!(name, "sda2");
        assert_eq!(info.fs_type.as_deref(), Some("btrfs"));
        assert_eq!(
            info.fs_uuid.as_deref(),
            Some("3bdc66e2-f30b-4ef1-97f0-c687934e25e2")
        );
        assert_eq!(
            info.part_uuid.as_deref(),
            Some("a9a4664c-f616-4654-9776-425f004a578e")
        );
    }

    /// A device that blkid saw but found no signature on must report
    /// present=true with all fields None — NOT collapsed to present=false.
    #[test]
    fn human_format_device_with_no_signature_is_present() {
        let body = "/dev/sda3:";
        let parsed = parse_human(body);
        assert_eq!(parsed.len(), 1);
        let (_, info) = &parsed[0];
        assert!(info.present);
        assert!(info.fs_type.is_none());
    }

    /// GUID case-insensitivity: blkid lowercases, but the ESP GUID must
    /// still match if it arrives uppercased from some other source.
    #[test]
    fn gpt_role_matches_esp_regardless_of_case() {
        let info = BlkidInfo {
            part_type_raw: Some("C12A7328-F81F-11D2-BA4B-00A0C93EC93B".to_string()),
            ..Default::default()
        };
        assert_eq!(info.gpt_role(), Some("esp"));
    }
}
