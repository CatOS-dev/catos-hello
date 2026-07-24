//! Inspection report: top-level structure that JSON contract is built on,
//! plus the target-root inspection sub-model.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::capability::{Capability, CapabilityStatus};
use crate::model::evidence::Evidence;
use crate::model::runtime::{Detection, RuntimeFacts};

/// Subset of `/etc/os-release` we extract. `raw_fields` keeps every key=value
/// pair we successfully parsed so downstream code can look up custom keys
/// without re-reading the file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OsRelease {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_like: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
    /// Every `KEY=VALUE` line successfully parsed, in file order. Values are
    /// de-quoted-normalised (surrounding quotes stripped) but otherwise raw.
    #[serde(default)]
    pub raw_fields: Vec<(String, String)>,
}

impl OsRelease {
    pub fn parse(input: &str) -> OsRelease {
        let mut out = OsRelease::default();
        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_string();
            if key.is_empty() {
                continue;
            }
            let value = normalise_os_release_value(value.trim());
            match key.as_str() {
                "NAME" => out.name = Some(value.clone()),
                "ID" => out.id = Some(value.clone()),
                "ID_LIKE" => out.id_like = Some(value.clone()),
                "VERSION" => out.version = Some(value.clone()),
                "PRETTY_NAME" => out.pretty_name = Some(value.clone()),
                _ => {}
            }
            out.raw_fields.push((key, value));
        }
        out
    }

    /// True if any ID-ish field mentions CatOS.
    pub fn looks_like_catos(&self) -> bool {
        let matches = |s: &Option<String>| {
            s.as_ref()
                .is_some_and(|v| v.to_ascii_lowercase().contains("catos"))
        };
        matches(&self.id) || matches(&self.id_like) || matches(&self.name)
    }
}

fn normalise_os_release_value(raw: &str) -> String {
    let s = raw.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Three-state presence for target-side paths. `Unknown` covers all
/// non-deterministic cases: permission denied, I/O error, broken symlink,
/// etc. Compression of these into a single `false` was the original sin
/// this enum corrects.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    /// Presence could not be determined reliably.
    #[default]
    Unknown,
    /// Path was positively observed to exist.
    Present,
    /// Path was positively observed to NOT exist (no permission / I/O
    /// ambiguity).
    Absent,
}

impl Presence {
    pub fn as_str(self) -> &'static str {
        match self {
            Presence::Present => "present",
            Presence::Absent => "absent",
            Presence::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A target-side tool probe. Status is three-state so permission and I/O
/// failures never collapse into a false "missing" result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPath {
    pub name: String,
    pub path: PathBuf,
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Target-root inspection. Phase 1 only reads files; it does NOT mount,
/// discover block devices, or auto-detect subvolumes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetInspection {
    /// Resolved target root path (as the user passed it).
    pub root: PathBuf,
    /// Parsed `/etc/os-release` if present and readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_release: Option<OsRelease>,
    pub has_fstab: Presence,
    pub has_crypttab: Presence,
    pub has_pacman_db: Presence,
    pub has_usr: Presence,
    pub has_boot: Presence,
    pub has_efi: Presence,
    pub has_boot_efi: Presence,
    /// CatOS-ness of the *target* root, derived from os-release ID fields.
    pub is_catos_target: Detection,
    /// Phase-1 tool probes inside the target root and on the host PATH.
    #[serde(default)]
    pub tool_paths: Vec<ToolPath>,
}

/// Non-fatal notice. Collected in [`InspectionReport::warnings`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

impl Warning {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Top-level report. This is what human/JSON renderers consume and what the
/// JSON contract guarantees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionReport {
    /// Bumped only on backward-incompatible JSON contract changes.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "programVersion")]
    pub program_version: String,
    /// argv[0]-derived invocation name (catos-system / catos-update /
    /// catos-recovery / catos-doctor). Informational only; never used for
    /// permission decisions.
    pub invocation: String,
    #[serde(rename = "targetRoot")]
    pub target_root: PathBuf,
    pub runtime: RuntimeFacts,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    pub target: TargetInspection,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_os_release() {
        let src = "# comment\nNAME=\"CatOS\"\nID=catos\nID_LIKE=arch\nVERSION=1\n";
        let p = OsRelease::parse(src);
        assert_eq!(p.name.as_deref(), Some("CatOS"));
        assert_eq!(p.id.as_deref(), Some("catos"));
        assert_eq!(p.id_like.as_deref(), Some("arch"));
        assert!(p.looks_like_catos());
    }

    #[test]
    fn os_release_handles_single_quotes_and_bare() {
        let p = OsRelease::parse("NAME='Arch'\nPRETTY_NAME=Arch Linux");
        assert_eq!(p.name.as_deref(), Some("Arch"));
        assert_eq!(p.pretty_name.as_deref(), Some("Arch Linux"));
        assert!(!p.looks_like_catos());
    }

    #[test]
    fn os_release_skips_malformed_lines() {
        let p = OsRelease::parse("garbage line\n=\nID=arch\n");
        assert_eq!(p.id.as_deref(), Some("arch"));
        // The "garbage line" with no = and the empty-key "=" should be dropped.
        assert_eq!(p.raw_fields.len(), 1);
    }
}
