//! Runtime facts: orthogonal boolean-ish detections about the running
//! environment, each carrying evidence and a three-state status.

use serde::{Deserialize, Serialize};

use crate::shared::model::evidence::Evidence;

/// Three-state detection. Never collapse to `bool`: `Unknown` is
/// semantically different from `NotDetected` and must survive serialisation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    /// Positive evidence that the condition holds.
    Detected,
    /// Positive evidence that the condition does NOT hold.
    NotDetected,
    /// Evidence insufficient or conflicting. Never used as "default".
    #[default]
    Unknown,
}

/// A single detection result, with the evidence trail behind it.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Detection {
    pub status: DetectionStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl Detection {
    pub fn detected(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::Detected,
            evidence,
        }
    }

    pub fn not_detected(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::NotDetected,
            evidence,
        }
    }

    pub fn unknown(evidence: Vec<Evidence>) -> Self {
        Self {
            status: DetectionStatus::Unknown,
            evidence,
        }
    }

    pub fn is_detected(&self) -> bool {
        matches!(self.status, DetectionStatus::Detected)
    }

    /// Combine two partial detections into one. Conflict -> Unknown.
    pub fn merge(self, other: Detection) -> Detection {
        use DetectionStatus::*;
        let mut evidence = self.evidence;
        evidence.extend(other.evidence);
        let status = match (self.status, other.status) {
            (Detected, Detected) => Detected,
            (NotDetected, NotDetected) => NotDetected,
            (a, Unknown) => a,
            (Unknown, b) => b,
            // Any mixed Detected/NotDetected pair is a conflict.
            _ => Unknown,
        };
        Detection { status, evidence }
    }
}

/// Orthogonal runtime facts. Multiple can be true simultaneously, e.g.
/// running from a LiveCD inside a chroot, or initramfs with a mounted target.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RuntimeFacts {
    pub is_initramfs: Detection,
    pub is_chroot: Detection,
    pub is_live_environment: Detection,
    pub is_snapshot_boot: Detection,
    pub has_systemd: Detection,
    pub root_is_read_only: Detection,
}

/// A convenience view for human display. Derived from facts, never replaces
/// them: the JSON contract always carries the underlying `Detection`s.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryRuntimeMode {
    RunningSystem,
    Chroot,
    LiveEnvironment,
    Initramfs,
    Unknown,
}

impl RuntimeFacts {
    /// Pick a single most-representative mode for human display.
    ///
    /// Rule precedence is documented so behaviour is reproducible:
    ///   1. initramfs wins (we are inside the early-boot environment)
    ///   2. live environment
    ///   3. chroot
    ///   4. running system (the default positive state)
    ///
    /// `is_snapshot_boot` is intentionally NOT consulted here: it is an
    /// orthogonal attribute (a running system can ALSO be booted from a
    /// snapshot). Letting it participate produced false `Unknown` on every
    /// Btrfs system whose subvol path did not contain "snapshot", which is
    /// the common case.
    ///
    /// `RunningSystem` is returned only when initramfs, live, and chroot have
    /// all been positively ruled out. If any of those axes remains Unknown,
    /// the primary mode remains Unknown rather than inventing certainty.
    pub fn primary_mode(&self) -> PrimaryRuntimeMode {
        use DetectionStatus::*;
        if matches!(self.is_initramfs.status, Detected) {
            return PrimaryRuntimeMode::Initramfs;
        }
        if matches!(self.is_live_environment.status, Detected) {
            return PrimaryRuntimeMode::LiveEnvironment;
        }
        if matches!(self.is_chroot.status, Detected) {
            return PrimaryRuntimeMode::Chroot;
        }
        if [
            self.is_initramfs.status,
            self.is_live_environment.status,
            self.is_chroot.status,
        ]
        .iter()
        .all(|status| matches!(status, NotDetected))
        {
            PrimaryRuntimeMode::RunningSystem
        } else {
            PrimaryRuntimeMode::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_conflict_produces_unknown() {
        let a = Detection::detected(vec![]);
        let b = Detection::not_detected(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Unknown);
    }

    #[test]
    fn merge_same_status_preserves_it() {
        let a = Detection::detected(vec![]);
        let b = Detection::detected(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Detected);
    }

    #[test]
    fn merge_with_unknown_preserves_other() {
        let a = Detection::detected(vec![]);
        let b = Detection::unknown(vec![]);
        assert_eq!(a.merge(b).status, DetectionStatus::Detected);
    }

    #[test]
    fn unknown_status_does_not_serialize_as_false() {
        let d = Detection::unknown(vec![]);
        let json = serde_json::to_string(&d.status).unwrap();
        assert_eq!(json, "\"unknown\"");
        assert_ne!(json, "false");
    }

    #[test]
    fn primary_mode_is_unknown_when_special_environment_is_unresolved() {
        let facts = RuntimeFacts::default();
        assert_eq!(facts.primary_mode(), PrimaryRuntimeMode::Unknown);
    }

    #[test]
    fn primary_mode_is_running_only_when_special_environments_are_ruled_out() {
        let not_detected = || Detection::not_detected(vec![]);
        let facts = RuntimeFacts {
            is_initramfs: not_detected(),
            is_chroot: not_detected(),
            is_live_environment: not_detected(),
            is_snapshot_boot: Detection::unknown(vec![]),
            has_systemd: Detection::unknown(vec![]),
            root_is_read_only: Detection::unknown(vec![]),
        };
        assert_eq!(facts.primary_mode(), PrimaryRuntimeMode::RunningSystem);
    }

    #[test]
    fn snapshot_status_does_not_override_running_system_mode() {
        let not_detected = || Detection::not_detected(vec![]);
        let facts = RuntimeFacts {
            is_initramfs: not_detected(),
            is_chroot: not_detected(),
            is_live_environment: not_detected(),
            is_snapshot_boot: Detection::detected(vec![]),
            has_systemd: Detection::detected(vec![]),
            root_is_read_only: Detection::not_detected(vec![]),
        };
        assert_eq!(facts.primary_mode(), PrimaryRuntimeMode::RunningSystem);
    }
}
