//! Safety layer: target selection, mounted-state refusal, running-
//! root refusal.
//!
//! This module is the ONLY place that decides whether a repair flow
//! may proceed. The orchestrator calls [`evaluate_safety`] with the
//! discovered devices and the user's explicit selection; the
//! verdict is binding.
//!
//! ## Hard rules
//!
//! * A device that backs the running root is ALWAYS refused. We do
//!   not trust the user's explicit selection to override this; an
//!   operator who explicitly asks `catos-repair fs /dev/sda1` while
//!   /dev/sda1 is `/` is making a mistake, not giving consent.
//! * A device that is already mounted (and we did not mount it) is
//!   ALWAYS refused. Repair tools require an unmounted target.
//! * Multiple equally-plausible candidates with no explicit choice
//!   is ALWAYS refused. We never guess.
//! * ESP, swap, LUKS container, LVM PV, mdraid member are NEVER
//!   auto-selected; they can only be explicit user choices.
//!
//! ## What this module does NOT do
//!
//! * It does not invoke any repair tool.
//! * It does not mount or unmount anything.
//! * It does not modify any state.

use std::path::{Path, PathBuf};

use crate::shared::model::evidence::Evidence;
use crate::target::model::{BlockDevice, PartitionRole};

/// The user's explicit choices for the repair flow. Distinct from
/// `cli::TargetSelection` because repair only ever needs ONE device
/// (we do not mount sub-volumes or ESPs alongside).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairTargetSelection {
    /// `catos-repair fs /dev/...` — the only block device we will
    /// consider. When set, candidate discovery is bypassed entirely
    /// and the explicit device is used (subject to safety checks).
    pub explicit_device: Option<PathBuf>,
}

/// What [`evaluate_safety`] concluded. The orchestrator matches on
/// `verdict` to decide whether to proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyDecision {
    pub verdict: SafetyVerdict,
    /// Evidence trail explaining the verdict. Always populated;
    /// refusals include the reason verbatim so the report can show
    /// "we refused because X".
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    /// Cleared to proceed. Carries the chosen device path and the
    /// filesystem type that device reports. The filesystem type may
    /// still be `None` if the device's signature could not be probed;
    /// the orchestrator treats that as `Unsupported`.
    Proceed {
        device: PathBuf,
        filesystem: Option<String>,
        was_mounted_before_session: bool,
    },
    /// Refused: the user supplied multiple equally-plausible
    /// candidates without an explicit `--device`. The list shows
    /// what we found.
    AmbiguousTarget { candidates: Vec<String> },
    /// Refused: the chosen device IS the running root.
    RunningRoot { device: PathBuf },
    /// Refused: the chosen device is mounted and we did not mount
    /// it. Repair tools require an unmounted target.
    Mounted {
        device: PathBuf,
        mount_point: PathBuf,
    },
    /// Refused: the explicit device is not one of the discovered
    /// block devices, or does not exist.
    DeviceNotFound { requested: PathBuf },
    /// Refused: the explicit device is a class we never auto-repair
    /// even when the user selected it explicitly. Currently this is
    /// just `swap` and other pseudo filesystems; ESP/FAT may be
    /// repaired when explicitly chosen (the spec only forbids
    /// auto-selecting ESP).
    UnsupportedRole { requested: PathBuf, reason: String },
}

impl SafetyVerdict {
    pub fn is_proceed(&self) -> bool {
        matches!(self, SafetyVerdict::Proceed { .. })
    }
}

/// Evaluate safety for the repair flow. Pure function of the
/// discovered device set and the user's explicit selection; no I/O
/// beyond the input slices.
///
/// Resolution order:
///   1. If the user supplied an explicit device, that device MUST be
///      present in `devices` and MUST NOT be the running root or
///      already mounted.
///   2. Otherwise, pick the unique root candidate with sufficient
///      confidence. Multiple candidates at the same confidence
///      level is AmbiguousTarget.
///   3. ESP, swap, LUKS, LVM PV, mdraid member are NEVER auto-
///      picked. They can only be repaired via explicit selection
///      (and even then, swap is refused because it has no fsck
///      surface).
pub fn evaluate_safety(
    devices: &[BlockDevice],
    selection: &RepairTargetSelection,
    running_root_device: Option<&RunningRootDevice>,
) -> SafetyDecision {
    let mut evidence = Vec::new();

    if let Some(explicit) = &selection.explicit_device {
        evidence.push(Evidence::new(
            "EXPLICIT_TARGET",
            "repair::safety",
            "operator supplied explicit block device".to_string(),
        ));
        return decide_explicit(devices, explicit, running_root_device, evidence);
    }

    evidence.push(Evidence::new(
        "AUTO_DISCOVERY",
        "repair::safety",
        "raw block-device discovery is insufficient for automatic repair; a verified CatOS root must be selected by the orchestrator",
    ));
    SafetyDecision {
        verdict: SafetyVerdict::AmbiguousTarget {
            candidates: Vec::new(),
        },
        evidence,
    }
}

fn decide_explicit(
    devices: &[BlockDevice],
    requested: &Path,
    running_root_device: Option<&RunningRootDevice>,
    mut evidence: Vec<Evidence>,
) -> SafetyDecision {
    let Some(device) = devices.iter().find(|d| {
        d.dev_path
            .as_ref()
            .is_some_and(|p| paths_equal(p, requested))
    }) else {
        evidence.push(Evidence::new(
            "DEVICE_NOT_FOUND",
            "repair::safety",
            format!(
                "explicit device {} was not in the discovered device set",
                requested.display()
            ),
        ));
        return SafetyDecision {
            verdict: SafetyVerdict::DeviceNotFound {
                requested: requested.to_path_buf(),
            },
            evidence,
        };
    };

    // Refuse swap regardless of explicit selection: swap has no fsck
    // surface; "repairing" it would mean reformatting, which the
    // spec forbids.
    if let Some(fs) = device.filesystem.as_deref() {
        if fs == "swap" {
            evidence.push(Evidence::new(
                "REFUSED_SWAP",
                "repair::safety",
                format!(
                    "device {} reports fstype=swap; swap has no fsck surface and we do not format",
                    requested.display()
                ),
            ));
            return SafetyDecision {
                verdict: SafetyVerdict::UnsupportedRole {
                    requested: requested.to_path_buf(),
                    reason: "swap filesystem has no fsck surface; repair would require reformatting which the spec forbids".to_string(),
                },
                evidence,
            };
        }
    }

    refuse_unsafe_running_root_or_mounted(device, running_root_device, evidence)
}

/// Continue the decision after we have a definite `device`. This is
/// shared between the explicit-selection and auto-discovery paths so
/// the safety checks (running root, mounted) cannot diverge.
fn refuse_unsafe_running_root_or_mounted(
    device: &BlockDevice,
    running_root_device: Option<&RunningRootDevice>,
    mut evidence: Vec<Evidence>,
) -> SafetyDecision {
    let Some(dev_path) = device.dev_path.clone() else {
        evidence.push(Evidence::new(
            "DEVICE_HAS_NO_DEV_PATH",
            "repair::safety",
            format!(
                "device {} has no stable /dev path; cannot address it for repair",
                device.name
            ),
        ));
        return SafetyDecision {
            verdict: SafetyVerdict::DeviceNotFound {
                requested: PathBuf::from(format!("/dev/{}", device.name)),
            },
            evidence,
        };
    };

    // Refuse the running root. Even if the user explicitly selected
    // it, repairing the live root is corrupting the live system.
    if let Some(running) = running_root_device {
        if paths_equal(&dev_path, &running.device)
            || running
                .alternate_paths
                .iter()
                .any(|alt| paths_equal(alt, &dev_path))
        {
            evidence.push(Evidence::new(
                "REFUSED_RUNNING_ROOT",
                "repair::safety",
                format!(
                    "device {} is the running root (mounted at {}); refusing to repair",
                    dev_path.display(),
                    running.mount_point.display()
                ),
            ));
            return SafetyDecision {
                verdict: SafetyVerdict::RunningRoot { device: dev_path },
                evidence,
            };
        }
    }

    // Refuse a mounted target. The spec requires the target to be
    // unmounted when repair tools run.
    if device.mounted_before_session {
        if let Some(mount_point) = device.mount_point.clone() {
            evidence.push(Evidence::new(
                "REFUSED_MOUNTED",
                "repair::safety",
                format!(
                    "device {} is mounted at {}; target must be unmounted before repair",
                    dev_path.display(),
                    mount_point.display()
                ),
            ));
            return SafetyDecision {
                verdict: SafetyVerdict::Mounted {
                    device: dev_path,
                    mount_point,
                },
                evidence,
            };
        }
        // mounted_before_session is true but we have no mount_point:
        // fail closed. The spec says "无法确认挂载状态时按不安全
        // 处理并拒绝" — when mount state is indeterminate, treat as
        // unsafe.
        evidence.push(Evidence::new(
            "REFUSED_MOUNT_STATE_UNKNOWN",
            "repair::safety",
            format!(
                "device {} reports mounted_before_session but we have no mount_point; treating as mounted and refusing",
                dev_path.display()
            ),
        ));
        return SafetyDecision {
            verdict: SafetyVerdict::Mounted {
                device: dev_path.clone(),
                mount_point: PathBuf::from("<unknown>"),
            },
            evidence,
        };
    }

    evidence.push(Evidence::new(
        "PROCEED",
        "repair::safety",
        format!(
            "target {} fstype={:?} is unmounted and is not the running root; clearing for repair",
            dev_path.display(),
            device.filesystem.as_deref().unwrap_or("?")
        ),
    ));

    SafetyDecision {
        verdict: SafetyVerdict::Proceed {
            device: dev_path,
            filesystem: device.filesystem.clone(),
            was_mounted_before_session: false,
        },
        evidence,
    }
}

/// A snapshot of the currently-running root, captured BEFORE the
/// repair flow starts. Used by [`evaluate_safety`] to refuse
/// repairing `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningRootDevice {
    /// `/proc/self/mountinfo`'s `/` mount point.
    pub mount_point: PathBuf,
    /// The block device that backs `/` (preferred form, e.g.
    /// `/dev/mapper/root` or `/dev/nvme0n1p2`).
    pub device: PathBuf,
    /// Other paths that resolve to the same device (e.g. `/dev/disk/
    /// by-uuid/...` entries). We refuse if ANY of these match the
    /// selected target.
    pub alternate_paths: Vec<PathBuf>,
}

/// Predicate: is this device a plausible root candidate worth auto-
/// selecting? Excludes ESP, swap, LUKS containers, LVM PVs, mdraid
/// members, and pseudo filesystems. A device with no filesystem
/// signature is NOT a candidate (we cannot repair what we cannot
/// identify).
pub fn is_plausible_root_candidate(device: &BlockDevice) -> bool {
    // ESP partitions are NEVER auto-selected. The spec explicitly
    // says FAT ESPs are not auto-repair targets.
    if matches!(device.partition_role, PartitionRole::Esp) {
        return false;
    }
    // swap, LUKS, LVM PV, mdraid members never have a usable fsck
    // surface.
    let Some(fs) = device.filesystem.as_deref() else {
        return false;
    };
    matches!(fs, "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" | "btrfs")
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    // Lexical compare is sufficient because both sides come from
    // either the user or /sys/dev/... canonical paths. We do NOT
    // canonicalize here because canonicalize(2) requires the path
    // to exist and we may be running in a namespace where it does
    // not (e.g. tests).
    a == b
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::model::{DeviceClass, DiskKind};

    fn ext4_root(name: &str, dev: &str) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            dev_path: Some(PathBuf::from(dev)),
            major_minor: Some("8:1".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(1),
            size_sectors: Some(1_000_000),
            read_only: false,
            removable: false,
            filesystem: Some("ext4".into()),
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: vec![],
            mounted_before_session: false,
            evidence: vec![],
        }
    }

    fn esp_device() -> BlockDevice {
        let mut d = ext4_root("sda1", "/dev/sda1");
        d.partition_role = PartitionRole::Esp;
        d.filesystem = Some("vfat".into());
        d
    }

    fn swap_device() -> BlockDevice {
        let mut d = ext4_root("sda2", "/dev/sda2");
        d.filesystem = Some("swap".into());
        d
    }

    fn running_root() -> RunningRootDevice {
        RunningRootDevice {
            mount_point: PathBuf::from("/"),
            device: PathBuf::from("/dev/sda3"),
            alternate_paths: vec![PathBuf::from("/dev/disk/by-uuid/abc")],
        }
    }

    #[test]
    fn explicit_device_proceeds_when_unmounted_and_not_root() {
        let devices = vec![ext4_root("sda1", "/dev/sda1")];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda1")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        match decision.verdict {
            SafetyVerdict::Proceed {
                device,
                filesystem,
                was_mounted_before_session,
            } => {
                assert_eq!(device, PathBuf::from("/dev/sda1"));
                assert_eq!(filesystem.as_deref(), Some("ext4"));
                assert!(!was_mounted_before_session);
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    #[test]
    fn explicit_device_refused_when_not_discovered() {
        let devices = vec![ext4_root("sda1", "/dev/sda1")];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda9")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(matches!(
            decision.verdict,
            SafetyVerdict::DeviceNotFound { .. }
        ));
    }

    #[test]
    fn explicit_device_refused_when_it_is_running_root() {
        let devices = vec![ext4_root("sda3", "/dev/sda3")];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda3")),
        };
        let decision = evaluate_safety(&devices, &selection, Some(&running_root()));
        assert!(matches!(
            decision.verdict,
            SafetyVerdict::RunningRoot { .. }
        ));
    }

    #[test]
    fn explicit_device_refused_via_alternate_path() {
        // The operator may select /dev/disk/by-uuid/abc instead of
        // the canonical /dev/sda3; we still recognise it as the
        // running root via alternate_paths.
        let devices = vec![ext4_root("sda3", "/dev/sda3")];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/disk/by-uuid/abc")),
        };
        // Adjust the device's dev_path to match the explicit selection
        // so we get past DeviceNotFound; the running-root check then
        // catches it via alternate_paths.
        let mut devices = devices;
        devices[0].dev_path = Some(PathBuf::from("/dev/disk/by-uuid/abc"));
        let decision = evaluate_safety(&devices, &selection, Some(&running_root()));
        assert!(matches!(
            decision.verdict,
            SafetyVerdict::RunningRoot { .. }
        ));
    }

    #[test]
    fn explicit_device_refused_when_already_mounted() {
        let mut devices = vec![ext4_root("sda1", "/dev/sda1")];
        devices[0].mounted_before_session = true;
        devices[0].mount_point = Some(PathBuf::from("/mnt/target"));
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda1")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        match decision.verdict {
            SafetyVerdict::Mounted {
                device,
                mount_point,
            } => {
                assert_eq!(device, PathBuf::from("/dev/sda1"));
                assert_eq!(mount_point, PathBuf::from("/mnt/target"));
            }
            other => panic!("expected Mounted, got {other:?}"),
        }
    }

    #[test]
    fn explicit_swap_device_is_refused_as_unsupported_role() {
        // swap has no fsck surface. The spec forbids auto-format;
        // we extend that to "no auto-repair of swap either" because
        // swap repair would mean re-creation.
        let devices = vec![swap_device()];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda2")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(matches!(
            decision.verdict,
            SafetyVerdict::UnsupportedRole { .. }
        ));
    }

    #[test]
    fn raw_auto_discovery_never_selects_a_filesystem() {
        let devices = vec![ext4_root("sda1", "/dev/sda1")];
        let selection = RepairTargetSelection::default();
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(
            matches!(decision.verdict, SafetyVerdict::AmbiguousTarget { candidates } if candidates.is_empty())
        );
    }

    #[test]
    fn raw_auto_discovery_does_not_leak_unverified_candidates() {
        let devices = vec![
            ext4_root("sda1", "/dev/sda1"),
            ext4_root("sdb1", "/dev/sdb1"),
        ];
        let selection = RepairTargetSelection::default();
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(
            matches!(decision.verdict, SafetyVerdict::AmbiguousTarget { candidates } if candidates.is_empty())
        );
    }

    #[test]
    fn auto_discovery_refuses_zero_candidates() {
        // No devices at all -> AmbiguousTarget with empty candidate
        // list. Distinct from "device not found" (which only fires
        // for explicit selections).
        let devices = vec![];
        let selection = RepairTargetSelection::default();
        let decision = evaluate_safety(&devices, &selection, None);
        match decision.verdict {
            SafetyVerdict::AmbiguousTarget { candidates } => {
                assert!(candidates.is_empty());
            }
            other => panic!("expected AmbiguousTarget, got {other:?}"),
        }
    }

    #[test]
    fn auto_discovery_skips_esp_and_swap() {
        // ESPs and swaps are NEVER auto-picked. If they are the only
        // devices, we report AmbiguousTarget (zero root candidates).
        let devices = vec![esp_device(), swap_device()];
        let selection = RepairTargetSelection::default();
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(matches!(
            decision.verdict,
            SafetyVerdict::AmbiguousTarget { .. }
        ));
    }

    #[test]
    fn explicit_esp_selection_is_allowed() {
        // The spec says FAT ESPs are not AUTO-repair targets, but
        // the operator may explicitly select one for repair. This
        // test pins that contract.
        let devices = vec![esp_device()];
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda1")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        match decision.verdict {
            SafetyVerdict::Proceed { filesystem, .. } => {
                assert_eq!(filesystem.as_deref(), Some("vfat"));
            }
            other => panic!("expected Proceed for explicit ESP, got {other:?}"),
        }
    }

    #[test]
    fn mounted_state_indeterminate_is_refused() {
        // mounted_before_session=true but mount_point=None: treat as
        // unsafe. The spec is explicit: "无法确认挂载状态时按不
        // 安全处理并拒绝".
        let mut devices = vec![ext4_root("sda1", "/dev/sda1")];
        devices[0].mounted_before_session = true;
        devices[0].mount_point = None;
        let selection = RepairTargetSelection {
            explicit_device: Some(PathBuf::from("/dev/sda1")),
        };
        let decision = evaluate_safety(&devices, &selection, None);
        assert!(matches!(decision.verdict, SafetyVerdict::Mounted { .. }));
    }
}
