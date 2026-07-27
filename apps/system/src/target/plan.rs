//! Target selection plan — the mount-free entry point Doctor and other
//! read-only consumers use to identify "the target" without going through
//! `repair`.
//!
//! Decision tree (mirrors the original Doctor target-selection spec):
//!
//! 1. If `/` is uniquely confirmed as CatOS via `/etc/os-release`, select
//!    the running root.
//! 2. Otherwise, surface `None`. We deliberately do NOT mount candidate
//!    devices here — that is `repair`'s job. Phase-1 target discovery is
//!    strictly read-only.
//!
//! The point of this module is the dependency direction: `target::plan`
//! depends only on `target::diagnose` and std; it never reaches into
//! `repair`, `mount`, `snapshot`, or `boot`.

use std::path::PathBuf;

use crate::target::diagnose::filesystem::RealFilesystem;
use crate::target::diagnose::runtime::detect_runtime;
use crate::target::diagnose::system_root::SystemRoot;
use crate::target::model::{DetectionStatus, PrimaryRuntimeMode, TargetIdentity};

/// The high-level outcome of target discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlanKind {
    /// The running root (`/`) was uniquely confirmed as CatOS.
    RunningRoot,
    /// A different offline root was identified.
    Offline,
    /// Multiple high-confidence targets; caller must disambiguate.
    Ambiguous,
    /// No unique CatOS target could be identified.
    None,
}

/// A target-discovery plan. Carries the resolved identity (when any) and
/// a kind tag. This is the type Doctor consumes directly.
#[derive(Debug, Clone)]
pub struct TargetPlan {
    pub kind: TargetPlanKind,
    pub identity: Option<TargetIdentity>,
    pub candidates: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for TargetPlan {
    fn default() -> Self {
        TargetPlan {
            kind: TargetPlanKind::None,
            identity: None,
            candidates: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Discover the target without mounting anything. Reads `/etc/os-release`
/// and `/proc/self/mountinfo` through the real filesystem; if `/` looks
/// like a CatOS system, returns `RunningRoot`. Otherwise returns `None`.
///
/// This is intentionally conservative: it never invents a target from a
/// guess. When more certainty is required (e.g. offline target content
/// inspection), the caller must invoke `repair`, which is allowed to
/// mount.
pub fn discover_target_plan() -> TargetPlan {
    discover_target_plan_with(&RealFilesystem)
}

/// Injecting variant used by tests.
pub fn discover_target_plan_with(fs: &RealFilesystem) -> TargetPlan {
    let mut warnings = Vec::new();

    let runtime = detect_runtime(fs);
    if runtime.is_live_environment.is_detected() {
        // A live environment is never itself "the target"; force None so
        // Doctor surfaces "boot the installed system or pick a device".
        return TargetPlan {
            kind: TargetPlanKind::None,
            identity: None,
            candidates: Vec::new(),
            warnings: vec!["running in a live environment; no in-place target".to_string()],
        };
    }

    if runtime.primary_mode() == PrimaryRuntimeMode::Initramfs {
        return TargetPlan {
            kind: TargetPlanKind::None,
            identity: None,
            candidates: Vec::new(),
            warnings: vec!["running in initramfs; no in-place target".to_string()],
        };
    }

    // Try to confirm `/` as CatOS by reading /etc/os-release confined to
    // the running root.
    match SystemRoot::from_user_input("/") {
        Ok(root) => {
            let inspection =
                crate::target::diagnose::candidate::inspect_target(fs, &root, &mut warnings);
            if inspection.is_catos_target.status == DetectionStatus::Detected {
                TargetPlan {
                    kind: TargetPlanKind::RunningRoot,
                    identity: Some(TargetIdentity {
                        root: PathBuf::from("/"),
                        root_device: None,
                        root_fstype: None,
                        root_subvol: None,
                        root_uuid: None,
                    }),
                    candidates: Vec::new(),
                    warnings,
                }
            } else {
                TargetPlan {
                    kind: TargetPlanKind::None,
                    identity: None,
                    candidates: Vec::new(),
                    warnings,
                }
            }
        }
        Err(error) => TargetPlan {
            kind: TargetPlanKind::None,
            identity: None,
            candidates: Vec::new(),
            warnings: vec![format!("cannot resolve running root: {error}")],
        },
    }
}
