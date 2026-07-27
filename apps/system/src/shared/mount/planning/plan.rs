//! Mount plan construction.
//!
//! Given a [`crate::shared::model::mount::MountPlan`] skeleton (target root, fstab
//! entries, discovered devices) produce the final ordered list of
//! [`MountStep`]s with per-fstype read-only safety options applied.
//!
//! ## Per-filesystem read-only safety
//!
//! Phase 2 supports ONLY read-only mounts and only of filesystems where
//! the kernel can guarantee zero writes to the underlying device on mount.
//! The decision matrix is derived from kernel source behaviour, NOT from
//! `mount(8)` man pages (which describe intent, not behaviour):
//!
//! | fstype           | safe option set                              | why                                                                                              | kernel source                                                                                                       |
//! |------------------|----------------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
//! | ext2 / ext3 / ext4 | `ro,noload`                                 | `noload` skips `ext4_load_journal` so a dirty journal is NOT replayed. `ro` alone replays it.    | `fs/ext4/super.c::ext4_fill_super`, `EXT4_MOUNT_NOLOAD`                                                             |
//! | btrfs            | `ro,rescue=nologreplay` (+ `subvol=`/`subvolid=`) | suppresses tree-log replay; standalone `nologreplay` was removed in Linux 6.16. | Btrfs mount-option documentation / `fs/btrfs/fs_context.c` |
//! | xfs              | `ro,norecovery`                              | `norecovery` sets `XFS_MOUNT_NORECOVERY`, skipping `xlog_recover`. Plain `ro` replays the log.   | `fs/xfs/xfs_super.c::xfs_fs_fill_super`, `fs/xfs/xfs_log.c::xlog_recover`                                           |
//! | f2fs             | `ro,norecovery,disable_roll_forward`         | both options together skip `f2fs_recover_fsync_data` and roll-forward recovery.                 | `fs/f2fs/super.c::f2fs_fill_super`, `CP_DISABLE_ROLL_FORWARD` flag                                                 |
//! | vfat / fat       | `ro`                                         | no journal, no recovery path.                                                                    | `fs/fat/inode.c::fat_fill_super`                                                                                    |
//! | exfat            | `ro`                                         | no journal, no recovery path.                                                                    | `fs/exfat/super.c::exfat_fill_super`                                                                                |
//! | swap             | (refused)                                    | no read-only mount concept; activation would write the swap header.                              | `mm/swapfile.c`                                                                                                     |
//! | anything else    | (refused)                                    | unknown semantics; refuse rather than guess.                                                     | —                                                                                                                   |
//!
//! `noload` on ext4 and `norecovery` on xfs have a real cost: on a dirty
//! filesystem they mount the *pre-journal* state, which may be slightly
//! stale. For phase-2 read-only inspection that is the correct tradeoff
//! (we explicitly prefer "no writes" over "current data"). The plan
//! surfaces this tradeoff via [`MountStep::failure_modes`] so the human
//! renderer can show it to the user before they say "go".
//!
//! ## Build path
//!
//! The plan builder is mostly pure: it consults fstab entries, device
//! hints, and the per-fstype table above. The only I/O it does is resolving
//! a device reference (UUID/PARTUUID/LABEL/PARTLABEL/Path) to a concrete
//! `/dev/...` path, which is delegated to [`DeviceResolver`]. Tests use a
//! fixture resolver.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::shared::model::evidence::Evidence;
use crate::shared::model::fstab::{FstabEntry, FstabEntryKind, FstabSource};
use crate::shared::model::mount::{MountError, MountErrorKind, MountPlan, MountStep, NamespaceState};
use crate::target::model::BlockDevice;

// ---------------------------------------------------------------------------
// Per-fstype option table
// ---------------------------------------------------------------------------

/// Classification of a fstype for phase-2 mount safety. Pure data; the
/// planner consults [`FstypePolicy::for_fstype`] to decide what to do.
#[derive(Debug, Clone)]
pub enum FstypePolicy {
    /// Mountable read-only with the given option suffix (added after the
    /// mandatory `ro`). `failure_modes` are surfaced in the plan so the
    /// human renderer can warn the user before they say "go".
    Safe {
        options: Vec<&'static str>,
        /// Honest statement of what the safety options cost (e.g.
        /// "stale data on dirty journal"). Empty when there is no cost.
        failure_modes: Vec<&'static str>,
    },
    /// Refused for phase 2. The reason is part of the JSON contract so
    /// downstream tooling can show why we refused instead of guessing.
    Refused {
        kind: MountErrorKind,
        reason: &'static str,
    },
}

impl FstypePolicy {
    /// The single source of truth for which fstypes phase 2 will mount.
    /// Adding a fstype here requires a kernel-source citation above and
    /// a test that pins the option set.
    pub fn for_fstype(fstype: &str) -> FstypePolicy {
        match fstype {
            "ext2" | "ext3" | "ext4" => FstypePolicy::Safe {
                options: vec!["noload"],
                failure_modes: vec!["on a dirty journal the visible data is the pre-journal state"],
            },
            "btrfs" => FstypePolicy::Safe {
                // Btrfs replays the tree log even for a read-only mount.
                // Linux 6.16 removed the deprecated standalone
                // `nologreplay`; the supported form is rescue=nologreplay.
                options: vec!["rescue=nologreplay"],
                failure_modes: vec![
                    "pending tree-log updates are deliberately not replayed; the visible state may be older",
                ],
            },
            "xfs" => FstypePolicy::Safe {
                options: vec!["norecovery"],
                failure_modes: vec![
                    "on a dirty log the visible data is the pre-log state",
                    "xfs refuses to mount with norecovery when the primary superblock is corrupt",
                ],
            },
            "f2fs" => FstypePolicy::Safe {
                options: vec!["norecovery", "disable_roll_forward"],
                failure_modes: vec![
                    "fsync data not yet checkpointed is invisible",
                    "roll-forward recovery skipped; recent changes may be absent",
                ],
            },
            "vfat" | "msdos" | "fat" | "fat32" | "fat16" | "fat12" => FstypePolicy::Safe {
                options: vec![],
                failure_modes: vec![],
            },
            "exfat" => FstypePolicy::Safe {
                options: vec![],
                failure_modes: vec![],
            },
            "swap" => FstypePolicy::Refused {
                kind: MountErrorKind::UnsupportedFilesystem,
                reason: "swap has no read-only mount; activation writes the swap header",
            },
            _ => FstypePolicy::Refused {
                kind: MountErrorKind::UnsupportedFilesystem,
                reason: "fstype not in the phase-2 read-only allow-list",
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Device reference resolver (the only I/O surface)
// ---------------------------------------------------------------------------

/// Resolve an [`FstabSource`] to a concrete `/dev/...` path against the
/// set of discovered devices. Implementations are pure functions over the
/// device list; tests use the same impl as production.
pub trait DeviceResolver {
    fn resolve(&self, source: &FstabSource) -> Resolution;
}

/// Result of resolving one source. The planner must handle every arm.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Exactly one device matches. Boxed because `BlockDevice` is large
    /// (320+ bytes); boxing keeps the enum cheap to pass around.
    One(Box<BlockDevice>),
    /// No device matches. Distinct from Ambiguous: zero is a positive
    /// "this fstab entry points at nothing we can see" finding.
    Zero { source: String },
    /// Multiple devices match. The planner must surface this as an
    /// ambiguity, never silently pick the first.
    Many { source: String, count: usize },
}

/// Default resolver: indexes devices by the four blkid identifiers.
pub struct IndexResolver<'a> {
    by_uuid: HashMap<String, &'a BlockDevice>,
    by_part_uuid: HashMap<String, &'a BlockDevice>,
    by_label: HashMap<String, Vec<&'a BlockDevice>>,
    by_part_label: HashMap<String, Vec<&'a BlockDevice>>,
    by_path: HashMap<String, &'a BlockDevice>,
    all: &'a [BlockDevice],
}

impl<'a> IndexResolver<'a> {
    pub fn new(devices: &'a [BlockDevice]) -> Self {
        let mut by_uuid: HashMap<String, &'a BlockDevice> = HashMap::new();
        let mut by_part_uuid: HashMap<String, &'a BlockDevice> = HashMap::new();
        let mut by_label: HashMap<String, Vec<&'a BlockDevice>> = HashMap::new();
        let mut by_part_label: HashMap<String, Vec<&'a BlockDevice>> = HashMap::new();
        let mut by_path: HashMap<String, &'a BlockDevice> = HashMap::new();
        for d in devices {
            if let Some(u) = &d.uuid {
                by_uuid.entry(u.clone()).or_insert(d);
            }
            if let Some(p) = &d.part_uuid {
                by_part_uuid.entry(p.clone()).or_insert(d);
            }
            if let Some(l) = &d.label {
                by_label.entry(l.clone()).or_default().push(d);
            }
            if let Some(pl) = &d.part_label {
                by_part_label.entry(pl.clone()).or_default().push(d);
            }
            if let Some(p) = &d.dev_path {
                by_path.entry(p.to_string_lossy().into_owned()).or_insert(d);
            }
        }
        Self {
            by_uuid,
            by_part_uuid,
            by_label,
            by_part_label,
            by_path,
            all: devices,
        }
    }
}

impl<'a> DeviceResolver for IndexResolver<'a> {
    fn resolve(&self, source: &FstabSource) -> Resolution {
        match source {
            FstabSource::Uuid(u) => match self.by_uuid.get(u) {
                Some(d) => Resolution::One(Box::new((*d).clone())),
                None => Resolution::Zero {
                    source: format!("UUID={u}"),
                },
            },
            FstabSource::PartUuid(p) => match self.by_part_uuid.get(p) {
                Some(d) => Resolution::One(Box::new((*d).clone())),
                None => Resolution::Zero {
                    source: format!("PARTUUID={p}"),
                },
            },
            // LABEL collisions are a real field bug: two disks labelled
            // `root`. We must count ALL matches and report Many when more
            // than one exists. HashMap<_,Vec> preserves every match.
            FstabSource::Label(l) => match self.by_label.get(l) {
                Some(v) if v.len() == 1 => {
                    Resolution::One(Box::new((**v.first().unwrap()).clone()))
                }
                Some(v) if v.len() > 1 => Resolution::Many {
                    source: format!("LABEL={l}"),
                    count: v.len(),
                },
                _ => Resolution::Zero {
                    source: format!("LABEL={l}"),
                },
            },
            FstabSource::PartLabel(pl) => match self.by_part_label.get(pl) {
                Some(v) if v.len() == 1 => {
                    Resolution::One(Box::new((**v.first().unwrap()).clone()))
                }
                Some(v) if v.len() > 1 => Resolution::Many {
                    source: format!("PARTLABEL={pl}"),
                    count: v.len(),
                },
                _ => Resolution::Zero {
                    source: format!("PARTLABEL={pl}"),
                },
            },
            FstabSource::Path(p) => match self.by_path.get(p) {
                Some(d) => Resolution::One(Box::new((*d).clone())),
                None => {
                    // A path we have no indexed device for may still be a
                    // legitimate device node we never discovered. Count
                    // matches across the full device slice for safety.
                    let matches: Vec<&BlockDevice> = self
                        .all
                        .iter()
                        .filter(|d| {
                            d.dev_path
                                .as_ref()
                                .is_some_and(|dp| dp.to_string_lossy() == p.as_str())
                        })
                        .collect();
                    match matches.len() {
                        0 => Resolution::Zero { source: p.clone() },
                        1 => Resolution::One(Box::new(matches[0].clone())),
                        n => Resolution::Many {
                            source: p.clone(),
                            count: n,
                        },
                    }
                }
            },
            FstabSource::Pseudo(_) => Resolution::Zero {
                source: "pseudo source".into(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Plan builder
// ---------------------------------------------------------------------------

/// Inputs to [`build_plan`]. All owned so the result is self-contained.
pub struct PlanInputs<'a> {
    /// Controlled session directory; all targets live under here.
    pub session_root: PathBuf,
    /// Discovered devices, used to resolve fstab references.
    pub devices: &'a [BlockDevice],
    /// Parsed fstab entries from the chosen root candidate.
    pub fstab: &'a [FstabEntry],
    /// Whether the caller wants ESP/boot mounts included.
    pub include_boot: bool,
    /// Whether ordinary local fstab entries should be mounted. Phase 2 keeps
    /// this false to minimise probe surface; mount-repair verification sets
    /// it true so every repaired standard subvolume is acceptance-tested.
    pub include_local: bool,
}

/// Build a [`MountPlan`] from inputs. Pure: no I/O beyond the resolver
/// (which only reads the supplied device slice).
///
/// Order rules (the session mounts in ascending `order`, unmounts in
/// descending):
///   1. Root (`/`) always first; order=10.
///   2. `/boot`, `/efi`, `/boot/efi` next; orders 20..30.
///   3. Anything else from fstab that is in the allow-list; order 40+.
///
/// Entries classified as Swap, Network, Bind, or Pseudo are silently
/// skipped — they appear in `selection_rationale` as "skipped: <kind>" so
/// the user knows we considered them.
pub fn build_plan(inputs: PlanInputs<'_>) -> Result<MountPlan, MountError> {
    let resolver = IndexResolver::new(inputs.devices);
    let target_root = inputs.session_root.join("target");
    let mut steps = Vec::new();
    let mut rationale = Vec::new();
    let warnings = Vec::new();
    let mut order: u32 = 10;
    let mut root_device: Option<String> = None;
    let mut root_subvolume: Option<String> = None;
    let mut extra_partitions: Vec<String> = Vec::new();

    // Sort fstab entries: root first, then boot, then others. Stable so
    // file order is preserved within a class.
    let mut sorted: Vec<&FstabEntry> = inputs.fstab.iter().collect();
    sorted.sort_by_key(|e| match e.kind {
        FstabEntryKind::Root => 0,
        FstabEntryKind::Boot => 1,
        FstabEntryKind::OtherLocal => 2,
        FstabEntryKind::Bind
        | FstabEntryKind::Pseudo
        | FstabEntryKind::Swap
        | FstabEntryKind::Network => 3,
    });

    for entry in sorted {
        if entry.noauto {
            rationale.push(format!(
                "skipped noauto entry: target={} (explicit selection is required)",
                entry.target
            ));
            continue;
        }
        // Skip kinds we never mount.
        match entry.kind {
            FstabEntryKind::Swap => {
                rationale.push(format!("skipped swap entry: target={}", entry.target));
                continue;
            }
            FstabEntryKind::Network => {
                rationale.push(format!(
                    "skipped network fs: target={}, fstype={}",
                    entry.target, entry.fstype
                ));
                continue;
            }
            FstabEntryKind::Bind => {
                rationale.push(format!("skipped bind entry: target={}", entry.target));
                continue;
            }
            FstabEntryKind::Pseudo => {
                rationale.push(format!("skipped pseudo fs: target={}", entry.target));
                continue;
            }
            FstabEntryKind::OtherLocal if !inputs.include_local => {
                rationale.push(format!(
                    "skipped non-boot local fs (caller did not request full local verification): target={}",
                    entry.target
                ));
                continue;
            }
            FstabEntryKind::Boot if !inputs.include_boot => {
                rationale.push(format!(
                    "skipped boot entry (--include-boot not set): target={}",
                    entry.target
                ));
                continue;
            }
            _ => {}
        }

        // Apply per-fstype policy.
        let policy = FstypePolicy::for_fstype(&entry.fstype);
        let fstype_opts: Vec<String> = match &policy {
            FstypePolicy::Safe { options, .. } => options.iter().map(|s| s.to_string()).collect(),
            FstypePolicy::Refused { kind, reason } => {
                return Err(MountError {
                    kind: *kind,
                    message: reason.to_string(),
                    device_or_path: Some(format!("target={}", entry.target)),
                    errno: None,
                    completed_steps: steps
                        .iter()
                        .map(|s: &MountStep| s.rationale.clone())
                        .collect(),
                    cleanup_complete: true,
                    residual_mounts: vec![],
                });
            }
        };

        // Resolve the source.
        let device = match resolver.resolve(&entry.source) {
            Resolution::One(d) => *d,
            Resolution::Zero { source } => {
                return Err(MountError {
                    kind: MountErrorKind::AmbiguousDeviceReference,
                    message: format!("fstab source `{source}` resolved to zero devices"),
                    device_or_path: Some(entry.target.clone()),
                    errno: None,
                    completed_steps: steps
                        .iter()
                        .map(|s: &MountStep| s.rationale.clone())
                        .collect(),
                    cleanup_complete: true,
                    residual_mounts: vec![],
                });
            }
            Resolution::Many { source, count } => {
                return Err(MountError {
                    kind: MountErrorKind::AmbiguousDeviceReference,
                    message: format!("fstab source `{source}` matched {count} devices"),
                    device_or_path: Some(entry.target.clone()),
                    errno: None,
                    completed_steps: steps
                        .iter()
                        .map(|s: &MountStep| s.rationale.clone())
                        .collect(),
                    cleanup_complete: true,
                    residual_mounts: vec![],
                });
            }
        };

        // Compose options from a strict allow-list. Recovery code must not
        // forward arbitrary fstab options such as recovery, clear_cache,
        // discard, journal_dev, logdev or rtdev. For btrfs we preserve only
        // subvol=/subvolid= because selecting the intended root depends on
        // them. Everything else is reported as deliberately ignored.
        let mut options = vec!["ro".to_string()];
        options.extend(fstype_opts.iter().cloned());
        for o in &entry.options {
            if is_allowed_fstab_mount_option(&entry.fstype, o)
                && !options.iter().any(|existing| existing == o)
            {
                options.push(o.clone());
            } else if !is_ignored_bookkeeping_option(o) {
                rationale.push(format!(
                    "ignored unsafe or unnecessary fstab option for {}: {}",
                    entry.target, o
                ));
            }
        }

        // Build the target path under session_root with lexical confinement.
        // fstab is untrusted input in a damaged system; `/../../host` must
        // never escape the controlled target directory.
        let target_path = safe_target_path(&target_root, &entry.target)?;

        // For btrfs, surface the subvol as the plan-level root_subvolume
        // when this is the root entry. This is how the session and the
        // candidate inspector know which subvolume the system is on.
        let subvol = options
            .iter()
            .find_map(|o| o.strip_prefix("subvol=").map(|s| s.to_string()));
        if matches!(entry.kind, FstabEntryKind::Root) {
            root_device = device
                .dev_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned());
            root_subvolume = subvol.clone();
        } else if let Some(src) = &device.dev_path {
            extra_partitions.push(src.to_string_lossy().into_owned());
        }

        let failure_modes: Vec<String> = if let FstypePolicy::Safe { failure_modes, .. } = &policy {
            failure_modes.iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        let rationale_text = match entry.kind {
            FstabEntryKind::Root => format!("root fs from {} at {}", device.name, entry.target),
            FstabEntryKind::Boot => format!("boot fs from {} at {}", device.name, entry.target),
            _ => format!("additional fs from {} at {}", device.name, entry.target),
        };

        let mut evidence = vec![Evidence::new(
            "FSTAB_ENTRY",
            "fstab",
            format!("target={} fstype={}", entry.target, entry.fstype),
        )
        .with_value(format!("source={}", device.name))];
        if let Some(sub) = &subvol {
            evidence.push(
                Evidence::new("BTRFS_SUBVOL", "fstab", "subvol specified").with_value(sub.clone()),
            );
        }

        steps.push(MountStep {
            order,
            source: device
                .dev_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("/dev/{}", device.name)),
            fstype: entry.fstype.clone(),
            target: target_path,
            options,
            rationale: rationale_text,
            depends_on: if matches!(entry.kind, FstabEntryKind::Root) {
                vec![]
            } else {
                vec![10]
            },
            failure_modes,
            evidence,
        });
        order = order.saturating_add(10);
    }

    // If no root step was produced, the plan is unusable. Return an
    // explicit error rather than an empty steps list (the session would
    // refuse an empty plan anyway; surfacing it here gives a clearer
    // message).
    if !steps.iter().any(|s| s.target == target_root) {
        return Err(MountError {
            kind: MountErrorKind::AmbiguousRootCandidate,
            message: "fstab has no entry for `/`; cannot build a mount plan".into(),
            device_or_path: None,
            errno: None,
            completed_steps: vec![],
            cleanup_complete: true,
            residual_mounts: vec![],
        });
    }

    rationale.insert(0, "plan built from fstab + discovered devices".into());

    Ok(MountPlan {
        session_root: inputs.session_root,
        target_root,
        namespace: NamespaceState::PrivateNamespace,
        root_device,
        root_subvolume,
        extra_partitions,
        steps,
        selection_rationale: rationale,
        safety_constraints: vec![
            "phase 2 supports only read-only mounts".into(),
            "any step that cannot be mounted ro is refused, not silently downgraded".into(),
            "the session unmounts in reverse order; pre-existing mounts are never unmounted".into(),
        ],
        warnings,
    })
}

/// Build a one-device, one-step plan used for short-lived candidate
/// inspection. `selector` is restricted to a btrfs `subvol=` or
/// `subvolid=` option; arbitrary mount options are never accepted here.
pub fn build_probe_plan(
    session_root: PathBuf,
    source: &str,
    fstype: &str,
    selector: Option<&str>,
) -> Result<MountPlan, MountError> {
    let policy = FstypePolicy::for_fstype(fstype);
    let (policy_options, failure_modes) = match policy {
        FstypePolicy::Safe {
            options,
            failure_modes,
        } => (options, failure_modes),
        FstypePolicy::Refused { kind, reason } => {
            return Err(MountError {
                kind,
                message: reason.to_string(),
                device_or_path: Some(source.to_string()),
                errno: None,
                completed_steps: vec![],
                cleanup_complete: true,
                residual_mounts: vec![],
            });
        }
    };

    let mut options = vec!["ro".to_string()];
    options.extend(policy_options.into_iter().map(str::to_string));
    if let Some(selector) = selector {
        if fstype != "btrfs" || !valid_btrfs_selector(selector) {
            return Err(MountError {
                kind: MountErrorKind::InvalidMountOption,
                message: "candidate probe selector is not a safe btrfs subvolume selector".into(),
                device_or_path: Some(selector.to_string()),
                errno: None,
                completed_steps: vec![],
                cleanup_complete: true,
                residual_mounts: vec![],
            });
        }
        options.push(selector.to_string());
    }

    let target_root = session_root.join("target");
    Ok(MountPlan {
        session_root,
        target_root: target_root.clone(),
        namespace: NamespaceState::PrivateNamespace,
        root_device: Some(source.to_string()),
        root_subvolume: selector
            .and_then(|value| value.strip_prefix("subvol="))
            .map(str::to_string),
        extra_partitions: vec![],
        steps: vec![MountStep {
            order: 10,
            source: source.to_string(),
            fstype: fstype.to_string(),
            target: target_root,
            options,
            rationale: "temporary read-only candidate inspection".into(),
            depends_on: vec![],
            failure_modes: failure_modes.into_iter().map(str::to_string).collect(),
            evidence: vec![Evidence::new(
                "PROBE_MOUNT",
                source,
                "short-lived read-only candidate probe",
            )],
        }],
        selection_rationale: vec!["explicit candidate probe plan".into()],
        safety_constraints: vec![
            "read-only mount".into(),
            "filesystem recovery and log replay disabled".into(),
            "mount is cleaned immediately after inspection".into(),
        ],
        warnings: vec![],
    })
}

fn valid_btrfs_selector(selector: &str) -> bool {
    if selector.contains([',', '\0']) {
        return false;
    }
    if let Some(path) = selector.strip_prefix("subvol=") {
        return path.starts_with('/') && !path.split('/').any(|part| part == "..");
    }
    selector
        .strip_prefix("subvolid=")
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Convenience predicate: does this path denote the target root inside
/// the session? Used by `session` to find the root step.
pub fn is_target_root(target: &Path, session_root: &Path) -> bool {
    target == session_root.join("target")
}

fn is_ignored_bookkeeping_option(option: &str) -> bool {
    matches!(option, "ro" | "rw" | "defaults" | "noauto" | "nofail")
        || option.starts_with("x-systemd.")
}

fn is_allowed_fstab_mount_option(fstype: &str, option: &str) -> bool {
    match fstype {
        "btrfs" => option.starts_with("subvol=") || option.starts_with("subvolid="),
        _ => false,
    }
}

fn safe_target_path(target_root: &Path, target: &str) -> Result<PathBuf, MountError> {
    use std::path::Component;

    let path = Path::new(target);
    if !path.is_absolute() && !target.is_empty() {
        return Err(unsafe_target_error(target, "fstab target is not absolute"));
    }

    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(unsafe_target_error(
                    target,
                    "fstab target contains an escaping path component",
                ));
            }
        }
    }

    Ok(if relative.as_os_str().is_empty() {
        target_root.to_path_buf()
    } else {
        target_root.join(relative)
    })
}

fn unsafe_target_error(target: &str, message: &str) -> MountError {
    MountError {
        kind: MountErrorKind::UnsafeTargetPath,
        message: message.to_string(),
        device_or_path: Some(target.to_string()),
        errno: None,
        completed_steps: vec![],
        cleanup_complete: true,
        residual_mounts: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::model::{DeviceClass, DiskKind, PartitionRole};

    fn ext4_root_device() -> BlockDevice {
        BlockDevice {
            name: "sda2".into(),
            dev_path: Some(PathBuf::from("/dev/sda2")),
            major_minor: Some("8:2".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(2),
            size_sectors: Some(1_000_000),
            read_only: false,
            removable: false,
            filesystem: Some("ext4".into()),
            uuid: Some("11111111-1111-1111-1111-111111111111".into()),
            part_uuid: Some("22222222-2222-2222-2222-222222222222".into()),
            label: Some("root".into()),
            part_label: None,
            mount_point: None,
            mounts: vec![],
            mounted_before_session: false,
            evidence: vec![],
        }
    }

    fn btrfs_root_device() -> BlockDevice {
        let mut d = ext4_root_device();
        d.name = "nvme0n1p2".into();
        d.dev_path = Some(PathBuf::from("/dev/nvme0n1p2"));
        d.filesystem = Some("btrfs".into());
        d.uuid = Some("3bdc66e2-f30b-4ef1-97f0-c687934e25e2".into());
        d.label = Some("catos-root".into());
        d
    }

    fn esp_device() -> BlockDevice {
        BlockDevice {
            name: "sda1".into(),
            dev_path: Some(PathBuf::from("/dev/sda1")),
            major_minor: Some("8:1".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: DiskKind::Gpt,
            partition_role: PartitionRole::Esp,
            partition_number: Some(1),
            size_sectors: Some(600_000),
            read_only: false,
            removable: false,
            filesystem: Some("vfat".into()),
            uuid: Some("2CB7-2D33".into()),
            part_uuid: Some("33333333-3333-3333-3333-333333333333".into()),
            label: Some("EFI".into()),
            part_label: None,
            mount_point: None,
            mounts: vec![],
            mounted_before_session: false,
            evidence: vec![],
        }
    }

    /// ext4 root: plan must include `ro,noload`. Guards against a future
    /// refactor that drops `noload` and silently replays journals on a
    /// dirty fs (data loss for recovery users).
    #[test]
    fn ext4_plan_includes_noload() {
        let dev = ext4_root_device();
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/".into(),
            fstype: "ext4".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 1,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .expect("plan");
        assert_eq!(plan.steps.len(), 1);
        let root = &plan.steps[0];
        assert!(root.options.contains(&"ro".into()));
        assert!(
            root.options.contains(&"noload".into()),
            "options: {:?}",
            root.options
        );
        assert!(plan.root_device.as_deref() == Some("/dev/sda2"));
    }

    /// btrfs root with subvol=/@: subvol must be preserved and surfaced
    /// as root_subvolume so the candidate inspector can match against
    /// subvol discovery.
    #[test]
    fn btrfs_plan_preserves_subvol() {
        let dev = btrfs_root_device();
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/".into(),
            fstype: "btrfs".into(),
            options: vec![
                "rw".into(),
                "relatime".into(),
                "compress=zstd:3".into(),
                "subvol=/@".into(),
            ],
            dump: 0,
            pass: 0,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .expect("plan");
        let root = &plan.steps[0];
        // rw must be stripped; ro added; subvol preserved.
        assert!(root.options.contains(&"ro".into()));
        assert!(root.options.contains(&"rescue=nologreplay".into()));
        assert!(!root.options.contains(&"rw".into()));
        assert!(
            root.options.iter().any(|o| o == "subvol=/@"),
            "options: {:?}",
            root.options
        );
        assert_eq!(plan.root_subvolume.as_deref(), Some("/@"));
        assert!(!root.options.iter().any(|o| o.starts_with("compress=")));
        assert!(!root.options.contains(&"relatime".into()));
    }

    /// A damaged fstab must not escape the controlled mount root.
    #[test]
    fn fstab_target_parent_escape_is_rejected() {
        let dev = ext4_root_device();
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/../../host".into(),
            fstype: "ext4".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 1,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let err = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .unwrap_err();
        assert_eq!(err.kind, MountErrorKind::UnsafeTargetPath);
    }

    /// User fstab options are not an execution policy. Only the btrfs
    /// subvolume selectors needed to locate the root may pass through.
    #[test]
    fn unsafe_fstab_options_are_not_forwarded() {
        let dev = btrfs_root_device();
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/".into(),
            fstype: "btrfs".into(),
            options: vec![
                "subvol=/@".into(),
                "clear_cache".into(),
                "recovery".into(),
                "discard".into(),
            ],
            dump: 0,
            pass: 0,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .expect("plan");
        let options = &plan.steps[0].options;
        assert!(options.contains(&"subvol=/@".into()));
        assert!(options.contains(&"rescue=nologreplay".into()));
        assert!(!options.contains(&"clear_cache".into()));
        assert!(!options.contains(&"recovery".into()));
        assert!(!options.contains(&"discard".into()));
    }

    #[test]
    fn probe_plan_uses_no_replay_options() {
        let plan = build_probe_plan(
            PathBuf::from("/run/catos-system/sessions/probe"),
            "/dev/sda2",
            "btrfs",
            Some("subvolid=5"),
        )
        .unwrap();
        assert!(plan.steps[0].options.contains(&"ro".into()));
        assert!(plan.steps[0].options.contains(&"rescue=nologreplay".into()));
        assert!(plan.steps[0].options.contains(&"subvolid=5".into()));
    }

    #[test]
    fn probe_plan_rejects_unsafe_selector() {
        let err = build_probe_plan(
            PathBuf::from("/run/catos-system/sessions/probe"),
            "/dev/sda2",
            "btrfs",
            Some("subvol=/@,clear_cache"),
        )
        .unwrap_err();
        assert_eq!(err.kind, MountErrorKind::InvalidMountOption);
    }

    /// xfs root must get `norecovery`. Without it a dirty xfs log replays
    /// and writes to the device.
    #[test]
    fn xfs_plan_includes_norecovery() {
        let mut dev = ext4_root_device();
        dev.filesystem = Some("xfs".into());
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/".into(),
            fstype: "xfs".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 1,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .expect("plan");
        assert!(plan.steps[0].options.contains(&"norecovery".into()));
    }

    /// ESP at /boot/efi must be included when include_boot=true and use
    /// vfat with no extra options (no journal to suppress).
    #[test]
    fn esp_plan_uses_plain_ro() {
        let root_dev = btrfs_root_device();
        let esp_dev = esp_device();
        let fstab = vec![
            FstabEntry {
                source: FstabSource::Uuid(root_dev.uuid.clone().unwrap()),
                target: "/".into(),
                fstype: "btrfs".into(),
                options: vec!["subvol=/@".into()],
                dump: 0,
                pass: 0,
                kind: FstabEntryKind::Root,
                noauto: false,
                nofail: false,
                has_systemd_options: false,
            },
            FstabEntry {
                source: FstabSource::Uuid(esp_dev.uuid.clone().unwrap()),
                target: "/boot/efi".into(),
                fstype: "vfat".into(),
                options: vec!["defaults".into()],
                dump: 0,
                pass: 2,
                kind: FstabEntryKind::Boot,
                noauto: false,
                nofail: false,
                has_systemd_options: false,
            },
        ];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[root_dev, esp_dev],
            fstab: &fstab,
            include_boot: true,
            include_local: false,
        })
        .expect("plan");
        assert_eq!(plan.steps.len(), 2);
        let esp = plan
            .steps
            .iter()
            .find(|s| s.target.ends_with("boot/efi"))
            .unwrap();
        assert!(esp.options.contains(&"ro".into()));
        assert!(!esp
            .options
            .iter()
            .any(|o| o.starts_with("noload") || o.starts_with("norecovery")));
        // Boot step depends on root step.
        assert!(esp.depends_on.contains(&10));
    }

    /// A swap entry in fstab must be skipped, not cause an error.
    #[test]
    fn swap_entry_is_skipped_not_error() {
        let root_dev = ext4_root_device();
        let fstab = vec![
            FstabEntry {
                source: FstabSource::Uuid(root_dev.uuid.clone().unwrap()),
                target: "/".into(),
                fstype: "ext4".into(),
                options: vec!["defaults".into()],
                dump: 0,
                pass: 1,
                kind: FstabEntryKind::Root,
                noauto: false,
                nofail: false,
                has_systemd_options: false,
            },
            FstabEntry {
                source: FstabSource::Uuid("swap-uuid".into()),
                target: "none".into(),
                fstype: "swap".into(),
                options: vec!["defaults".into()],
                dump: 0,
                pass: 0,
                kind: FstabEntryKind::Swap,
                noauto: false,
                nofail: false,
                has_systemd_options: false,
            },
        ];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[root_dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .expect("plan");
        assert_eq!(plan.steps.len(), 1); // only the root step
        assert!(plan
            .selection_rationale
            .iter()
            .any(|r| r.contains("skipped swap")));
    }

    #[test]
    fn noauto_boot_entry_is_not_mounted() {
        let root_dev = ext4_root_device();
        let esp_dev = esp_device();
        let fstab = vec![
            FstabEntry {
                source: FstabSource::Uuid(root_dev.uuid.clone().unwrap()),
                target: "/".into(),
                fstype: "ext4".into(),
                options: vec![],
                dump: 0,
                pass: 1,
                kind: FstabEntryKind::Root,
                noauto: false,
                nofail: false,
                has_systemd_options: false,
            },
            FstabEntry {
                source: FstabSource::Uuid(esp_dev.uuid.clone().unwrap()),
                target: "/boot/efi".into(),
                fstype: "vfat".into(),
                options: vec!["noauto".into()],
                dump: 0,
                pass: 2,
                kind: FstabEntryKind::Boot,
                noauto: true,
                nofail: false,
                has_systemd_options: false,
            },
        ];
        let plan = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[root_dev, esp_dev],
            fstab: &fstab,
            include_boot: true,
            include_local: false,
        })
        .unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert!(plan
            .selection_rationale
            .iter()
            .any(|item| item.contains("skipped noauto")));
    }

    /// A refused fstype (zfs, ntfs3, ...) must produce a structured
    /// error, NOT an empty plan or a silent skip.
    #[test]
    fn refused_fstype_returns_error() {
        let mut dev = ext4_root_device();
        dev.filesystem = Some("ntfs3".into());
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(dev.uuid.clone().unwrap()),
            target: "/".into(),
            fstype: "ntfs3".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 1,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let err = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[dev],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .unwrap_err();
        assert_eq!(err.kind, MountErrorKind::UnsupportedFilesystem);
    }

    /// An unresolvable UUID (zero matches) must error explicitly. We do
    /// NOT silently skip a fstab line — the recovery tool must know the
    /// device is missing.
    #[test]
    fn unresolvable_uuid_errors() {
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid("does-not-exist".into()),
            target: "/".into(),
            fstype: "ext4".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 1,
            kind: FstabEntryKind::Root,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let err = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[],
            fstab: &fstab,
            include_boot: false,
            include_local: false,
        })
        .unwrap_err();
        assert_eq!(err.kind, MountErrorKind::AmbiguousDeviceReference);
    }

    /// No root entry means no usable plan. We refuse rather than emit an
    /// empty steps list (the session would refuse an empty plan anyway;
    /// surfacing here gives a clearer message).
    #[test]
    fn no_root_entry_is_error() {
        let esp = esp_device();
        let fstab = vec![FstabEntry {
            source: FstabSource::Uuid(esp.uuid.clone().unwrap()),
            target: "/boot/efi".into(),
            fstype: "vfat".into(),
            options: vec!["defaults".into()],
            dump: 0,
            pass: 2,
            kind: FstabEntryKind::Boot,
            noauto: false,
            nofail: false,
            has_systemd_options: false,
        }];
        let err = build_plan(PlanInputs {
            session_root: PathBuf::from("/run/catos-system/sessions/abc"),
            devices: &[esp],
            fstab: &fstab,
            include_boot: true,
            include_local: false,
        })
        .unwrap_err();
        assert_eq!(err.kind, MountErrorKind::AmbiguousRootCandidate);
    }
}
