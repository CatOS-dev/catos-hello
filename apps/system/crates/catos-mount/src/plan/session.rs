//! Mount plan construction: read-only session/probe planning.
//!
//! Wraps the planner (plan builder) and prober (short-lived read-only
//! probe mounts) as private modules and re-exports their public API.
//! Both depend only on `crate::mount` and `crate::target`.

mod planner {
    //! Mount plan construction.
    //!
    //! Given a [`crate::model::MountPlan`] skeleton (target root, fstab
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

    use crate::diagnose::fstab::{FstabEntry, FstabEntryKind, FstabSource};
    use crate::model::{MountError, MountErrorKind, MountPlan, MountStep, NamespaceState};
    use catos_target::model::BlockDevice;
    use catos_target::Evidence;

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
                FstypePolicy::Safe { options, .. } => {
                    options.iter().map(|s| s.to_string()).collect()
                }
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

            let failure_modes: Vec<String> =
                if let FstypePolicy::Safe { failure_modes, .. } = &policy {
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
                    Evidence::new("BTRFS_SUBVOL", "fstab", "subvol specified")
                        .with_value(sub.clone()),
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
                "the session unmounts in reverse order; pre-existing mounts are never unmounted"
                    .into(),
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
                    message: "candidate probe selector is not a safe btrfs subvolume selector"
                        .into(),
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
        use catos_target::model::{DeviceClass, DiskKind, PartitionRole};

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
}

mod prober {
    //! Short-lived read-only probe mounts for unmounted root/ESP candidates.
    //!
    //! A probe mount is deliberately not a user-visible target session. It
    //! mounts exactly one known filesystem inside a private mount namespace,
    //! collects minimal evidence, and cleans up before returning.

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::planner::build_probe_plan;
    use crate::diagnose::fstab::parse_all_with_diagnostics;
    use crate::diagnose::fstab::FstabEntry;
    use crate::execute::secure_dir::SESSION_ROOT_PARENT;
    use crate::model::{CleanupReport, MountError, MountErrorKind};
    use crate::session::ReadOnlyMountSession;
    use catos_process::run_trusted_tool;
    use catos_target::diagnose::candidate::identify_candidates;
    use catos_target::diagnose::candidate::inspect_target;
    use catos_target::diagnose::filesystem::{FilesystemProbe, RealFilesystem};
    use catos_target::diagnose::runtime::ProcCaps;
    use catos_target::diagnose::system_root::SystemRoot;
    use catos_target::model::{
        BlockDevice, BtrfsSubvolume, BtrfsSubvolumeKind, EspCandidate, RootCandidate,
        RootCandidateConfidence,
    };
    use catos_target::model::{TargetInspection, Warning};
    use catos_target::Evidence;

    static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const MAX_PROBED_DEVICES: usize = 64;
    const MAX_BTRFS_SUBVOLUMES: usize = 512;
    const MAX_INSPECTED_BTRFS_ROOTS: usize = 64;

    #[derive(Default)]
    pub struct ProbeCandidates {
        pub roots: Vec<RootCandidate>,
        pub esps: Vec<EspCandidate>,
        pub btrfs_subvolumes: Vec<BtrfsSubvolume>,
        pub warnings: Vec<Warning>,
    }

    pub struct SelectedTargetProbe {
        pub fstab: Vec<FstabEntry>,
        pub inspection: TargetInspection,
        pub cleanup: CleanupReport,
        pub warnings: Vec<Warning>,
    }

    /// Inspect one explicitly selected root device. This is the bridge from
    /// LiveCD/initramfs device selection to a complete fstab-based mount plan:
    /// the selected root is mounted read-only, its own fstab is read through
    /// SystemRoot confinement, and the probe is cleaned before returning.
    pub fn inspect_selected_root(
        device: &BlockDevice,
        subvolume: Option<&str>,
    ) -> Result<SelectedTargetProbe, MountError> {
        let source = device
            .dev_path
            .as_ref()
            .and_then(|path| path.to_str())
            .ok_or_else(|| {
                simple_mount_error(
                    MountErrorKind::DeviceNotFound,
                    "selected root device has no usable /dev path",
                    Some(device.name.clone()),
                )
            })?;
        let fstype = device.filesystem.as_deref().ok_or_else(|| {
            simple_mount_error(
                MountErrorKind::UnsupportedFilesystem,
                "selected root device has no identified filesystem",
                Some(source.to_string()),
            )
        })?;
        let selector = match (fstype, subvolume) {
            ("btrfs", Some(path)) => Some(format!("subvol={path}")),
            ("btrfs", None) => None,
            (_, Some(_)) => {
                return Err(simple_mount_error(
                    MountErrorKind::InvalidMountOption,
                    "--root-subvolume is valid only for btrfs",
                    Some(source.to_string()),
                ));
            }
            (_, None) => None,
        };

        let plan = build_probe_plan(
            probe_session_root(&device.name),
            source,
            fstype,
            selector.as_deref(),
        )?;
        let id = plan
            .session_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("selected-root")
            .to_string();
        let mut session = ReadOnlyMountSession::new(id, &plan);
        let snapshot = session.run(&plan)?;
        let target_path = snapshot.target_root.to_str().ok_or_else(|| {
            simple_mount_error(
                MountErrorKind::UnsafeTargetPath,
                "temporary target path is not valid UTF-8",
                Some(snapshot.target_root.display().to_string()),
            )
        })?;
        let target = SystemRoot::from_user_input(target_path).map_err(|error| {
            simple_mount_error(
                MountErrorKind::UnsafeTargetPath,
                &error.to_string(),
                Some(target_path.to_string()),
            )
        })?;
        let fs = RealFilesystem;
        let fstab_result =
            fs.rooted_read_to_string(target.canonical_path(), Path::new("etc/fstab"));
        let (fstab, diagnostics) = match fstab_result {
            Ok(body) => crate::diagnose::fstab::parse_all_with_diagnostics(&body),
            Err(catos_target::FsError::NotFound) => (Vec::new(), Vec::new()),
            Err(error) => {
                let cleanup = session.cleanup();
                return Err(MountError {
                    cleanup_complete: cleanup.all_clean,
                    residual_mounts: cleanup_residual_paths(&cleanup),
                    ..simple_mount_error(
                        MountErrorKind::MountFailed,
                        &format!("cannot read selected target fstab: {error}"),
                        Some(target_path.to_string()),
                    )
                });
            }
        };
        let mut inspection_warnings = Vec::new();
        let inspection = inspect_target(&fs, &target, &mut inspection_warnings);
        let mut warnings: Vec<Warning> = diagnostics
            .into_iter()
            .map(|diagnostic| {
                Warning::new(
                    "FSTAB_PARSE_ERROR",
                    format!(
                        "target fstab line {} is invalid ({:?}): {}",
                        diagnostic.line, diagnostic.kind, diagnostic.text
                    ),
                )
            })
            .collect();
        warnings.extend(
            inspection_warnings
                .into_iter()
                .map(|message| Warning::new("TARGET_INSPECTION_WARNING", message)),
        );
        let cleanup = session.cleanup();
        if !cleanup.all_clean {
            return Err(MountError {
                kind: MountErrorKind::CleanupIncomplete,
                message: "selected root probe left residual mounts".into(),
                device_or_path: Some(source.to_string()),
                errno: None,
                completed_steps: vec!["selected root inspected".into()],
                cleanup_complete: false,
                residual_mounts: cleanup_residual_paths(&cleanup),
            });
        }

        Ok(SelectedTargetProbe {
            fstab,
            inspection,
            cleanup,
            warnings,
        })
    }

    fn simple_mount_error(
        kind: MountErrorKind,
        message: &str,
        device_or_path: Option<String>,
    ) -> MountError {
        MountError {
            kind,
            message: message.to_string(),
            device_or_path,
            errno: None,
            completed_steps: vec![],
            cleanup_complete: true,
            residual_mounts: vec![],
        }
    }

    fn cleanup_residual_paths(cleanup: &CleanupReport) -> Vec<String> {
        cleanup
            .residual
            .iter()
            .map(|item| item.resource.target.display().to_string())
            .collect()
    }

    pub fn probe_unmounted_candidates(
        devices: &[BlockDevice],
        fstab: &[FstabEntry],
    ) -> ProbeCandidates {
        if ProcCaps::from_current_process().cap_sys_admin != Some(true) {
            return ProbeCandidates {
                warnings: vec![Warning::new(
                    "CANDIDATE_PROBE_UNAVAILABLE",
                    "unmounted candidate inspection requires effective CAP_SYS_ADMIN",
                )],
                ..Default::default()
            };
        }

        let mut report = ProbeCandidates::default();
        for device in devices
            .iter()
            .filter(|device| device.mount_point.is_none())
            .filter(|device| device.dev_path.is_some())
            .take(MAX_PROBED_DEVICES)
        {
            let Some(fstype) = device.filesystem.as_deref() else {
                continue;
            };
            match fstype {
                "btrfs" => probe_btrfs(device, &mut report),
                "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" => {
                    probe_simple(device, fstab, &mut report)
                }
                "vfat" | "fat" | "fat32" | "fat16" | "fat12" => {
                    probe_simple(device, fstab, &mut report)
                }
                _ => {}
            }
        }
        report
    }

    fn probe_simple(device: &BlockDevice, fstab: &[FstabEntry], report: &mut ProbeCandidates) {
        let Some(source) = device.dev_path.as_ref().and_then(|path| path.to_str()) else {
            return;
        };
        let Some(fstype) = device.filesystem.as_deref() else {
            return;
        };
        let session_root = probe_session_root(&device.name);
        let plan = match build_probe_plan(session_root, source, fstype, None) {
            Ok(plan) => plan,
            Err(error) => {
                report.warnings.push(Warning::new(
                    "PROBE_PLAN_REFUSED",
                    format!("cannot probe {source}: {error}"),
                ));
                return;
            }
        };
        let id = plan
            .session_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("probe")
            .to_string();
        let mut session = ReadOnlyMountSession::new(id, &plan);
        let snapshot = match session.run(&plan) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                report.warnings.push(Warning::new(
                    "PROBE_MOUNT_FAILED",
                    format!("cannot inspect {source}: {error}"),
                ));
                return;
            }
        };

        let candidate_fstab = RealFilesystem
            .rooted_read_to_string(&snapshot.target_root, Path::new("etc/fstab"))
            .map(|body| parse_all_with_diagnostics(&body).0)
            .unwrap_or_default();
        let mut mounted = device.clone();
        mounted.mount_point = Some(snapshot.target_root.clone());
        mounted.mounted_before_session = false;
        // Prefer the candidate's own fstab when it is available. This lets
        // root confidence require that the filesystem we mounted is the
        // source of that target's `/` entry, rather than treating any
        // unmounted ext4 data partition as a possible system root.
        let fstab = if candidate_fstab.is_empty() {
            fstab
        } else {
            &candidate_fstab
        };
        let (mut roots, mut esps, _, warnings) = identify_candidates(&[mounted], fstab);
        for candidate in &mut roots {
            candidate.mounted_at = None;
            candidate.evidence.push(Evidence::new(
                "TEMPORARY_READ_ONLY_PROBE",
                source,
                "candidate content inspected through a short-lived read-only mount",
            ));
        }
        for candidate in &mut esps {
            candidate.evidence.push(Evidence::new(
                "TEMPORARY_READ_ONLY_PROBE",
                source,
                "ESP content inspected through a short-lived read-only mount",
            ));
        }
        report.roots.extend(roots);
        report.esps.extend(esps);
        report.warnings.extend(warnings);

        let cleanup = session.cleanup();
        if !cleanup.all_clean {
            report.warnings.push(Warning::new(
                "PROBE_CLEANUP_INCOMPLETE",
                format!("temporary probe for {source} left residual mounts"),
            ));
        }
    }

    fn probe_btrfs(device: &BlockDevice, report: &mut ProbeCandidates) {
        let Some(source) = device.dev_path.as_ref().and_then(|path| path.to_str()) else {
            return;
        };
        let session_root = probe_session_root(&device.name);
        let plan = match build_probe_plan(session_root, source, "btrfs", Some("subvolid=5")) {
            Ok(plan) => plan,
            Err(error) => {
                report.warnings.push(Warning::new(
                    "BTRFS_PROBE_PLAN_REFUSED",
                    format!("cannot probe {source}: {error}"),
                ));
                return;
            }
        };
        let id = plan
            .session_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("probe")
            .to_string();
        let mut session = ReadOnlyMountSession::new(id, &plan);
        let snapshot = match session.run(&plan) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                report.warnings.push(Warning::new(
                    "BTRFS_PROBE_MOUNT_FAILED",
                    format!("cannot inspect {source}: {error}"),
                ));
                return;
            }
        };

        let (mut subvolumes, mut warnings) = enumerate_btrfs_subvolumes(&snapshot.target_root);
        if subvolumes.is_empty() {
            subvolumes = fallback_btrfs_subvolumes(&snapshot.target_root);
        }
        inspect_btrfs_roots(
            device,
            &snapshot.target_root,
            &mut subvolumes,
            &mut report.roots,
        );
        report.btrfs_subvolumes.extend(subvolumes);
        report.warnings.append(&mut warnings);

        let cleanup = session.cleanup();
        if !cleanup.all_clean {
            report.warnings.push(Warning::new(
                "BTRFS_PROBE_CLEANUP_INCOMPLETE",
                format!("temporary btrfs probe for {source} left residual mounts"),
            ));
        }
    }

    fn enumerate_btrfs_subvolumes(root: &Path) -> (Vec<BtrfsSubvolume>, Vec<Warning>) {
        let mut warnings = Vec::new();
        let Some(root_str) = root.to_str() else {
            return (Vec::new(), warnings);
        };

        let listed = run_trusted_tool(
            "btrfs",
            &["subvolume", "list", root_str],
            Duration::from_secs(4),
            1024 * 1024,
        );
        let readonly = run_trusted_tool(
            "btrfs",
            &["subvolume", "list", "-r", root_str],
            Duration::from_secs(4),
            1024 * 1024,
        );
        let default = run_trusted_tool(
            "btrfs",
            &["subvolume", "get-default", root_str],
            Duration::from_secs(2),
            64 * 1024,
        );

        let mut entries: BTreeMap<String, (Option<u64>, bool)> = BTreeMap::new();
        match listed {
            Ok(output) if output.success() && !output.stdout_truncated => {
                for (id, path) in parse_btrfs_subvolume_list(&output.stdout)
                    .into_iter()
                    .take(MAX_BTRFS_SUBVOLUMES)
                {
                    entries.entry(path).or_insert((id, false));
                }
            }
            Ok(output) => warnings.push(Warning::new(
                "BTRFS_SUBVOLUME_LIST_FAILED",
                format!("{} exited {}", output.path.display(), output.status),
            )),
            Err(error) => warnings.push(Warning::new("BTRFS_TOOL_UNAVAILABLE", error)),
        }

        if let Ok(output) = readonly {
            if output.success() && !output.stdout_truncated {
                for (id, path) in parse_btrfs_subvolume_list(&output.stdout) {
                    let entry = entries.entry(path).or_insert((id, false));
                    entry.1 = true;
                }
            }
        }

        let default_path = default
            .ok()
            .filter(|output| output.success() && !output.stdout_truncated)
            .and_then(|output| parse_btrfs_default_path(&output.stdout));

        let mut subvolumes = vec![BtrfsSubvolume {
            path: "/".into(),
            id: Some(5),
            name: None,
            kind: BtrfsSubvolumeKind::TopLevel,
            is_default: default_path.as_deref() == Some("/"),
            read_only: false,
            evidence: vec![Evidence::new(
                "BTRFS_TOP_LEVEL",
                root.display().to_string(),
                "filesystem mounted with subvolid=5",
            )],
        }];
        subvolumes.extend(entries.into_iter().map(|(path, (id, read_only))| {
            let normalized = normalize_subvolume_path(&path);
            let name = Path::new(&normalized)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string);
            let snapshot = looks_like_snapshot_path(&normalized);
            BtrfsSubvolume {
                path: normalized.clone(),
                id,
                name,
                kind: if snapshot {
                    if read_only {
                        BtrfsSubvolumeKind::ReadOnlySnapshot
                    } else {
                        BtrfsSubvolumeKind::SnapshotContainer
                    }
                } else {
                    BtrfsSubvolumeKind::Unknown
                },
                is_default: default_path.as_deref() == Some(normalized.as_str()),
                read_only,
                evidence: vec![Evidence::new(
                    "BTRFS_SUBVOLUME_LIST",
                    root.display().to_string(),
                    "subvolume reported by btrfs-progs",
                )
                .with_value(normalized)],
            }
        }));
        (subvolumes, warnings)
    }

    fn inspect_btrfs_roots(
        device: &BlockDevice,
        top_level: &Path,
        subvolumes: &mut [BtrfsSubvolume],
        roots: &mut Vec<RootCandidate>,
    ) {
        let mut inspected = 0usize;
        for subvolume in subvolumes {
            if inspected >= MAX_INSPECTED_BTRFS_ROOTS {
                break;
            }
            if matches!(
                subvolume.kind,
                BtrfsSubvolumeKind::TopLevel
                    | BtrfsSubvolumeKind::ReadOnlySnapshot
                    | BtrfsSubvolumeKind::SnapshotContainer
            ) {
                continue;
            }
            let Some(path) = safe_subvolume_join(top_level, &subvolume.path) else {
                continue;
            };
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            inspected += 1;
            let mut mounted = device.clone();
            mounted.mount_point = Some(path);
            mounted.mounted_before_session = false;
            let fstab = RealFilesystem
                .rooted_read_to_string(
                    mounted.mount_point.as_ref().unwrap(),
                    Path::new("etc/fstab"),
                )
                .map(|body| parse_all_with_diagnostics(&body).0)
                .unwrap_or_default();
            let (mut candidates, _, _, _) = identify_candidates(&[mounted], &fstab);
            let Some(mut candidate) = candidates.pop() else {
                subvolume.kind = BtrfsSubvolumeKind::Data;
                continue;
            };
            candidate.mounted_at = None;
            candidate.subvolume = Some(subvolume.path.clone());
            candidate.evidence.push(Evidence::new(
                "BTRFS_SUBVOLUME_INSPECTED",
                device
                    .dev_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| device.name.clone()),
                "subvolume inspected through the top-level read-only probe mount",
            ));
            if candidate.confidence == RootCandidateConfidence::High
                || candidate.confidence == RootCandidateConfidence::Medium
            {
                subvolume.kind = BtrfsSubvolumeKind::RootCandidate;
                roots.push(candidate);
            } else {
                subvolume.kind = BtrfsSubvolumeKind::Data;
            }
        }
    }

    fn fallback_btrfs_subvolumes(root: &Path) -> Vec<BtrfsSubvolume> {
        let mut paths = BTreeSet::new();
        for name in ["@", "@root", "root"] {
            let path = root.join(name);
            if std::fs::symlink_metadata(&path)
                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            {
                paths.insert(name.to_string());
            }
        }
        paths
            .into_iter()
            .map(|path| BtrfsSubvolume {
                path: normalize_subvolume_path(&path),
                id: None,
                name: Some(path),
                kind: BtrfsSubvolumeKind::Unknown,
                is_default: false,
                read_only: false,
                evidence: vec![Evidence::new(
                    "BTRFS_COMMON_ROOT_NAME",
                    root.display().to_string(),
                    "common root subvolume name found without btrfs-progs",
                )],
            })
            .collect()
    }

    fn parse_btrfs_subvolume_list(bytes: &[u8]) -> Vec<(Option<u64>, String)> {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter_map(|line| {
                let id = line
                    .strip_prefix("ID ")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse().ok());
                let (_, path) = line.split_once(" path ")?;
                if path.is_empty() {
                    None
                } else {
                    Some((id, path.to_string()))
                }
            })
            .collect()
    }

    fn parse_btrfs_default_path(bytes: &[u8]) -> Option<String> {
        let body = String::from_utf8_lossy(bytes);
        if body.contains("FS_TREE") {
            return Some("/".into());
        }
        let (_, path) = body.trim().split_once(" path ")?;
        Some(normalize_subvolume_path(path))
    }

    fn normalize_subvolume_path(path: &str) -> String {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            "/".into()
        } else {
            format!("/{trimmed}")
        }
    }

    fn safe_subvolume_join(root: &Path, subvolume: &str) -> Option<PathBuf> {
        let mut relative = PathBuf::new();
        for component in Path::new(subvolume).components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(part) => relative.push(part),
                Component::ParentDir | Component::Prefix(_) => return None,
            }
        }
        Some(root.join(relative))
    }

    fn looks_like_snapshot_path(path: &str) -> bool {
        path == "/.snapshots"
            || path.starts_with("/.snapshots/")
            || path.contains("/timeshift-btrfs/")
            || path.ends_with("/snapshot")
    }

    fn probe_session_root(device_name: &str) -> PathBuf {
        let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Path::new(SESSION_ROOT_PARENT).join(format!(
            "probe-{}-{}-{sequence}",
            std::process::id(),
            sanitize_component(device_name)
        ))
    }

    fn sanitize_component(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_btrfs_subvolume_list_output() {
            let parsed = parse_btrfs_subvolume_list(
            b"ID 256 gen 10 top level 5 path @\nID 300 gen 11 top level 256 path @/.snapshots/1/snapshot\n",
        );
            assert_eq!(parsed[0], (Some(256), "@".into()));
            assert_eq!(parsed[1].1, "@/.snapshots/1/snapshot");
        }

        #[test]
        fn rejects_subvolume_path_escape() {
            assert!(safe_subvolume_join(Path::new("/probe"), "/@/../host").is_none());
            assert_eq!(
                safe_subvolume_join(Path::new("/probe"), "/@/root"),
                Some(PathBuf::from("/probe/@/root"))
            );
        }

        #[test]
        fn snapshot_paths_are_not_root_candidates() {
            assert!(looks_like_snapshot_path("/@/.snapshots/1/snapshot"));
            assert!(!looks_like_snapshot_path("/@"));
        }

        #[test]
        fn default_path_parser_handles_top_level_and_named_subvolume() {
            assert_eq!(
                parse_btrfs_default_path(b"ID 5 (FS_TREE)"),
                Some("/".into())
            );
            assert_eq!(
                parse_btrfs_default_path(b"ID 256 gen 1 top level 5 path @"),
                Some("/@".into())
            );
        }
    }
}

pub use planner::{build_plan, build_probe_plan, FstypePolicy, PlanInputs};
pub use prober::{
    inspect_selected_root, probe_unmounted_candidates, ProbeCandidates, SelectedTargetProbe,
};
