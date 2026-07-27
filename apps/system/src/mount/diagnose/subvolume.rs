//! Standard CatOS subvolume rebuild decision logic.
//!
//! Spec § 五 authorises recreating a missing CatOS standard btrfs
//! subvolume **only** when every precondition holds. This module
//! encodes those rules as a pure function of fstab + on-disk facts,
//! so the same logic can drive:
//!
//! * the repair orchestrator's plan builder;
//! * a future Doctor mount diagnosis (so the two cannot disagree);
//! * unit tests that do not need root, loop devices, or real btrfs.
//!
//! ## Authorised conditions (all must hold)
//!
//! 1. The target root btrfs filesystem has been uniquely identified.
//! 2. The fstab contains a CatOS standard mount-point → subvol entry
//!    for this subvolume (i.e. there is historical evidence the
//!    subvolume used to exist), OR the target is confirmed CatOS and
//!    the spec's "missing standard entry" path applies.
//! 3. The missing subvolume is one of the eight CatOS standard
//!    subvolumes.
//! 4. No filesystem object already exists at the subvolume's path
//!    (i.e. we will not overwrite an existing subvolume or
//!    directory).
//! 5. The mount-point directory either does not exist or is empty.
//!    If it exists and contains data, we surface `DataConflict` and
//!    do not migrate data.
//! 6. The btrfs filesystem is writable.
//!
//! ## What this module does NOT do
//!
//! * It does not invoke `btrfs subvolume create`. That is the
//!   orchestrator's job, in a private mount namespace, with the
//!   per-FSID lock held.
//! * It does not touch Snapper configuration. `@snapshots` rebuild
//!   only recreates the subvolume and the fstab line; Snapper
//!   configuration problems are reported for Doctor to handle.
//! * It does not delete unknown subvolumes.
//! * It does not delete user data.
//! * It does not move, copy, or rsync data from a mount-point
//!   directory into a freshly created subvolume.

use crate::mount::diagnose::fstab::FstabEntry;
use crate::mount::model::{
    standard_mount_point_for_subvol, standard_subvol_for_mount_point, MountProblem,
    PlannedSubvolume,
};

/// What the on-disk probe observed about one potential subvolume path.
///
/// The orchestrator fills this in by enumerating the btrfs top-level
/// subvolumes (via the existing `mount::probe` surface). Tests
/// construct it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubvolObservation {
    /// The subvolume path relative to the btrfs top level, including
    /// the leading slash. Must match a row in
    /// [`CATOS_STANDARD_SUBVOLS`].
    pub subvol: String,
    /// `true` iff a btrfs subvolume exists at this path.
    pub exists_as_subvol: bool,
    /// `true` iff a regular directory exists at this path inside the
    /// top-level subvolume.
    pub exists_as_directory: bool,
    /// `true` iff some other filesystem object (file, symlink, ...)
    /// exists at this path.
    pub exists_as_other: bool,
    /// For subvolumes whose mount point is a real directory on the
    /// mounted target, the number of entries the directory contains.
    /// `None` if the mount point does not exist or is not enumerable.
    pub mount_point_entry_count: Option<usize>,
}

/// What the probe observed about every potential subvolume, keyed by
/// subvolume path. Tests build this directly; the orchestrator builds
/// it from a `mount::probe::BtrfsProbe`.
#[derive(Debug, Clone, Default)]
pub struct SubvolFacts {
    pub observations: Vec<SubvolObservation>,
}

impl SubvolFacts {
    pub fn find(&self, subvol: &str) -> Option<&SubvolObservation> {
        self.observations.iter().find(|o| o.subvol == subvol)
    }
}

/// What the fstab says about each CatOS standard mount point. Built
/// by the plan builder from the parsed fstab; tests construct it
/// directly.
#[derive(Debug, Clone, Default)]
pub struct FstabHistory {
    /// Mount points that have a CatOS-correct fstab entry pointing
    /// at the matching standard subvol.
    pub correct: Vec<String>,
    /// Mount points whose fstab entry points at the WRONG subvol.
    pub wrong_subvol: Vec<(String, String)>,
}

impl FstabHistory {
    pub fn has_correct_entry(&self, mount_point: &str) -> bool {
        self.correct.iter().any(|mp| mp == mount_point)
    }
    pub fn has_any_entry_for(&self, mount_point: &str) -> bool {
        self.correct.iter().any(|mp| mp == mount_point)
            || self.wrong_subvol.iter().any(|(mp, _)| mp == mount_point)
    }
}

/// Whether the target is confirmed CatOS. The orchestrator decides
/// this from `/etc/os-release` evidence; tests pass it in directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatosConfirmation {
    #[default]
    NotConfirmed,
    Confirmed,
}

/// One decision the plan builder made for a single subvolume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubvolDecision {
    /// The subvolume already exists; no action needed.
    AlreadyExists { subvol: String },
    /// The subvolume is missing AND every precondition holds; the
    /// plan should create it. Carries the matching mount point.
    Create {
        subvol: String,
        mount_point: String,
        reason: String,
    },
    /// The subvolume is missing but the mount-point directory has
    /// data; the plan may create the subvolume and fix fstab, but
    /// the directory data is NOT migrated. The final report MUST
    /// surface `DataConflict`.
    CreateWithDataConflict {
        subvol: String,
        mount_point: String,
        reason: String,
    },
    /// The path is occupied by something that is neither a subvolume
    /// nor an empty directory. We refuse to overwrite.
    RefuseOccupied { subvol: String, reason: String },
    /// No fstab evidence the subvolume ever existed and the target
    /// is not confirmed CatOS. We do not invent standard subvolumes
    /// from nothing.
    RefuseNoHistory { subvol: String, reason: String },
}

impl SubvolDecision {
    /// `true` iff the decision authorises creating the subvolume
    /// (with or without data-conflict reporting).
    pub fn authorises_create(&self) -> bool {
        matches!(
            self,
            SubvolDecision::Create { .. } | SubvolDecision::CreateWithDataConflict { .. }
        )
    }

    pub fn subvol(&self) -> &str {
        match self {
            SubvolDecision::AlreadyExists { subvol }
            | SubvolDecision::Create { subvol, .. }
            | SubvolDecision::CreateWithDataConflict { subvol, .. }
            | SubvolDecision::RefuseOccupied { subvol, .. }
            | SubvolDecision::RefuseNoHistory { subvol, .. } => subvol,
        }
    }

    /// Convert into a [`PlannedSubvolume`] when the decision
    /// authorises creation. Returns `None` for refusals and no-op.
    pub fn into_planned(self) -> Option<PlannedSubvolume> {
        match self {
            SubvolDecision::Create {
                subvol,
                mount_point,
                reason,
            }
            | SubvolDecision::CreateWithDataConflict {
                subvol,
                mount_point,
                reason,
            } => Some(PlannedSubvolume {
                subvol,
                mount_point,
                reason,
            }),
            SubvolDecision::AlreadyExists { .. }
            | SubvolDecision::RefuseOccupied { .. }
            | SubvolDecision::RefuseNoHistory { .. } => None,
        }
    }
}

/// Decide what to do for every CatOS standard subvolume, given the
/// fstab evidence, the on-disk observations, and the CatOS
/// confirmation status. Returns one decision per standard subvolume
/// (whether or not it appears in fstab), in declaration order.
///
/// This is the function Doctor and `catos-repair mount` MUST share.
pub fn decide_all(
    history: &FstabHistory,
    facts: &SubvolFacts,
    catos: CatosConfirmation,
) -> Vec<SubvolDecision> {
    crate::mount::model::CATOS_STANDARD_SUBVOLS
        .iter()
        .map(|row| decide_one(row.subvol, history, facts, catos))
        .collect()
}

/// Decide for one subvolume path. Public so the orchestrator can
/// re-evaluate a single subvolume at apply time after re-probing.
pub fn decide_one(
    subvol: &str,
    history: &FstabHistory,
    facts: &SubvolFacts,
    catos: CatosConfirmation,
) -> SubvolDecision {
    let mount_point = standard_mount_point_for_subvol(subvol).unwrap_or("/");
    let observation = facts.find(subvol);

    // Subvolume already exists: nothing to do.
    if let Some(obs) = observation {
        if obs.exists_as_subvol {
            return SubvolDecision::AlreadyExists {
                subvol: subvol.to_string(),
            };
        }
    }

    // Path occupied by something that is not a subvolume (regular
    // directory, file, symlink, ...). Btrfs refuses to create a
    // subvolume at an occupied path anyway; we surface the
    // condition as a refusal rather than delete user data. The
    // spec is explicit: "不得覆盖目录内容; 不得悄悄搬迁数据".
    if let Some(obs) = observation {
        if obs.exists_as_other || obs.exists_as_directory {
            return SubvolDecision::RefuseOccupied {
                subvol: subvol.to_string(),
                reason: format!(
                    "path {subvol} is occupied by a non-subvolume object (directory={}, other={}); \
                     refusing to overwrite",
                    obs.exists_as_directory, obs.exists_as_other
                ),
            };
        }
    }

    // Authorisation: fstab history OR confirmed CatOS target.
    let fstab_history = history.has_any_entry_for(mount_point);
    let authorised = fstab_history || catos == CatosConfirmation::Confirmed;
    if !authorised {
        return SubvolDecision::RefuseNoHistory {
            subvol: subvol.to_string(),
            reason: format!(
                "no fstab entry references {mount_point} and target is not confirmed CatOS; \
                 refusing to invent the {subvol} subvolume from nothing"
            ),
        };
    }

    // Mount-point directory inspection.
    let mount_point_entry_count = observation
        .and_then(|o| o.mount_point_entry_count)
        .unwrap_or(0);
    if mount_point_entry_count > 0 {
        // Directory has data. Spec § 五: we MAY create the subvolume
        // and fix fstab, but the directory data is NOT migrated.
        return SubvolDecision::CreateWithDataConflict {
            subvol: subvol.to_string(),
            mount_point: mount_point.to_string(),
            reason: format!(
                "{subvol} missing; mount-point {mount_point} contains {mount_point_entry_count} \
                 existing entr(ies); subvolume will be created but data will NOT be migrated"
            ),
        };
    }

    // Either the directory does not exist or it is empty: safe to
    // create.
    SubvolDecision::Create {
        subvol: subvol.to_string(),
        mount_point: mount_point.to_string(),
        reason: format!(
            "{subvol} missing and authorised by {}",
            if fstab_history {
                "existing fstab entry"
            } else {
                "confirmed CatOS target"
            }
        ),
    }
}

/// Convert a slice of decisions into the model's `MountProblem`
/// representation, for the diagnosis surface. `AlreadyExists` and
/// authorised `Create` produce no problems; refusals and conflicts
/// do.
pub fn decisions_to_problems(decisions: &[SubvolDecision]) -> Vec<MountProblem> {
    let mut out = Vec::new();
    for d in decisions {
        match d {
            SubvolDecision::AlreadyExists { .. } | SubvolDecision::Create { .. } => {}
            SubvolDecision::CreateWithDataConflict {
                subvol,
                mount_point,
                ..
            } => {
                out.push(MountProblem::MissingSubvolume {
                    subvol: subvol.clone(),
                });
                out.push(MountProblem::MissingMountPoint {
                    mount_point: mount_point.clone(),
                });
            }
            SubvolDecision::RefuseOccupied { subvol, reason }
            | SubvolDecision::RefuseNoHistory { subvol, reason } => {
                out.push(MountProblem::UnsafeMountPoint {
                    mount_point: subvol.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }
    out
}

/// Helper: build [`FstabHistory`] from a parsed fstab. Public so the
/// orchestrator does not duplicate the matching logic.
pub fn history_from_entries<'a, I>(entries: I) -> FstabHistory
where
    I: IntoIterator<Item = &'a FstabEntry>,
{
    let mut history = FstabHistory::default();
    for entry in entries {
        let standard_subvol = standard_subvol_for_mount_point(&entry.target);
        let entry_subvol = entry
            .options
            .iter()
            .find_map(|opt| opt.strip_prefix("subvol=").map(str::to_string));
        match (standard_subvol, entry_subvol) {
            (Some(std), Some(actual)) if actual == std => {
                history.correct.push(entry.target.clone());
            }
            (Some(_), Some(actual)) => {
                history.wrong_subvol.push((entry.target.clone(), actual));
            }
            _ => {}
        }
    }
    history
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::diagnose::fstab::FstabEntry;

    fn obs(subvol: &str) -> SubvolObservation {
        SubvolObservation {
            subvol: subvol.to_string(),
            exists_as_subvol: false,
            exists_as_directory: false,
            exists_as_other: false,
            mount_point_entry_count: None,
        }
    }

    fn entry(target: &str, subvol: &str) -> FstabEntry {
        // Minimal entry for history_from_entries: target + subvol
        // option. We use the real parser to make sure the shape is
        // correct.
        let line = format!("UUID=root  {target}  btrfs  defaults,subvol={subvol}  0 0");
        crate::mount::diagnose::fstab::parse_line(&line).unwrap().unwrap()
    }

    // ---- Spec § 十一 非特权测试 → 标准子卷决策 ----

    #[test]
    fn fstab_present_subvol_missing_authorises_create_for_home() {
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![obs("/@home")],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(matches!(home, SubvolDecision::Create { .. }));
        assert!(home.authorises_create());
    }

    #[test]
    fn fstab_present_subvol_missing_authorises_create_for_var_log() {
        let history = FstabHistory {
            correct: vec!["/var/log".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![obs("/@log")],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let log = decisions.iter().find(|d| d.subvol() == "/@log").unwrap();
        assert!(matches!(log, SubvolDecision::Create { .. }));
    }

    #[test]
    fn no_history_and_not_catos_refuses_create() {
        // Spec: "fstab 没有历史条目且目标不是明确 CatOS 时，不批量创建".
        let history = FstabHistory::default();
        let facts = SubvolFacts::default();
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        // No `Create` decisions should fire.
        assert!(decisions
            .iter()
            .all(|d| !matches!(d, SubvolDecision::Create { .. })));
        // All non-`/@`-already-exists should be `RefuseNoHistory`.
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(matches!(home, SubvolDecision::RefuseNoHistory { .. }));
    }

    #[test]
    fn confirmed_catos_without_fstab_history_authorises_missing_standard_entries() {
        // Spec § 五: "如果是全新缺失的标准条目，可根据已确认的
        // CatOS 布局新增条目". So on a confirmed CatOS target,
        // missing standard subvolumes ARE authorised even without
        // explicit fstab history. The "don't mass-create" rule
        // applies only to NOT-confirmed targets.
        let history = FstabHistory::default();
        let facts = SubvolFacts::default();
        let decisions = decide_all(&history, &facts, CatosConfirmation::Confirmed);
        for d in &decisions {
            assert!(
                matches!(
                    d,
                    SubvolDecision::Create { .. } | SubvolDecision::AlreadyExists { .. }
                ),
                "{d:?} should authorise on confirmed CatOS"
            );
        }
    }

    #[test]
    fn existing_subvol_is_noop() {
        // Spec: "同名子卷已存在时不重复创建".
        let mut o = obs("/@home");
        o.exists_as_subvol = true;
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(matches!(home, SubvolDecision::AlreadyExists { .. }));
        assert!(!home.authorises_create());
    }

    #[test]
    fn path_is_regular_directory_refuses_overwrite() {
        // Spec: "同名路径是普通目录时拒绝覆盖". A non-empty directory
        // at the subvol path is a data conflict; an EMPTY directory
        // could be replaced but we conservatively refuse to keep the
        // rule simple and predictable.
        let mut o = obs("/@home");
        o.exists_as_directory = true;
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(
            matches!(home, SubvolDecision::RefuseOccupied { .. }),
            "got {home:?}"
        );
    }

    #[test]
    fn path_is_non_directory_object_refuses_overwrite() {
        let mut o = obs("/@home");
        o.exists_as_other = true;
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(matches!(home, SubvolDecision::RefuseOccupied { .. }));
    }

    #[test]
    fn mount_point_has_data_creates_with_data_conflict() {
        // Spec: "mount point 有数据时标记 data conflict" and
        // "空 mount point 可以安全完成".
        let mut o = obs("/@home");
        o.mount_point_entry_count = Some(3);
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        match home {
            SubvolDecision::CreateWithDataConflict { mount_point, .. } => {
                assert_eq!(mount_point, "/home")
            }
            other => panic!("expected CreateWithDataConflict, got {other:?}"),
        }
        // Data-conflict decisions still authorise creation.
        assert!(home.authorises_create());
    }

    #[test]
    fn empty_mount_point_safe_create() {
        let mut o = obs("/@home");
        o.mount_point_entry_count = Some(0);
        let history = FstabHistory {
            correct: vec!["/home".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let home = decisions.iter().find(|d| d.subvol() == "/@home").unwrap();
        assert!(matches!(home, SubvolDecision::Create { .. }));
    }

    #[test]
    fn snapshots_subvol_does_not_touch_recovery_data() {
        // Spec: "@snapshots 不得触碰 Recovery transaction 数据".
        // We only authorise the subvolume creation; the orchestrator
        // MUST NOT delete or modify any pre-existing content under
        // /.snapshots. The decision surface here makes the @snapshots
        // case look identical to any other standard subvolume so the
        // orchestrator cannot accidentally special-case it into
        // wiping data.
        let mut o = obs("/@snapshots");
        o.mount_point_entry_count = Some(7); // existing snapshots
        let history = FstabHistory {
            correct: vec!["/.snapshots".into()],
            wrong_subvol: vec![],
        };
        let facts = SubvolFacts {
            observations: vec![o],
        };
        let decisions = decide_all(&history, &facts, CatosConfirmation::NotConfirmed);
        let snapshots = decisions
            .iter()
            .find(|d| d.subvol() == "/@snapshots")
            .unwrap();
        // Existing data → CreateWithDataConflict, NEVER destructive.
        assert!(matches!(
            snapshots,
            SubvolDecision::CreateWithDataConflict { .. }
        ));
    }

    #[test]
    fn history_from_entries_classifies_correct_and_wrong_subvol() {
        let entries = vec![
            entry("/home", "/@home"),     // correct
            entry("/var/log", "/@wrong"), // wrong subvol
            entry("/data", "/@data"),     // not a standard subvol
        ];
        let history = history_from_entries(&entries);
        assert!(history.has_correct_entry("/home"));
        assert!(history.has_any_entry_for("/var/log"));
        assert!(!history.has_any_entry_for("/data"));
        // wrong_subvol tracked
        assert_eq!(
            history.wrong_subvol.iter().find(|(mp, _)| mp == "/var/log"),
            Some(&("/var/log".to_string(), "/@wrong".to_string()))
        );
    }

    #[test]
    fn into_planned_only_for_authorised_decisions() {
        let create = SubvolDecision::Create {
            subvol: "/@home".into(),
            mount_point: "/home".into(),
            reason: "r".into(),
        };
        assert!(create.clone().into_planned().is_some());

        let conflict = SubvolDecision::CreateWithDataConflict {
            subvol: "/@home".into(),
            mount_point: "/home".into(),
            reason: "r".into(),
        };
        assert!(conflict.clone().into_planned().is_some());

        let exists = SubvolDecision::AlreadyExists {
            subvol: "/@home".into(),
        };
        assert!(exists.into_planned().is_none());
    }
}
