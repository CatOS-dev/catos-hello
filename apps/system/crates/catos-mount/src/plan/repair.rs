//! Mount-repair plan construction + structure-preserving fstab editor +
//! pure path-safety policy.
//!
//! All three are pure (no syscalls, no mounts, no btrfs). They live
//! together because the plan builder is the only consumer of the
//! fstab editor and the path-safety policy, and the spec's `mount/plan`
//! directory carries exactly `session.rs` + `repair.rs`.

mod path_safety {
    //! Pure path-safety checks for mount-repair target operations.
    //!
    //! Spec § 六 requires every mount-point directory we create to go
    //! through confined, dirfd-relative access that rejects symlinks,
    //! `..` components, magic links, and non-directory objects. This
    //! module is the *policy* layer; the kernel's `openat2(2)` with
    //! `RESOLVE_IN_ROOT` is the *enforcement* layer (defence in depth).

    use std::path::{Component, Path};

    /// Reason a path was rejected.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PathRejection {
        Empty,
        NotAbsolute,
        ParentComponent,
        PrefixComponent,
        MagicLink,
        EscapesRoot,
        EmptyComponent,
    }

    impl PathRejection {
        pub fn code(&self) -> &'static str {
            match self {
                PathRejection::Empty => "empty",
                PathRejection::NotAbsolute => "not_absolute",
                PathRejection::ParentComponent => "parent_component",
                PathRejection::PrefixComponent => "prefix_component",
                PathRejection::MagicLink => "magic_link",
                PathRejection::EscapesRoot => "escapes_root",
                PathRejection::EmptyComponent => "empty_component",
            }
        }
    }

    pub fn validate_mount_point_path(path: &Path) -> Result<(), PathRejection> {
        if path.as_os_str().is_empty() {
            return Err(PathRejection::Empty);
        }
        if !path.is_absolute() {
            return Err(PathRejection::NotAbsolute);
        }
        let s = path.to_string_lossy();
        let magic_roots = ["/proc", "/sys", "/dev/fd", "/dev/pts"];
        for root in magic_roots {
            if s == root
                || s.starts_with(&format!("{root}/"))
                || s.starts_with("/proc/self/")
                || s.starts_with("/proc/thread-self/")
            {
                return Err(PathRejection::MagicLink);
            }
        }

        let mut normalised_depth: i32 = 0;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(_) => {
                    normalised_depth += 1;
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(PathRejection::ParentComponent);
                }
                Component::Prefix(_) => return Err(PathRejection::PrefixComponent),
            }
        }
        if normalised_depth < 0 {
            return Err(PathRejection::EscapesRoot);
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PathObservation {
        pub is_symlink: bool,
        pub is_directory: bool,
        pub is_regular_file: bool,
        pub is_other: bool,
    }

    impl PathObservation {
        pub fn directory() -> Self {
            Self {
                is_symlink: false,
                is_directory: true,
                is_regular_file: false,
                is_other: false,
            }
        }
        pub fn missing() -> Self {
            Self {
                is_symlink: false,
                is_directory: false,
                is_regular_file: false,
                is_other: false,
            }
        }
    }

    pub fn validate_directory_creation(
        path: &Path,
        observation: &PathObservation,
    ) -> Result<(), PathRejection> {
        validate_mount_point_path(path)?;
        if observation.is_symlink {
            return Err(PathRejection::MagicLink);
        }
        if observation.is_regular_file || observation.is_other {
            return Err(PathRejection::EscapesRoot);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_relative_path() {
            let err = validate_mount_point_path(Path::new("home")).unwrap_err();
            assert_eq!(err, PathRejection::NotAbsolute);
        }

        #[test]
        fn rejects_parent_component() {
            let err = validate_mount_point_path(Path::new("/home/../etc")).unwrap_err();
            assert_eq!(err, PathRejection::ParentComponent);
        }

        #[test]
        fn rejects_proc_magic_link() {
            for p in ["/proc", "/proc/self", "/proc/self/fd/0", "/proc/1/root"] {
                let err = validate_mount_point_path(Path::new(p)).unwrap_err();
                assert_eq!(err, PathRejection::MagicLink, "path {p}");
            }
        }

        #[test]
        fn rejects_sys_magic_link() {
            let err = validate_mount_point_path(Path::new("/sys/class/block/sda")).unwrap_err();
            assert_eq!(err, PathRejection::MagicLink);
        }

        #[test]
        fn accepts_standard_mount_points() {
            for p in [
                "/",
                "/home",
                "/root",
                "/srv",
                "/var/cache",
                "/var/tmp",
                "/var/log",
                "/.snapshots",
                "/boot",
                "/boot/efi",
                "/efi",
            ] {
                assert!(validate_mount_point_path(Path::new(p)).is_ok(), "path {p}");
            }
        }

        #[test]
        fn directory_creation_rejects_symlink_at_leaf() {
            let obs = PathObservation {
                is_symlink: true,
                is_directory: false,
                is_regular_file: false,
                is_other: false,
            };
            let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
            assert_eq!(err, PathRejection::MagicLink);
        }

        #[test]
        fn directory_creation_rejects_regular_file_at_leaf() {
            let obs = PathObservation {
                is_symlink: false,
                is_directory: false,
                is_regular_file: true,
                is_other: false,
            };
            let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
            assert_eq!(err, PathRejection::EscapesRoot);
        }

        #[test]
        fn directory_creation_accepts_missing_path() {
            let obs = PathObservation::missing();
            assert!(validate_directory_creation(Path::new("/home/user/new"), &obs).is_ok());
        }

        #[test]
        fn directory_creation_accepts_existing_directory() {
            let obs = PathObservation::directory();
            assert!(validate_directory_creation(Path::new("/home"), &obs).is_ok());
        }

        #[test]
        fn directory_creation_rejects_other_object_kind() {
            let obs = PathObservation {
                is_symlink: false,
                is_directory: false,
                is_regular_file: false,
                is_other: true,
            };
            let err = validate_directory_creation(Path::new("/home"), &obs).unwrap_err();
            assert_eq!(err, PathRejection::EscapesRoot);
        }

        #[test]
        fn empty_path_rejected() {
            let err = validate_mount_point_path(Path::new("")).unwrap_err();
            assert_eq!(err, PathRejection::Empty);
        }
    }
}

mod fstab_edit {
    //! Structure-preserving `/etc/fstab` editor.
    //!
    //! The diagnose-layer parser correctly drops comments and blank
    //! lines because diagnosis only needs to *understand* a fstab. The
    //! repair flow needs to *edit* one without destroying the user's
    //! comments, blank-line groupings, or unknown entries. This editor
    //! rewrites only the lines the plan explicitly named.

    use crate::model::PlannedFstabEdit;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FstabEditError {
        LineOutOfRange { line: usize },
        NotAnEntry { line: usize },
        ConflictingEdits { line: usize },
        CannotIsolateSource { line: usize },
    }

    impl std::fmt::Display for FstabEditError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FstabEditError::LineOutOfRange { line } => {
                    write!(f, "fstab edit targets line {line} which is out of range")
                }
                FstabEditError::NotAnEntry { line } => write!(
                    f,
                    "fstab edit targets line {line} which is a comment or blank line; not editable"
                ),
                FstabEditError::ConflictingEdits { line } => write!(
                    f,
                    "two fstab edits target line {line}; the plan builder must merge them"
                ),
                FstabEditError::CannotIsolateSource { line } => write!(
                    f,
                    "cannot isolate source column on line {line}; line has fewer than 2 fields"
                ),
            }
        }
    }

    impl std::error::Error for FstabEditError {}

    pub fn apply_edits(
        original: &str,
        edits: &[PlannedFstabEdit],
    ) -> Result<String, FstabEditError> {
        let lines: Vec<&str> = original.split('\n').collect();
        let entry_line_count = if original.is_empty() {
            0
        } else if original.ends_with('\n') {
            lines.len().saturating_sub(1)
        } else {
            lines.len()
        };

        let mut touched_lines: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for edit in edits {
            match edit {
                PlannedFstabEdit::ReplaceSource { line, .. }
                | PlannedFstabEdit::ReplaceEntry { line, .. }
                | PlannedFstabEdit::DropDuplicate { line, .. } => {
                    if *line == 0 || *line > entry_line_count {
                        return Err(FstabEditError::LineOutOfRange { line: *line });
                    }
                    if !touched_lines.insert(*line) {
                        return Err(FstabEditError::ConflictingEdits { line: *line });
                    }
                    let raw = lines[*line - 1];
                    let trimmed = raw.trim_start();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        return Err(FstabEditError::NotAnEntry { line: *line });
                    }
                }
                PlannedFstabEdit::AppendEntry { .. } => {}
            }
        }

        let edit_for_line = |line: usize| -> Option<&PlannedFstabEdit> {
            edits.iter().find(|e| match e {
                PlannedFstabEdit::ReplaceSource { line: l, .. }
                | PlannedFstabEdit::ReplaceEntry { line: l, .. }
                | PlannedFstabEdit::DropDuplicate { line: l, .. } => *l == line,
                PlannedFstabEdit::AppendEntry { .. } => false,
            })
        };

        let mut out = String::with_capacity(original.len() + 64);
        for index in 1..=entry_line_count {
            let original_line = lines[index - 1];
            let newline_present = index < entry_line_count || original.ends_with('\n');
            match edit_for_line(index) {
                None => {
                    out.push_str(original_line);
                    if newline_present {
                        out.push('\n');
                    }
                }
                Some(PlannedFstabEdit::ReplaceSource { new_source, .. }) => {
                    let rewritten = replace_source_column(original_line, new_source)?;
                    out.push_str(&rewritten);
                    if newline_present {
                        out.push('\n');
                    }
                }
                Some(PlannedFstabEdit::ReplaceEntry { new_line, .. }) => {
                    out.push_str(new_line);
                    if newline_present {
                        out.push('\n');
                    }
                }
                Some(PlannedFstabEdit::DropDuplicate { .. }) => {}
                Some(PlannedFstabEdit::AppendEntry { .. }) => unreachable!(
                    "append edits are not associated with a line; the lookup function excludes them"
                ),
            }
        }

        for edit in edits {
            if let PlannedFstabEdit::AppendEntry { new_line, .. } = edit {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(new_line);
                out.push('\n');
            }
        }

        Ok(out)
    }

    fn replace_source_column(line: &str, new_source: &str) -> Result<String, FstabEditError> {
        let bytes = line.as_bytes();
        let mut start = 0usize;
        while start < bytes.len() && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        if start >= bytes.len() {
            return Err(FstabEditError::CannotIsolateSource { line: 0 });
        }
        let mut end = start;
        while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
            end += 1;
        }
        if end == start {
            return Err(FstabEditError::CannotIsolateSource { line: 0 });
        }
        let mut tail = end;
        while tail < bytes.len() && bytes[tail].is_ascii_whitespace() {
            tail += 1;
        }
        if tail >= bytes.len() {
            return Err(FstabEditError::CannotIsolateSource { line: 0 });
        }

        let prefix = &line[..start];
        let separator = &line[end..tail];
        let rest = &line[tail..];
        Ok(format!("{prefix}{new_source}{separator}{rest}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn replace_src(line: usize, src: &str) -> PlannedFstabEdit {
            PlannedFstabEdit::ReplaceSource {
                line,
                new_source: src.to_string(),
                reason: "test".into(),
            }
        }

        fn replace_entry(line: usize, body: &str) -> PlannedFstabEdit {
            PlannedFstabEdit::ReplaceEntry {
                line,
                new_line: body.to_string(),
                reason: "test".into(),
            }
        }

        fn append(body: &str) -> PlannedFstabEdit {
            PlannedFstabEdit::AppendEntry {
                new_line: body.to_string(),
                reason: "test".into(),
            }
        }

        fn drop_dup(line: usize) -> PlannedFstabEdit {
            PlannedFstabEdit::DropDuplicate {
                line,
                reason: "test".into(),
            }
        }

        #[test]
        fn preserves_comments_blank_lines_and_unknown_entries() {
            let original = "# header comment\n\
                            \n\
                            UUID=old-root  /  btrfs  defaults  0 0\n\
                            \n\
                            # /home\n\
                            UUID=old-root  /home  btrfs  defaults  0 0\n\
                            server:/share  /mnt/nfs  nfs  defaults  0 0\n";
            let edited = apply_edits(original, &[]).unwrap();
            assert_eq!(edited, original, "no edits must be identity");
        }

        #[test]
        fn replaces_only_target_source_keeps_rest_of_line() {
            let original = "UUID=old-root  /  btrfs  rw,relatime,compress=zstd:3,subvol=/@  0 0\n";
            let edited = apply_edits(original, &[replace_src(1, "UUID=new-root")]).unwrap();
            assert_eq!(
                edited,
                "UUID=new-root  /  btrfs  rw,relatime,compress=zstd:3,subvol=/@  0 0\n"
            );
        }

        #[test]
        fn replaces_root_subvol_options() {
            let original = "UUID=root  /  btrfs  rw,relatime,subvol=/@old  0 0\n";
            let edited = apply_edits(
                original,
                &[replace_entry(
                    1,
                    "UUID=root  /  btrfs  rw,relatime,subvol=/@  0 0",
                )],
            )
            .unwrap();
            assert_eq!(edited, "UUID=root  /  btrfs  rw,relatime,subvol=/@  0 0\n");
        }

        #[test]
        fn appends_missing_standard_entry_preserving_trailing_content() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n\
                            UUID=esp  /boot/efi  vfat  defaults  0 2\n";
            let edited = apply_edits(
                original,
                &[append(
                    "UUID=root  /home  btrfs  defaults,subvol=/@home  0 0",
                )],
            )
            .unwrap();
            assert_eq!(
                edited,
                "UUID=root  /  btrfs  defaults  0 0\n\
                 UUID=esp  /boot/efi  vfat  defaults  0 2\n\
                 UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n"
            );
        }

        #[test]
        fn append_inserts_trailing_newline_when_missing() {
            let original = "UUID=root  /  btrfs  defaults  0 0";
            let edited = apply_edits(
                original,
                &[append("UUID=root  /home  btrfs  defaults  0 0")],
            )
            .unwrap();
            assert_eq!(
                edited,
                "UUID=root  /  btrfs  defaults  0 0\n\
                 UUID=root  /home  btrfs  defaults  0 0\n"
            );
        }

        #[test]
        fn does_not_double_append_newline_when_already_present() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n";
            let edited = apply_edits(
                original,
                &[append("UUID=root  /home  btrfs  defaults  0 0")],
            )
            .unwrap();
            assert_eq!(
                edited,
                "UUID=root  /  btrfs  defaults  0 0\n\
                 UUID=root  /home  btrfs  defaults  0 0\n"
            );
            assert!(!edited.ends_with("\n\n"));
        }

        #[test]
        fn drops_duplicate_entry_only_when_explicitly_asked() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n\
                            UUID=root  /  btrfs  defaults  0 0\n";
            let edited = apply_edits(original, &[drop_dup(2)]).unwrap();
            assert_eq!(edited, "UUID=root  /  btrfs  defaults  0 0\n");
        }

        #[test]
        fn swap_entry_is_preserved() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n\
                            UUID=swap  none  swap  defaults  0 0\n";
            let edited = apply_edits(original, &[replace_src(1, "UUID=new-root")]).unwrap();
            assert_eq!(
                edited,
                "UUID=new-root  /  btrfs  defaults  0 0\n\
                 UUID=swap  none  swap  defaults  0 0\n"
            );
        }

        #[test]
        fn noauto_and_nofail_lines_are_preserved_when_not_edited() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n\
                            /dev/sdb1  /mnt/external  ext4  noauto,nofail,ro  0 0\n";
            let edited = apply_edits(original, &[]).unwrap();
            assert_eq!(edited, original);
        }

        #[test]
        fn rejects_edit_targeting_comment() {
            let original = "# header\nUUID=root  /  btrfs  defaults  0 0\n";
            let err = apply_edits(original, &[replace_src(1, "UUID=new")]).unwrap_err();
            assert!(matches!(err, FstabEditError::NotAnEntry { line: 1 }));
        }

        #[test]
        fn rejects_edit_targeting_blank_line() {
            let original = "\nUUID=root  /  btrfs  defaults  0 0\n";
            let err = apply_edits(original, &[replace_src(1, "UUID=new")]).unwrap_err();
            assert!(matches!(err, FstabEditError::NotAnEntry { line: 1 }));
        }

        #[test]
        fn rejects_edit_targeting_out_of_range_line() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n";
            let err = apply_edits(original, &[replace_src(99, "UUID=new")]).unwrap_err();
            assert!(matches!(err, FstabEditError::LineOutOfRange { line: 99 }));
        }

        #[test]
        fn rejects_two_edits_on_same_line() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n";
            let err = apply_edits(
                original,
                &[
                    replace_src(1, "UUID=new"),
                    replace_entry(1, "UUID=other  /  btrfs  defaults  0 0"),
                ],
            )
            .unwrap_err();
            assert!(matches!(err, FstabEditError::ConflictingEdits { line: 1 }));
        }

        #[test]
        fn replace_source_preserves_multi_space_separator() {
            let original = "UUID=old     /     btrfs   defaults   0 0\n";
            let edited = apply_edits(original, &[replace_src(1, "UUID=new")]).unwrap();
            assert_eq!(edited, "UUID=new     /     btrfs   defaults   0 0\n");
        }

        #[test]
        fn replace_source_rejects_single_field_line() {
            let original = "lonelytoken\n";
            let err = apply_edits(original, &[replace_src(1, "UUID=new")]).unwrap_err();
            assert!(matches!(err, FstabEditError::CannotIsolateSource { .. }));
        }

        #[test]
        fn multiple_distinct_edits_apply_in_one_pass() {
            let original = "UUID=old-root  /  btrfs  subvol=/@old  0 0\n\
                            UUID=old-esp  /boot/efi  vfat  defaults  0 2\n";
            let edited = apply_edits(
                original,
                &[
                    replace_entry(1, "UUID=new-root  /  btrfs  subvol=/@  0 0"),
                    replace_src(2, "UUID=new-esp"),
                ],
            )
            .unwrap();
            assert_eq!(
                edited,
                "UUID=new-root  /  btrfs  subvol=/@  0 0\n\
                 UUID=new-esp  /boot/efi  vfat  defaults  0 2\n"
            );
        }

        #[test]
        fn blank_line_at_end_is_preserved() {
            let original = "UUID=root  /  btrfs  defaults  0 0\n\n";
            let edited = apply_edits(original, &[]).unwrap();
            assert_eq!(edited, original);
        }

        #[test]
        fn edit_uses_one_based_line_numbers_matching_parser() {
            let original = "# comment\nUUID=root  /  btrfs  defaults  0 0\n";
            let edited = apply_edits(original, &[replace_src(2, "UUID=new")]).unwrap();
            assert_eq!(edited, "# comment\nUUID=new  /  btrfs  defaults  0 0\n");
        }
    }
}

// ---------------------------------------------------------------------------
// Plan construction
// ---------------------------------------------------------------------------

use crate::diagnose::fstab::{parse_all_with_diagnostics, parse_line, FstabEntry, FstabSource};
use crate::diagnose::layout::is_fat_fstype;
use crate::diagnose::subvolume::{decide_all, history_from_entries, SubvolDecision};
use crate::diagnose::target::diagnose;
use crate::model::{
    default_mount_options, BootMountLayout, FstabDigest, MountProblem, MountRepairPlan,
    PlannedDirectory, PlannedFstabEdit, PlannedSubvolume,
};

pub use fstab_edit::{apply_edits, FstabEditError};
pub use path_safety::{
    validate_directory_creation, validate_mount_point_path, PathObservation, PathRejection,
};

pub use crate::diagnose::target::{MountPointObservation, MountRepairInputs};
pub use crate::model::MountRepairOutcome;

/// Apply the plan's fstab edits to the original text and verify the
/// result re-parses cleanly. Returns the new text on success. This is
/// the **in-memory** apply; the privileged layer writes the returned
/// text to disk atomically.
pub fn apply_in_memory(
    original: &str,
    plan: &crate::model::MountRepairPlan,
) -> Result<String, MountRepairOutcome> {
    let new_text = apply_edits(original, &plan.fstab_edits)
        .map_err(|_| MountRepairOutcome::ConflictingFstab)?;
    let (_, new_diagnostics) = parse_all_with_diagnostics(&new_text);
    if !new_diagnostics.is_empty() {
        return Err(MountRepairOutcome::ConflictingFstab);
    }
    Ok(new_text)
}

/// Build an immutable [`MountRepairPlan`] from diagnosis + subvol
/// decisions + fstab edit plan. Pure: a function of [`MountRepairInputs`].
pub fn build_plan(inputs: &MountRepairInputs) -> MountRepairPlan {
    let problems = diagnose(inputs);
    let fstab_digest = digest_of(&inputs.fstab_text);
    let (entries, _diagnostics) = parse_all_with_diagnostics(&inputs.fstab_text);
    let fstab_edits = build_fstab_edits(inputs, &problems);
    let subvolumes = build_subvol_plan(&entries, inputs);
    let directories = build_directory_plan(inputs);
    let unresolved_conflicts = collect_conflicts(&problems);
    let risks = collect_risks(&problems, &subvolumes);

    MountRepairPlan {
        target: inputs.target.clone(),
        fstab_digest,
        problems,
        fstab_edits,
        subvolumes,
        directories,
        unresolved_conflicts,
        risks,
    }
}

pub fn digest_of(text: &str) -> FstabDigest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    FstabDigest {
        sha256: hex,
        byte_len: text.len() as u64,
    }
}

fn build_fstab_edits(
    inputs: &MountRepairInputs,
    problems: &[MountProblem],
) -> Vec<PlannedFstabEdit> {
    let mut edits = Vec::new();
    let entries_with_lines = parse_with_lines(&inputs.fstab_text);
    let entries: Vec<&FstabEntry> = entries_with_lines.iter().map(|(e, _)| e).collect();

    // Root UUID / subvol fixes. Only a root problem can rewrite `/`.
    for (entry, line) in &entries_with_lines {
        if entry.target != "/" {
            continue;
        }
        let line = *line;
        // Wrong UUID: replace source.
        if let Some(expected) = inputs.target.root_uuid.as_ref() {
            if let FstabSource::Uuid(actual) = &entry.source {
                if actual != expected {
                    edits.push(PlannedFstabEdit::ReplaceSource {
                        line,
                        new_source: format!("UUID={expected}"),
                        reason: format!(
                            "root UUID {actual} does not match discovered device ({expected})"
                        ),
                    });
                }
            }
        }
        // Wrong subvol on btrfs root.
        if entry.fstype == "btrfs"
            && problems
                .iter()
                .any(|p| matches!(p, MountProblem::RootWrongSubvol { .. }))
        {
            let source = inputs
                .target
                .root_uuid
                .as_ref()
                .map(|uuid| format!("UUID={uuid}"));
            edits.push(PlannedFstabEdit::ReplaceEntry {
                line,
                new_line: entry_with_subvol(entry, "/@", source.as_deref()),
                reason: "root subvol must be /@ per CatOS standard layout".into(),
            });
        }
    }

    // Correct existing non-root standard entries in place.
    for (entry, line) in &entries_with_lines {
        let Some(expected) = crate::model::standard_subvol_for_mount_point(&entry.target) else {
            continue;
        };
        if entry.target == "/" || entry.fstype != "btrfs" {
            continue;
        }
        let wrong_standard_subvol = problems.iter().any(|problem| matches!(problem,
            MountProblem::StandardWrongSubvol { mount_point, .. } if mount_point == &entry.target
        ));
        let wrong_snapshots_subvol = entry.target == "/.snapshots"
            && problems
                .iter()
                .any(|problem| matches!(problem, MountProblem::SnapshotsWrongSubvol { .. }));
        if wrong_standard_subvol || wrong_snapshots_subvol {
            edits.push(PlannedFstabEdit::ReplaceEntry {
                line: *line,
                new_line: entry_with_subvol(entry, expected, None),
                reason: format!("{} must use subvol={expected}", entry.target),
            });
        }
    }

    // Missing standard entries: append.
    for spec in crate::model::CATOS_STANDARD_SUBVOLS {
        if spec.mount_point == "/" {
            continue;
        }
        let already = entries.iter().any(|e| e.target == spec.mount_point);
        let problem_present = problems.iter().any(|p| match p {
            MountProblem::MissingStandardEntry { mount_point, .. } => {
                mount_point == spec.mount_point
            }
            _ => false,
        });
        if !already && problem_present {
            let root_source = inputs
                .target
                .root_uuid
                .as_ref()
                .map(|uuid| format!("UUID={uuid}"))
                .or_else(|| {
                    entries
                        .iter()
                        .find(|e| e.target == "/")
                        .map(|e| source_column_string(&e.source))
                });
            let Some(root_source) = root_source else {
                continue;
            };
            let opts = default_mount_options("btrfs").unwrap_or("defaults");
            edits.push(PlannedFstabEdit::AppendEntry {
                new_line: format!(
                    "{root_source}  {mp}  btrfs  {opts},subvol={subvol}  0 0",
                    mp = spec.mount_point,
                    subvol = spec.subvol,
                ),
                reason: format!(
                    "missing CatOS standard entry for {mp} → {subvol}",
                    mp = spec.mount_point,
                    subvol = spec.subvol,
                ),
            });
        }
    }

    // ESP source fix.
    if let (Some(esp_uuid), Some(esp_mount_point)) = (
        inputs.target.esp_uuid.as_ref(),
        inputs
            .target
            .boot_layout
            .as_ref()
            .and_then(BootMountLayout::esp_mount_point),
    ) {
        for (entry, line) in &entries_with_lines {
            if entry.target != esp_mount_point || !is_fat_fstype(&entry.fstype) {
                continue;
            }
            let already_correct =
                matches!(&entry.source, FstabSource::Uuid(actual) if actual == esp_uuid);
            if already_correct {
                continue;
            }
            edits.push(PlannedFstabEdit::ReplaceSource {
                line: *line,
                new_source: format!("UUID={esp_uuid}"),
                reason: format!("ESP source does not match discovered device ({esp_uuid})"),
            });
        }
    }

    dedupe_edits(edits)
}

fn entry_with_subvol(entry: &FstabEntry, subvol: &str, source_override: Option<&str>) -> String {
    let source = source_override
        .map(str::to_owned)
        .unwrap_or_else(|| source_column_string(&entry.source));
    let options: Vec<String> = entry
        .options
        .iter()
        .filter(|option| !option.starts_with("subvol=") && !option.starts_with("subvolid="))
        .cloned()
        .collect();
    let mut opts = options;
    opts.push(format!("subvol={subvol}"));
    format!(
        "{}  {}  {}  {}  {} {}",
        source,
        entry.target,
        entry.fstype,
        opts.join(","),
        entry.dump,
        entry.pass,
    )
}

fn source_column_string(source: &FstabSource) -> String {
    match source {
        FstabSource::Uuid(v) => format!("UUID={v}"),
        FstabSource::PartUuid(v) => format!("PARTUUID={v}"),
        FstabSource::Label(v) => format!("LABEL={v}"),
        FstabSource::PartLabel(v) => format!("PARTLABEL={v}"),
        FstabSource::Path(v) => v.clone(),
        FstabSource::Pseudo(v) => v.clone(),
    }
}

/// Parse the verbatim fstab text and return each entry paired
/// with its 1-based file line number.
fn parse_with_lines(fstab_text: &str) -> Vec<(FstabEntry, usize)> {
    let mut out = Vec::new();
    for (idx, line) in fstab_text.lines().enumerate() {
        if let Ok(Some(entry)) = parse_line(line) {
            out.push((entry, idx + 1));
        }
    }
    out
}

fn dedupe_edits(mut edits: Vec<PlannedFstabEdit>) -> Vec<PlannedFstabEdit> {
    let mut seen_full_replace: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for e in &edits {
        if let PlannedFstabEdit::ReplaceEntry { line, .. } = e {
            seen_full_replace.insert(*line);
        }
    }
    edits.retain(|e| match e {
        PlannedFstabEdit::ReplaceSource { line, .. } => !seen_full_replace.contains(line),
        _ => true,
    });
    edits
}

fn build_subvol_plan(entries: &[FstabEntry], inputs: &MountRepairInputs) -> Vec<PlannedSubvolume> {
    if inputs.target.root_fstype != "btrfs" {
        return Vec::new();
    }
    let history = history_from_entries(entries);
    let decisions = decide_all(&history, &inputs.subvol_facts, inputs.catos_confirmation);
    decisions
        .into_iter()
        .filter_map(|d| match d {
            SubvolDecision::Create { .. } | SubvolDecision::CreateWithDataConflict { .. } => {
                d.into_planned()
            }
            _ => None,
        })
        .collect()
}

fn build_directory_plan(inputs: &MountRepairInputs) -> Vec<PlannedDirectory> {
    let mut out = Vec::new();
    if inputs.target.root_fstype == "btrfs" {
        for spec in crate::model::CATOS_STANDARD_SUBVOLS {
            if spec.mount_point == "/" {
                continue;
            }
            let obs = inputs
                .mount_point_observations
                .get(spec.mount_point)
                .copied()
                .unwrap_or_else(MountPointObservation::missing);
            if !obs.exists && !obs.is_symlink && !obs.is_other_object {
                out.push(PlannedDirectory {
                    mount_point: spec.mount_point.to_string(),
                    reason: format!(
                        "standard CatOS mount point {} does not exist; creating",
                        spec.mount_point
                    ),
                });
            }
        }
    }
    // ESP mount points.
    for mp in ["/boot/efi", "/efi", "/boot"] {
        let obs = inputs
            .mount_point_observations
            .get(mp)
            .copied()
            .unwrap_or_else(MountPointObservation::missing);
        if !obs.exists && !obs.is_symlink && !obs.is_other_object {
            let (entries, _) = parse_all_with_diagnostics(&inputs.fstab_text);
            if entries.iter().any(|e| e.target == mp) {
                out.push(PlannedDirectory {
                    mount_point: mp.to_string(),
                    reason: format!("ESP mount point {mp} referenced by fstab does not exist"),
                });
            }
        }
    }
    out
}

fn collect_conflicts(problems: &[MountProblem]) -> Vec<String> {
    let mut out = Vec::new();
    for p in problems {
        match p {
            MountProblem::UnparseableLine { .. }
            | MountProblem::MissingRootEntry
            | MountProblem::RootSourceUnresolvable
            | MountProblem::DuplicateMountPoint { .. }
            | MountProblem::AmbiguousEsp { .. } => {
                out.push(format!("unresolved: {} ({})", p.code(), problem_summary(p)))
            }
            MountProblem::UnsafeMountPoint {
                mount_point,
                reason,
            } => out.push(format!("unsafe path {mount_point}: {reason}")),
            _ => {}
        }
    }
    out
}

fn collect_risks(problems: &[MountProblem], subvolumes: &[PlannedSubvolume]) -> Vec<String> {
    let mut out = Vec::new();
    if problems
        .iter()
        .any(|p| matches!(p, MountProblem::SnapshotsWrongSubvol { .. }))
    {
        out.push(
            "@snapshots subvol is wrong; snapper configuration may need Doctor attention".into(),
        );
    }
    if subvolumes.iter().any(|s| s.subvol == "/@snapshots") {
        out.push("recreating @snapshots does not run snapper create-config; check Doctor".into());
    }
    out
}

fn problem_summary(p: &MountProblem) -> String {
    match p {
        MountProblem::UnparseableLine { line, reason } => format!("line {line}: {reason}"),
        MountProblem::MissingRootEntry => "no entry for /".into(),
        MountProblem::RootSourceUnresolvable => "root source unresolvable".into(),
        MountProblem::RootUuidMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::RootWrongSubvol { actual } => format!("actual subvol: {actual}"),
        MountProblem::StandardWrongSubvol {
            mount_point,
            expected,
            actual,
        } => format!("{mount_point}: expected {expected}, got {actual}"),
        MountProblem::MissingStandardEntry {
            mount_point,
            subvol,
        } => format!("{mount_point} → {subvol} missing"),
        MountProblem::SnapshotsWrongSubvol { actual } => format!("@snapshots actual: {actual}"),
        MountProblem::EspUuidMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::EspMountPointMismatch { expected, actual } => {
            format!("expected {expected}, got {actual}")
        }
        MountProblem::DuplicateMountPoint { mount_point } => {
            format!("multiple entries for {mount_point}")
        }
        MountProblem::SwapEntryMistyped => "swap entry mistyped".into(),
        MountProblem::MissingSubvolume { subvol } => format!("{subvol} missing"),
        MountProblem::MissingMountPoint { mount_point } => format!("{mount_point} missing"),
        MountProblem::UnsafeMountPoint {
            mount_point,
            reason,
        } => format!("{mount_point}: {reason}"),
        MountProblem::AmbiguousEsp { candidates } => {
            format!("multiple ESP candidates: {}", candidates.join(", "))
        }
        MountProblem::StaleSource { source } => format!("source {source} no longer exists"),
    }
}
