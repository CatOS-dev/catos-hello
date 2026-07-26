//! Structure-preserving `/etc/fstab` editor.
//!
//! The phase-2 fstab parser ([`crate::parse::fstab`]) correctly drops
//! comments and blank lines because phase-2 only needs to *understand*
//! a fstab. The mount-repair flow needs to *edit* one without
//! destroying the user's comments, blank-line groupings, or unknown
//! entries. Re-serialising the parsed AST would silently delete every
//! comment in the user's fstab — exactly the failure mode the spec
//! calls out in § 四:
//!
//! > 如果现有 parser 丢失注释和格式，必须为 repair 增加能够保留原
//! > 文本结构的编辑层。
//!
//! ## Design
//!
//! The editor takes the **verbatim original text** and a list of
//! [`PlannedFstabEdit`]s, and produces the new text by line-oriented
//! rewriting:
//!
//! * `ReplaceSource { line, new_source }` rewrites only the source
//!   column of `line`, leaving the rest of the line verbatim.
//! * `ReplaceEntry { line, new_line }` rewrites the whole line.
//! * `AppendEntry { new_line }` appends to the end of the file
//!   (inserting a trailing newline only if the original did not end
//!   with one).
//! * `DropDuplicate { line }` deletes the line.
//!
//! Lines are 1-based to match the existing parser's
//! [`FstabDiagnostic::line`].
//!
//! Every edit carries a `reason` that is preserved in the plan and in
//! the final report so the audit trail is self-explaining.
//!
//! ## Hard rules
//!
//! * Comments (`#...`) and blank lines are NEVER modified or removed
//!   by this editor. The only way a comment can vanish is if the
//!   caller asks to drop a non-comment line that turned out to be a
//!   comment — the editor rejects that with [`FstabEditError`].
//! * An edit whose `line` is out of range is rejected. We never
//!   silently no-op.
//! * The editor does NOT re-parse or re-tokenise the lines it leaves
//!   alone. That is the whole point: the original bytes are preserved
//!   byte-for-byte except for the lines the plan explicitly named.
//! * The editor does NOT invent new entries by itself. The plan
//!   builder decides what to add; the editor only applies.

use crate::shared::model::mount_repair::PlannedFstabEdit;

/// Error returned when an edit cannot be applied safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FstabEditError {
    /// A `line` index was 0 or beyond the end of the file.
    LineOutOfRange { line: usize },
    /// A `ReplaceSource` or `DropDuplicate` targeted a comment or
    /// blank line. Those are never editable.
    NotAnEntry { line: usize },
    /// Two edits in the same plan targeted the same line. Apply is
    /// defined for a set of distinct lines; merging is the plan
    /// builder's job, not the editor's.
    ConflictingEdits { line: usize },
    /// A `ReplaceSource` was asked of a line that is not a real fstab
    /// entry (fewer than 2 whitespace-separated tokens). We refuse to
    /// guess where the source column ends.
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

/// Apply a sequence of planned edits to the original fstab text and
/// return the new text.
///
/// Order of operations:
///
/// 1. Validate that all `line` references are in range and point at
///    real entries (not comments / blanks). Reject the whole plan if
///    any edit is invalid — applying half a plan silently is exactly
///    what the spec forbids.
/// 2. Validate that no two edits target the same line.
/// 3. Walk the original lines once, applying edits as we go. Appends
///    are queued and applied at the end.
/// 4. For appends, ensure exactly one trailing newline.
pub fn apply_edits(original: &str, edits: &[PlannedFstabEdit]) -> Result<String, FstabEditError> {
    // Split keeping line endings so we can reconstruct verbatim. We
    // split on `\n` and keep each line's trailing newline; the last
    // "line" may have no trailing newline if the file did not end
    // with one.
    let lines: Vec<&str> = original.split('\n').collect();
    // split('\n') on "a\nb\n" yields ["a","b",""]; we treat the
    // trailing empty as "no final newline" semantics. 1-based line
    // numbers come from the parser, which counts `body.lines()` —
    // that matches our index `i` in 0..lines.len() minus the trailing
    // empty if present.
    let entry_line_count = if original.is_empty() {
        0
    } else if original.ends_with('\n') {
        lines.len().saturating_sub(1)
    } else {
        lines.len()
    };

    // Validate every edit up-front so we never apply a partial plan.
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
                // The targeted line must be a real entry, not a
                // comment or blank. We deliberately do NOT call the
                // phase-2 parser here because the editor must work
                // even if the parser would reject the line; we only
                // require that the line have non-whitespace content
                // and not start with `#`.
                let raw = lines[*line - 1];
                let trimmed = raw.trim_start();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return Err(FstabEditError::NotAnEntry { line: *line });
                }
            }
            PlannedFstabEdit::AppendEntry { .. } => {}
        }
    }

    // Apply edits in a single pass. We rebuild each line, recording
    // the new content plus its trailing newline. Appends are
    // collected and emitted after the last existing line.
    let mut appends: Vec<&PlannedFstabEdit> = Vec::new();
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
            Some(PlannedFstabEdit::DropDuplicate { .. }) => {
                // Omit the line entirely (including its newline).
            }
            Some(PlannedFstabEdit::AppendEntry { .. }) => unreachable!(
                "append edits are not associated with a line; the lookup function excludes them"
            ),
        }
    }

    // Apply appends.
    for edit in edits {
        if let PlannedFstabEdit::AppendEntry { new_line, .. } = edit {
            appends.push(edit);
            // Ensure the existing content ends with exactly one
            // newline before appending.
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(new_line);
            out.push('\n');
        }
    }
    // Deduplicate the borrow so the unused `appends` warning does not
    // fire under strict lints; the loop above already consumed them.
    drop(appends);

    Ok(out)
}

/// Replace the source (first whitespace-separated field) of a single
/// fstab line, preserving the original whitespace between source and
/// the next field. The point of preserving the original whitespace
/// is to keep diffs minimal — a rewrite that turned
/// `UUID=abc   /   btrfs   ...` (three spaces) into
/// `UUID=def / btrfs ...` (one space) would surprise the user even
/// though both parse identically.
fn replace_source_column(line: &str, new_source: &str) -> Result<String, FstabEditError> {
    // Find the first run of non-whitespace, then the first run of
    // whitespace after it. We deliberately work on bytes to avoid
    // any UTF-8 boundary surprises (fstab is ASCII in practice, but
    // being explicit costs nothing).
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
    // Require at least one more field after the source — otherwise
    // this is not a real fstab entry and we cannot safely know where
    // the source column ends.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // ---- Spec § 十一 非特权测试 → fstab 编辑 ----

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
        // Exactly one blank separator-free line each.
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
        // Spec: swap entries must NOT be touched unless the plan
        // explicitly names them. The editor does not classify; it
        // only applies named edits.
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
        // Original used three spaces between source and mount-point.
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
        // The trailing empty line is preserved because we keep the
        // blank line itself verbatim.
        let edited = apply_edits(original, &[]).unwrap();
        assert_eq!(edited, original);
    }

    #[test]
    fn edit_uses_one_based_line_numbers_matching_parser() {
        // Pin the convention: the parser's `FstabDiagnostic.line`
        // uses 1-based counting. The editor must agree so a plan
        // built from a parser diagnostic addresses the right line.
        let original = "# comment\nUUID=root  /  btrfs  defaults  0 0\n";
        // Line 1 is the comment, line 2 is the entry.
        let edited = apply_edits(original, &[replace_src(2, "UUID=new")]).unwrap();
        assert_eq!(edited, "# comment\nUUID=new  /  btrfs  defaults  0 0\n");
    }
}
