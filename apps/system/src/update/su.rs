//! Privilege elevation command discovery. Picks the first available
//! of `sudo`, `sudo-rs`, `doas`, `run0` — the same precedence
//! `arch-update` uses. The list is fixed and short by design.

use catos_process::trusted_tool_path;
use std::path::PathBuf;

const CANDIDATES: &[&str] = &["sudo", "sudo-rs", "doas", "run0"];

/// Return the absolute path of the first available elevation command.
/// Callers must execute this exact path rather than resolving the basename
/// through the caller-controlled `PATH` a second time.
pub fn pick_su_cmd() -> Option<PathBuf> {
    for candidate in CANDIDATES {
        if let Some(path) = trusted_tool_path(candidate) {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_canonical() {
        assert_eq!(CANDIDATES, &["sudo", "sudo-rs", "doas", "run0"]);
    }

    #[test]
    fn selected_elevation_tool_is_an_absolute_trusted_path() {
        if let Some(path) = pick_su_cmd() {
            assert!(path.is_absolute(), "selected path was relative: {path:?}");
            assert!(
                CANDIDATES
                    .iter()
                    .any(|candidate| path.file_name().is_some_and(|name| name == *candidate)),
                "unexpected elevation tool: {path:?}"
            );
        }
    }
}
