//! Privilege elevation command discovery. Picks the first available
//! of `sudo`, `sudo-rs`, `doas`, `run0` — the same precedence
//! `arch-update` uses. The list is fixed and short by design.

use catos_process::trusted_tool_path;

const CANDIDATES: &[&str] = &["sudo", "sudo-rs", "doas", "run0"];

/// Return the basename of the first available elevation command, or
/// `None` if none are present. The returned value is just the
/// basename (e.g. `"sudo"`); callers pass it straight to
/// `Command::new`.
pub fn pick_su_cmd() -> Option<String> {
    for candidate in CANDIDATES {
        if trusted_tool_path(candidate).is_some() {
            return Some((*candidate).to_string());
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
}
