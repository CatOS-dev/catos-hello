//! Shared terminal presentation for target discovery.
//!
//! Discovery remains in `catos-target`; this module only renders the stable
//! candidate model and performs bounded, validated terminal input.

use std::io::{self, BufRead, IsTerminal, Write};

use crate::target::discovery::{DiscoveryReport, TargetCandidate};
use crate::target::model::BlockDevice;
use crate::target::model::RootCandidateConfidence;

#[derive(Debug, Clone)]
pub enum Selection {
    Selected(Box<TargetCandidate>),
    Declined,
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub enum LuksSelection {
    Selected(Box<BlockDevice>),
    Declined,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSelectionPolicy {
    Any,
    OfflineOnly,
    OfflineOnlyAllowUnverified,
    PreferRunningRoot,
}

fn interactive_terminal_available(stdin_is_terminal: bool, stdout_is_terminal: bool) -> bool {
    stdin_is_terminal && stdout_is_terminal
}

pub(crate) fn terminal_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if terminal_control_character(character) => {
                use std::fmt::Write as _;
                write!(output, "\\u{{{:x}}}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output
}

fn terminal_control_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

pub fn select_target_with_policy(
    report: &DiscoveryReport,
    program: &str,
    policy: TargetSelectionPolicy,
) -> Selection {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let interactive = interactive_terminal_available(stdin.is_terminal(), stdout.is_terminal());
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    select_target_with_policy_with(
        report,
        program,
        policy,
        interactive,
        &mut input,
        &mut output,
    )
}

#[cfg(test)]
fn select_target_with_policy_for_terminal(
    report: &DiscoveryReport,
    program: &str,
    policy: TargetSelectionPolicy,
    interactive: bool,
) -> Selection {
    let mut input = io::Cursor::new(Vec::<u8>::new());
    let mut output = Vec::new();
    select_target_with_policy_with(
        report,
        program,
        policy,
        interactive,
        &mut input,
        &mut output,
    )
}

fn select_target_with_policy_with<R: BufRead, W: Write>(
    report: &DiscoveryReport,
    program: &str,
    policy: TargetSelectionPolicy,
    interactive: bool,
    input: &mut R,
    output: &mut W,
) -> Selection {
    if policy == TargetSelectionPolicy::PreferRunningRoot {
        let running = report
            .candidates
            .iter()
            .filter(|candidate| candidate.running_environment_member)
            .collect::<Vec<_>>();
        match running.as_slice() {
            [candidate] => {
                if interactive {
                    if let Err(error) = write_summary(output, candidate) {
                        return Selection::Unavailable(error);
                    }
                }
                return Selection::Selected(Box::new((*candidate).clone()));
            }
            [] => {}
            _ => {
                return Selection::Unavailable(
                    "multiple candidates claim to be the current running root".into(),
                )
            }
        }
    }
    let offline_only = matches!(
        policy,
        TargetSelectionPolicy::OfflineOnly | TargetSelectionPolicy::OfflineOnlyAllowUnverified
    );
    let candidates = report
        .candidates
        .iter()
        .filter(|candidate| !offline_only || !candidate.running_environment_member)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        eprintln!("{program}: no diagnosable CatOS system was found");
        if offline_only
            && report
                .candidates
                .iter()
                .any(|candidate| candidate.running_environment_member)
        {
            eprintln!(
                "{program}: the current running root is CatOS but is not eligible for this offline operation"
            );
        }
        for item in report.excluded.iter().chain(&report.rejected) {
            eprintln!("{program}: {}: {}", item.source, item.reason);
        }
        let reason = if offline_only {
            "no offline CatOS candidate"
        } else {
            "no CatOS candidate"
        };
        return Selection::Unavailable(reason.into());
    }
    select_from_candidates_with_override(
        &candidates,
        program,
        interactive,
        policy == TargetSelectionPolicy::OfflineOnlyAllowUnverified,
        input,
        output,
    )
}

#[cfg(test)]
fn select_from_candidates<R: BufRead, W: Write>(
    candidates: &[&TargetCandidate],
    program: &str,
    interactive: bool,
    input: &mut R,
    output: &mut W,
) -> Selection {
    select_from_candidates_with_override(candidates, program, interactive, false, input, output)
}

fn select_from_candidates_with_override<R: BufRead, W: Write>(
    candidates: &[&TargetCandidate],
    program: &str,
    interactive: bool,
    allow_unverified_noninteractive: bool,
    input: &mut R,
    output: &mut W,
) -> Selection {
    if !interactive {
        return match candidates {
            [] => Selection::Unavailable("no target candidate was found".into()),
            [candidate]
                if candidate.confidence == RootCandidateConfidence::High
                    || allow_unverified_noninteractive =>
            {
                Selection::Selected(Box::new((*candidate).clone()))
            }
            [candidate] => Selection::Unavailable(format!(
                "the only target candidate {} has {:?} confidence and requires interactive confirmation",
                candidate.root_device.display(),
                candidate.confidence
            )),
            _ => Selection::Unavailable(format!(
                "{} target candidates require an interactive terminal",
                candidates.len()
            )),
        };
    }
    if candidates.len() == 1 && candidates[0].confidence == RootCandidateConfidence::High {
        let candidate = candidates[0];
        if let Err(error) = write_summary(output, candidate) {
            return Selection::Unavailable(error);
        }
        return match read_confirm_with(input, output, program, "Use this target?") {
            Ok(true) => Selection::Selected(Box::new(candidate.clone())),
            Ok(false) => Selection::Declined,
            Err(error) => Selection::Unavailable(error),
        };
    }
    let heading = if candidates
        .iter()
        .any(|candidate| !candidate.os_release.looks_like_catos())
    {
        "Available maintenance targets:"
    } else {
        "Available CatOS targets:"
    };
    if let Err(error) =
        writeln!(output, "{heading}").map_err(|error| format!("stdout write failed: {error}"))
    {
        return Selection::Unavailable(error);
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if let Err(error) = writeln!(output, "  [{}] {}", index + 1, summary(candidate))
            .map_err(|error| format!("stdout write failed: {error}"))
        {
            return Selection::Unavailable(error);
        }
    }
    if let Err(error) =
        writeln!(output, "  [0] Back").map_err(|error| format!("stdout write failed: {error}"))
    {
        return Selection::Unavailable(error);
    }
    match read_index_with(input, output, program, "target", candidates.len()) {
        Ok(Some(index)) => {
            let candidate = candidates[index].clone();
            match write_summary(output, &candidate) {
                Ok(()) => Selection::Selected(Box::new(candidate)),
                Err(error) => Selection::Unavailable(error),
            }
        }
        Ok(None) => Selection::Declined,
        Err(error) => Selection::Unavailable(error),
    }
}

/// Pick an encrypted container only when no eligible CatOS candidate exists.
/// The unlocked mapper is subsequently re-discovered and passed through the
/// caller's explicit target-selection policy.
pub fn select_luks_device(devices: &[BlockDevice], program: &str) -> Result<LuksSelection, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    select_luks_device_with(
        devices,
        program,
        interactive_terminal_available(stdin.is_terminal(), stdout.is_terminal()),
        &mut input,
        &mut output,
    )
}

fn select_luks_device_with<R: BufRead, W: Write>(
    devices: &[BlockDevice],
    program: &str,
    interactive: bool,
    input: &mut R,
    output: &mut W,
) -> Result<LuksSelection, String> {
    let candidates = luks_candidates(devices);
    if candidates.is_empty() {
        return Ok(LuksSelection::Unavailable);
    }
    if !interactive {
        return Err("an encrypted target requires an interactive terminal".into());
    }
    writeln!(output, "Encrypted containers:")
        .map_err(|error| format!("stdout write failed: {error}"))?;
    for (index, device) in candidates.iter().enumerate() {
        let device_name = device
            .dev_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| device.name.clone());
        writeln!(
            output,
            "  [{}] {} UUID={}",
            index + 1,
            terminal_text(&device_name),
            terminal_text(device.uuid.as_deref().unwrap_or("unknown"))
        )
        .map_err(|error| format!("stdout write failed: {error}"))?;
    }
    writeln!(output, "  [0] Back").map_err(|error| format!("stdout write failed: {error}"))?;
    let Some(index) = read_index_with(
        input,
        output,
        program,
        "encrypted container",
        candidates.len(),
    )?
    else {
        return Ok(LuksSelection::Declined);
    };
    Ok(LuksSelection::Selected(Box::new(
        (*candidates[index]).clone(),
    )))
}

fn luks_candidates(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    devices
        .iter()
        .filter(|device| {
            device
                .filesystem
                .as_deref()
                .is_some_and(|fs| fs.eq_ignore_ascii_case("crypto_LUKS"))
        })
        .collect()
}

pub fn summary(candidate: &TargetCandidate) -> String {
    let distro = if candidate.os_release.looks_like_catos() {
        candidate
            .os_release
            .pretty_name
            .as_deref()
            .or(candidate.os_release.name.as_deref())
            .unwrap_or("CatOS")
    } else {
        candidate
            .os_release
            .pretty_name
            .as_deref()
            .or(candidate.os_release.name.as_deref())
            .unwrap_or("Unverified system")
    };
    let uuid = candidate.root_uuid.as_deref().unwrap_or("unknown");
    let subvol = candidate
        .root_subvolume
        .as_deref()
        .map(|value| format!(" subvol={}", terminal_text(value)))
        .unwrap_or_default();
    format!(
        "{} — {} — {} UUID={}{}",
        terminal_text(distro),
        terminal_text(&candidate.root_device.display().to_string()),
        terminal_text(&candidate.root_fstype),
        terminal_text(uuid),
        subvol
    )
}

fn write_summary<W: Write>(output: &mut W, candidate: &TargetCandidate) -> Result<(), String> {
    writeln!(output, "Selected target: {}", summary(candidate))
        .map_err(|error| format!("stdout write failed: {error}"))
}

fn read_confirm_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    program: &str,
    prompt: &str,
) -> Result<bool, String> {
    loop {
        write!(output, "{program}: {prompt} [y/N] ")
            .map_err(|error| format!("stdout write failed: {error}"))?;
        output
            .flush()
            .map_err(|error| format!("stdout write failed: {error}"))?;
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|error| format!("stdin read failed: {error}"))?;
        if read == 0 {
            writeln!(output).map_err(|error| format!("stdout write failed: {error}"))?;
            return Ok(false);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "n" | "no" => return Ok(false),
            "y" | "yes" => return Ok(true),
            _ => writeln!(output, "{program}: enter y or n")
                .map_err(|error| format!("stdout write failed: {error}"))?,
        }
    }
}

fn read_index_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    program: &str,
    noun: &str,
    count: usize,
) -> Result<Option<usize>, String> {
    loop {
        write!(output, "{program}: pick {noun} [0-{count}]: ")
            .map_err(|e| format!("stdout write failed: {e}"))?;
        output
            .flush()
            .map_err(|e| format!("stdout write failed: {e}"))?;
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|e| format!("stdin read failed: {e}"))?;
        if read == 0 {
            writeln!(output).map_err(|e| format!("stdout write failed: {e}"))?;
            return Ok(None);
        }
        match line.trim().parse::<usize>() {
            Ok(0) => return Ok(None),
            Ok(index) if index <= count => return Ok(Some(index - 1)),
            _ => writeln!(output, "{program}: enter a number from 0 to {count}")
                .map_err(|e| format!("stdout write failed: {e}"))?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn candidate(path: &str, running: bool) -> TargetCandidate {
        TargetCandidate {
            root_device: PathBuf::from(path),
            root_fstype: "btrfs".into(),
            root_uuid: Some(format!("uuid-{path}")),
            root_subvolume: Some("/@".into()),
            root_subvolume_id: Some(256),
            filesystem_id: Some("fsid".into()),
            label: None,
            os_release: crate::target::model::OsRelease {
                pretty_name: Some("CatOS".into()),
                ..Default::default()
            },
            fstab_identity: None,
            currently_mounted: running,
            running_environment_member: running,
            confidence: RootCandidateConfidence::High,
            evidence: Vec::new(),
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
        }
    }

    #[test]
    fn interactive_selection_requires_both_terminal_streams() {
        assert!(interactive_terminal_available(true, true));
        assert!(!interactive_terminal_available(true, false));
        assert!(!interactive_terminal_available(false, true));
        assert!(!interactive_terminal_available(false, false));
    }

    #[test]
    fn noninteractive_running_root_selection_does_not_write_stdout() {
        let report = DiscoveryReport {
            candidates: vec![candidate("/dev/running", true)],
            ..Default::default()
        };
        let mut input = io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let selection = select_target_with_policy_with(
            &report,
            "catos-doctor",
            TargetSelectionPolicy::PreferRunningRoot,
            false,
            &mut input,
            &mut output,
        );
        assert!(matches!(selection, Selection::Selected(_)));
        assert!(output.is_empty());
    }

    #[test]
    fn noninteractive_selection_distinguishes_low_confidence_from_multiple_candidates() {
        let mut low = candidate("/dev/uncertain", false);
        low.confidence = RootCandidateConfidence::Low;
        let mut input = io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        match select_from_candidates(&[&low], "catos-repair", false, &mut input, &mut output) {
            Selection::Unavailable(reason) => {
                assert!(reason.contains("only target candidate"), "{reason}");
                assert!(reason.contains("Low confidence"), "{reason}");
                assert!(!reason.contains("multiple"), "{reason}");
            }
            other => panic!("expected unavailable selection, got {other:?}"),
        }

        let high_a = candidate("/dev/a", false);
        let high_b = candidate("/dev/b", false);
        match select_from_candidates(
            &[&high_a, &high_b],
            "catos-repair",
            false,
            &mut input,
            &mut output,
        ) {
            Selection::Unavailable(reason) => {
                assert!(reason.contains("2 target candidates"), "{reason}");
            }
            other => panic!("expected unavailable selection, got {other:?}"),
        }
    }

    #[test]
    fn forced_offline_policy_selects_one_unverified_candidate_noninteractively() {
        let mut low = candidate("/dev/uncertain", false);
        low.confidence = RootCandidateConfidence::Low;
        low.os_release = Default::default();
        let report = DiscoveryReport {
            candidates: vec![low],
            ..Default::default()
        };

        match select_target_with_policy_for_terminal(
            &report,
            "catos-chroot",
            TargetSelectionPolicy::OfflineOnlyAllowUnverified,
            false,
        ) {
            Selection::Selected(selected) => {
                assert_eq!(selected.root_device, PathBuf::from("/dev/uncertain"));
                assert_eq!(selected.confidence, RootCandidateConfidence::Low);
            }
            other => panic!("expected forced selection, got {other:?}"),
        }
    }

    #[test]
    fn forced_offline_policy_still_refuses_ambiguous_or_running_targets() {
        let mut first = candidate("/dev/first", false);
        first.confidence = RootCandidateConfidence::Low;
        let mut second = candidate("/dev/second", false);
        second.confidence = RootCandidateConfidence::Medium;
        let ambiguous = DiscoveryReport {
            candidates: vec![first, second],
            ..Default::default()
        };
        assert!(matches!(
            select_target_with_policy_for_terminal(
                &ambiguous,
                "catos-chroot",
                TargetSelectionPolicy::OfflineOnlyAllowUnverified,
                false,
            ),
            Selection::Unavailable(_)
        ));

        let running_only = DiscoveryReport {
            candidates: vec![candidate("/dev/running", true)],
            ..Default::default()
        };
        assert!(matches!(
            select_target_with_policy_for_terminal(
                &running_only,
                "catos-chroot",
                TargetSelectionPolicy::OfflineOnlyAllowUnverified,
                false,
            ),
            Selection::Unavailable(_)
        ));
    }

    #[test]
    fn target_selection_output_failure_is_unavailable_not_a_panic() {
        let report = DiscoveryReport {
            candidates: vec![candidate("/dev/root", false)],
            ..Default::default()
        };
        let mut input = io::Cursor::new(b"yes\n".to_vec());
        let selection = select_target_with_policy_with(
            &report,
            "catos-repair",
            TargetSelectionPolicy::Any,
            true,
            &mut input,
            &mut FailingWriter,
        );
        match selection {
            Selection::Unavailable(error) => assert!(error.contains("stdout write failed")),
            other => panic!("expected unavailable selection, got {other:?}"),
        }
    }

    #[test]
    fn prefer_running_root_selects_it_before_offline_candidates() {
        let report = DiscoveryReport {
            candidates: vec![
                candidate("/dev/running", true),
                candidate("/dev/offline", false),
            ],
            ..Default::default()
        };
        match select_target_with_policy(
            &report,
            "catos-doctor",
            TargetSelectionPolicy::PreferRunningRoot,
        ) {
            Selection::Selected(selected) => {
                assert_eq!(selected.root_device, PathBuf::from("/dev/running"));
                assert!(selected.running_environment_member);
            }
            other => panic!("expected running root selection, got {other:?}"),
        }
    }

    #[test]
    fn offline_only_policy_never_returns_the_running_root() {
        let report = DiscoveryReport {
            candidates: vec![
                candidate("/dev/running", true),
                candidate("/dev/offline", false),
            ],
            ..Default::default()
        };
        match select_target_with_policy_for_terminal(
            &report,
            "catos-chroot",
            TargetSelectionPolicy::OfflineOnly,
            false,
        ) {
            Selection::Selected(selected) => {
                assert_eq!(selected.root_device, PathBuf::from("/dev/offline"));
                assert!(!selected.running_environment_member);
            }
            other => panic!("expected offline selection, got {other:?}"),
        }
    }

    #[test]
    fn offline_only_policy_refuses_a_running_root_only_report() {
        let report = DiscoveryReport {
            candidates: vec![candidate("/dev/running", true)],
            ..Default::default()
        };
        match select_target_with_policy(&report, "catos-chroot", TargetSelectionPolicy::OfflineOnly)
        {
            Selection::Unavailable(reason) => assert!(reason.contains("offline")),
            other => panic!("expected unavailable selection, got {other:?}"),
        }
    }

    #[test]
    fn target_summary_escapes_terminal_control_characters() {
        let mut target = candidate("/dev/root", false);
        target.os_release.pretty_name = Some("CatOS\x1b[2J\nspoof".into());
        target.root_subvolume = Some("/@\nother".into());

        let rendered = summary(&target);
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("CatOS\\u{1b}[2J\\nspoof"));
        assert!(rendered.contains("subvol=/@\\nother"));
    }

    #[test]
    fn unverified_target_summary_and_heading_do_not_claim_catos_identity() {
        let mut target = candidate("/dev/unverified", false);
        target.os_release = Default::default();
        target.confidence = RootCandidateConfidence::Medium;
        assert!(summary(&target).starts_with("Unverified system — "));

        let mut input = io::Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        let result =
            select_from_candidates(&[&target], "catos-chroot", true, &mut input, &mut output);
        assert!(matches!(result, Selection::Declined));
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Available maintenance targets:"));
        assert!(!output.contains("Available CatOS targets:"));
    }

    #[test]
    fn summary_includes_device_uuid_and_subvolume() {
        let candidate = TargetCandidate {
            root_device: PathBuf::from("/dev/nvme0n1p3"),
            root_fstype: "btrfs".into(),
            root_uuid: Some("uuid".into()),
            root_subvolume: Some("/@".into()),
            root_subvolume_id: Some(256),
            filesystem_id: Some("fsid".into()),
            label: None,
            os_release: crate::target::model::OsRelease {
                pretty_name: Some("CatOS".into()),
                ..Default::default()
            },
            fstab_identity: None,
            currently_mounted: false,
            running_environment_member: false,
            confidence: RootCandidateConfidence::High,
            evidence: Vec::new(),
        };
        assert_eq!(
            summary(&candidate),
            "CatOS — /dev/nvme0n1p3 — btrfs UUID=uuid subvol=/@"
        );
    }

    #[test]
    fn luks_picker_only_exposes_encrypted_containers_before_rediscovery() {
        let encrypted = crate::target::model::BlockDevice {
            name: "sda2".into(),
            dev_path: Some(PathBuf::from("/dev/sda2")),
            major_minor: None,
            parent: String::new(),
            class: Default::default(),
            disk_kind: Default::default(),
            partition_role: crate::target::model::PartitionRole::Unknown,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: Some("crypto_LUKS".into()),
            uuid: Some("luks-id".into()),
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        };
        let mut plain = encrypted.clone();
        plain.filesystem = Some("ext4".into());
        assert_eq!(
            luks_candidates(&[plain, encrypted.clone()]),
            vec![&encrypted]
        );
    }

    #[test]
    fn luks_picker_distinguishes_absence_decline_and_selection() {
        let encrypted = crate::target::model::BlockDevice {
            name: "sda2".into(),
            dev_path: Some(PathBuf::from("/dev/sda2")),
            major_minor: None,
            parent: String::new(),
            class: Default::default(),
            disk_kind: Default::default(),
            partition_role: crate::target::model::PartitionRole::Unknown,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: Some("crypto_LUKS".into()),
            uuid: Some("luks-id".into()),
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        };

        let mut no_input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert!(matches!(
            select_luks_device_with(&[], "catos-chroot", true, &mut no_input, &mut output).unwrap(),
            LuksSelection::Unavailable
        ));

        let mut decline = std::io::Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        assert!(matches!(
            select_luks_device_with(
                std::slice::from_ref(&encrypted),
                "catos-chroot",
                true,
                &mut decline,
                &mut output,
            )
            .unwrap(),
            LuksSelection::Declined
        ));

        let mut select = std::io::Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        match select_luks_device_with(
            std::slice::from_ref(&encrypted),
            "catos-chroot",
            true,
            &mut select,
            &mut output,
        )
        .unwrap()
        {
            LuksSelection::Selected(device) => {
                assert_eq!(device.dev_path, encrypted.dev_path);
            }
            other => panic!("expected selected encrypted device, got {other:?}"),
        }
    }

    #[test]
    fn target_picker_is_one_based_and_zero_goes_back() {
        let mut selected = std::io::Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut selected, &mut output, "catos-repair", "target", 2).unwrap(),
            Some(1)
        );

        let mut back = std::io::Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut back, &mut output, "catos-repair", "target", 2).unwrap(),
            None
        );
    }

    #[test]
    fn target_picker_reprompts_invalid_input_and_eof_cancels() {
        let mut input = std::io::Cursor::new(b"3\n1\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut input, &mut output, "catos-repair", "target", 2).unwrap(),
            Some(0)
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("enter a number from 0 to 2"));

        let mut eof = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut eof, &mut output, "catos-repair", "target", 2).unwrap(),
            None
        );
    }
}
