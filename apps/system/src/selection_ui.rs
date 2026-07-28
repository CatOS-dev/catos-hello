//! Shared terminal presentation for target discovery.
//!
//! Discovery remains in `catos-target`; this module only renders the stable
//! candidate model and performs bounded, validated terminal input.

use std::io::{self, BufRead, IsTerminal, Write};

use crate::target::discovery::{DiscoveryReport, TargetCandidate};
use crate::target::model::RootCandidateConfidence;
use crate::target::model::BlockDevice;

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
    PreferRunningRoot,
}

pub fn select_target_with_policy(report: &DiscoveryReport, program: &str, policy: TargetSelectionPolicy) -> Selection {
    select_target_with_policy_for_terminal(report, program, policy, io::stdin().is_terminal())
}

fn select_target_with_policy_for_terminal(
    report: &DiscoveryReport,
    program: &str,
    policy: TargetSelectionPolicy,
    interactive: bool,
) -> Selection {
    if policy == TargetSelectionPolicy::PreferRunningRoot {
        let running = report.candidates.iter().filter(|candidate| candidate.running_environment_member).collect::<Vec<_>>();
        match running.as_slice() {
            [candidate] => { print_summary(candidate); return Selection::Selected(Box::new((*candidate).clone())); }
            [] => {}
            _ => return Selection::Unavailable("multiple candidates claim to be the current running root".into()),
        }
    }
    let candidates = report.candidates.iter()
        .filter(|candidate| policy != TargetSelectionPolicy::OfflineOnly || !candidate.running_environment_member)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        eprintln!("{program}: no diagnosable CatOS system was found");
        if policy == TargetSelectionPolicy::OfflineOnly
            && report.candidates.iter().any(|candidate| candidate.running_environment_member)
        {
            eprintln!("{program}: the current running root is CatOS but is not eligible for this offline operation");
        }
        for item in report.excluded.iter().chain(&report.rejected) {
            eprintln!("{program}: {}: {}", item.source, item.reason);
        }
        let reason = if policy == TargetSelectionPolicy::OfflineOnly { "no offline CatOS candidate" } else { "no CatOS candidate" };
        return Selection::Unavailable(reason.into());
    }
    select_from_candidates(&candidates, program, interactive)
}

fn select_from_candidates(
    candidates: &[&TargetCandidate],
    program: &str,
    interactive: bool,
) -> Selection {
    if !interactive {
        return match candidates {
            [candidate] if candidate.confidence == RootCandidateConfidence::High => Selection::Selected(Box::new((*candidate).clone())),
            _ => Selection::Unavailable("multiple target candidates require an interactive terminal".into()),
        };
    }
    if candidates.len() == 1 && candidates[0].confidence == RootCandidateConfidence::High {
        let candidate = candidates[0];
        print_summary(candidate);
        return match read_confirm(program, "Use this target?") {
            Ok(true) => Selection::Selected(Box::new(candidate.clone())),
            Ok(false) => Selection::Declined,
            Err(error) => Selection::Unavailable(error),
        };
    }
    println!("Available CatOS targets:");
    for (index, candidate) in candidates.iter().enumerate() {
        println!("  [{}] {}", index + 1, summary(candidate));
    }
    println!("  [0] Back");
    match read_index(program, "target", candidates.len()) {
        Ok(Some(index)) => { let candidate = candidates[index].clone(); print_summary(&candidate); Selection::Selected(Box::new(candidate)) }
        Ok(None) => Selection::Declined,
        Err(error) => Selection::Unavailable(error),
    }
}

/// Pick an encrypted container only when no eligible CatOS candidate exists.
/// The unlocked mapper is subsequently re-discovered and passed through the
/// caller's explicit target-selection policy.
pub fn select_luks_device(
    devices: &[BlockDevice],
    program: &str,
) -> Result<LuksSelection, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    select_luks_device_with(
        devices,
        program,
        io::stdin().is_terminal(),
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
        writeln!(
            output,
            "  [{}] {} UUID={}",
            index + 1,
            device
                .dev_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| device.name.clone()),
            device.uuid.as_deref().unwrap_or("unknown")
        )
        .map_err(|error| format!("stdout write failed: {error}"))?;
    }
    writeln!(output, "  [0] Back")
        .map_err(|error| format!("stdout write failed: {error}"))?;
    let Some(index) = read_index_with(
        input,
        output,
        program,
        "encrypted container",
        candidates.len(),
    )? else {
        return Ok(LuksSelection::Declined);
    };
    Ok(LuksSelection::Selected(Box::new((*candidates[index]).clone())))
}

fn luks_candidates(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    devices.iter().filter(|device| device.filesystem.as_deref().is_some_and(|fs| fs.eq_ignore_ascii_case("crypto_LUKS"))).collect()
}

pub fn summary(candidate: &TargetCandidate) -> String {
    let distro = candidate.os_release.pretty_name.as_deref().or(candidate.os_release.name.as_deref()).unwrap_or("CatOS");
    let uuid = candidate.root_uuid.as_deref().unwrap_or("unknown");
    let subvol = candidate.root_subvolume.as_deref().map(|v| format!(" subvol={v}")).unwrap_or_default();
    format!("{distro} — {} — {} UUID={uuid}{subvol}", candidate.root_device.display(), candidate.root_fstype)
}

fn print_summary(candidate: &TargetCandidate) { println!("Selected target: {}", summary(candidate)); }

fn read_confirm(program: &str, prompt: &str) -> Result<bool, String> {
    loop {
        print!("{program}: {prompt} [y/N] ");
        io::stdout().flush().map_err(|e| format!("stdout write failed: {e}"))?;
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| format!("stdin read failed: {e}"))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "n" | "no" => return Ok(false),
            "y" | "yes" => return Ok(true),
            _ => eprintln!("{program}: enter y or n"),
        }
    }
}

fn read_index(program: &str, noun: &str, count: usize) -> Result<Option<usize>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    read_index_with(&mut input, &mut output, program, noun, count)
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
        output.flush().map_err(|e| format!("stdout write failed: {e}"))?;
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
        TargetCandidate { root_device: PathBuf::from(path), root_fstype: "btrfs".into(), root_uuid: Some(format!("uuid-{path}")), root_subvolume: Some("/@".into()), root_subvolume_id: Some(256), filesystem_id: Some("fsid".into()), label: None, os_release: crate::target::model::OsRelease { pretty_name: Some("CatOS".into()), ..Default::default() }, fstab_identity: None, currently_mounted: running, running_environment_member: running, confidence: RootCandidateConfidence::High, evidence: Vec::new() }
    }

    #[test]
    fn prefer_running_root_selects_it_before_offline_candidates() {
        let report = DiscoveryReport { candidates: vec![candidate("/dev/running", true), candidate("/dev/offline", false)], ..Default::default() };
        match select_target_with_policy(&report, "catos-doctor", TargetSelectionPolicy::PreferRunningRoot) {
            Selection::Selected(selected) => { assert_eq!(selected.root_device, PathBuf::from("/dev/running")); assert!(selected.running_environment_member); }
            other => panic!("expected running root selection, got {other:?}"),
        }
    }

    #[test]
    fn offline_only_policy_never_returns_the_running_root() {
        let report = DiscoveryReport { candidates: vec![candidate("/dev/running", true), candidate("/dev/offline", false)], ..Default::default() };
        match select_target_with_policy_for_terminal(
            &report,
            "catos-chroot",
            TargetSelectionPolicy::OfflineOnly,
            false,
        ) {
            Selection::Selected(selected) => { assert_eq!(selected.root_device, PathBuf::from("/dev/offline")); assert!(!selected.running_environment_member); }
            other => panic!("expected offline selection, got {other:?}"),
        }
    }

    #[test]
    fn offline_only_policy_refuses_a_running_root_only_report() {
        let report = DiscoveryReport { candidates: vec![candidate("/dev/running", true)], ..Default::default() };
        match select_target_with_policy(&report, "catos-chroot", TargetSelectionPolicy::OfflineOnly) {
            Selection::Unavailable(reason) => assert!(reason.contains("offline")),
            other => panic!("expected unavailable selection, got {other:?}"),
        }
    }

    #[test]
    fn summary_includes_device_uuid_and_subvolume() {
        let candidate = TargetCandidate { root_device: PathBuf::from("/dev/nvme0n1p3"), root_fstype: "btrfs".into(), root_uuid: Some("uuid".into()), root_subvolume: Some("/@".into()), root_subvolume_id: Some(256), filesystem_id: Some("fsid".into()), label: None, os_release: crate::target::model::OsRelease { pretty_name: Some("CatOS".into()), ..Default::default() }, fstab_identity: None, currently_mounted: false, running_environment_member: false, confidence: RootCandidateConfidence::High, evidence: Vec::new() };
        assert_eq!(summary(&candidate), "CatOS — /dev/nvme0n1p3 — btrfs UUID=uuid subvol=/@");
    }

    #[test]
    fn luks_picker_only_exposes_encrypted_containers_before_rediscovery() {
        let encrypted = crate::target::model::BlockDevice {
            name: "sda2".into(), dev_path: Some(PathBuf::from("/dev/sda2")), major_minor: None, parent: String::new(), class: Default::default(), disk_kind: Default::default(), partition_role: crate::target::model::PartitionRole::Unknown, partition_number: None, size_sectors: None, read_only: false, removable: false, filesystem: Some("crypto_LUKS".into()), uuid: Some("luks-id".into()), part_uuid: None, label: None, part_label: None, mount_point: None, mounts: Vec::new(), mounted_before_session: false, evidence: Vec::new(),
        };
        let mut plain = encrypted.clone();
        plain.filesystem = Some("ext4".into());
        assert_eq!(luks_candidates(&[plain, encrypted.clone()]), vec![&encrypted]);
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
            select_luks_device_with(&[], "catos-chroot", true, &mut no_input, &mut output)
                .unwrap(),
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
            read_index_with(&mut selected, &mut output, "catos-repair", "target", 2)
                .unwrap(),
            Some(1)
        );

        let mut back = std::io::Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut back, &mut output, "catos-repair", "target", 2)
                .unwrap(),
            None
        );
    }

    #[test]
    fn target_picker_reprompts_invalid_input_and_eof_cancels() {
        let mut input = std::io::Cursor::new(b"3\n1\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut input, &mut output, "catos-repair", "target", 2)
                .unwrap(),
            Some(0)
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("enter a number from 0 to 2"));

        let mut eof = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert_eq!(
            read_index_with(&mut eof, &mut output, "catos-repair", "target", 2)
                .unwrap(),
            None
        );
    }
}
