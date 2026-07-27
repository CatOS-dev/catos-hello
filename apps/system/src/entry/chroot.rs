//! `catos-chroot` CLI application orchestration.

use std::io::{IsTerminal, Write};

use crate::chroot::diagnose::fstab::read_from_device;
use crate::chroot::execute::{
    authorize, execute_plan, open_luks, ChrootPrivilegeEvidence, OpenedLuks, SystemChrootEffects,
};
use crate::chroot::model::{BlockDevice, ChrootExecutionOutcome, Subvolume};
use crate::chroot::plan::{build_plan, ChrootPlanInputs, ExtraMountSelection};
use crate::chroot::session::{establish_private_namespace, ChrootSessionRoot};
use crate::error::exit_code;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ChrootOptions {
    skip_root_check: bool,
    no_auto_mount: bool,
    no_systemd_chroot: bool,
    show_btrfs_dot_snapshots: bool,
}

pub fn run(argv: &[String]) -> i32 {
    let options = match parse_argv(argv) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("catos-chroot: argument error: {message}");
            return exit_code::ARG_ERROR;
        }
    };

    let evidence = if options.skip_root_check {
        ChrootPrivilegeEvidence::ExplicitNonRootOverride
    } else {
        ChrootPrivilegeEvidence::EffectiveUid(unsafe { libc::geteuid() })
    };
    let authorization = match authorize(evidence) {
        Ok(authorization) => authorization,
        Err(message) => {
            eprintln!(
                "catos-chroot: {message}; pass --skip-root-check to override (not recommended)"
            );
            return exit_code::PERMISSION_DENIED;
        }
    };

    if let Err(message) = establish_private_namespace() {
        eprintln!("catos-chroot: cannot establish private mount namespace: {message}");
        return exit_code::PROBE_FAILED;
    }

    let mut devices = target_inventory_for_chroot();
    if devices.is_empty() {
            eprintln!("catos-chroot: no usable block devices found");
            return exit_code::PROBE_FAILED;
    }

    let discovery = crate::target::discovery::discover_targets();
    let mut opened_luks: Option<OpenedLuks> = None;
    let selected_target = match crate::selection_ui::select_target(&discovery, "catos-chroot") {
        crate::selection_ui::Selection::Selected(candidate) => candidate,
        crate::selection_ui::Selection::Declined => {
            eprintln!("catos-chroot: target selection declined");
            return exit_code::ARG_ERROR;
        }
        crate::selection_ui::Selection::Unavailable(reason) if discovery.candidates.is_empty() => {
            let encrypted = match crate::selection_ui::select_luks_device(&crate::target::discovery::discover_inventory(), "catos-chroot") {
                Ok(Some(device)) => device,
                Ok(None) => { eprintln!("catos-chroot: {reason}"); return exit_code::PROBE_FAILED; }
                Err(error) => { eprintln!("catos-chroot: {error}"); return exit_code::PROBE_FAILED; }
            };
            let Some(luks_device) = target_block_to_chroot(&encrypted) else {
                eprintln!("catos-chroot: encrypted inventory device has no path");
                return exit_code::PROBE_FAILED;
            };
            let opened = match open_luks(&luks_device, authorization) {
                Ok(opened) => opened,
                Err(error) => { eprintln!("catos-chroot: {error}"); return exit_code::PROBE_FAILED; }
            };
            let mut opened = Some(opened);
            match resolve_after_luks(
                crate::target::discovery::discover_targets,
                |report| crate::selection_ui::select_target(report, "catos-chroot"),
                target_inventory_for_chroot,
                || opened.take().expect("opened LUKS token").close(),
            ) {
                Ok((selected, fresh_inventory)) => { devices = fresh_inventory; opened_luks = opened; selected }
                Err(error) => { eprintln!("catos-chroot: {error}"); return exit_code::PROBE_FAILED; }
            }
        }
        crate::selection_ui::Selection::Unavailable(reason) => { eprintln!("catos-chroot: {reason}"); return exit_code::PROBE_FAILED; }
    };
    let root_device = match find_selected_device(&devices, &selected_target.root_device) {
        Some(device) => device.clone(),
        None => {
            return fail_with_luks_cleanup(
                opened_luks.take(), exit_code::PROBE_FAILED,
                format!("selected device {} disappeared from fresh shared inventory", selected_target.root_device.display()),
            );
        }
    };

    let selected_subvolume = if root_device.is_btrfs() {
        match (selected_target.root_subvolume.as_deref(), selected_target.root_subvolume_id) {
            (Some(path), Some(id)) => Some(Subvolume { id, name: path.trim_start_matches('/').to_string() }),
            _ => return fail_with_luks_cleanup(opened_luks.take(), exit_code::PROBE_FAILED, "selected Btrfs target has incomplete shared subvolume identity".into()),
        }
    } else {
        None
    };

    let fstab = if options.no_auto_mount {
        Vec::new()
    } else {
        match read_from_device(&root_device, selected_subvolume.as_ref()) {
            Ok(entries) => entries,
            Err(message) => {
                return fail_with_luks_cleanup(opened_luks.take(), exit_code::PROBE_FAILED, message);
            }
        }
    };

    let extra_mounts = prompt_extra_mounts(&devices);
    let plan = match build_plan(ChrootPlanInputs {
        root_device: &root_device,
        root_subvolume: selected_subvolume.as_ref(),
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &extra_mounts,
        use_systemd_chroot: !options.no_systemd_chroot,
    }) {
        Ok(plan) => plan,
        Err(error) => {
            return fail_with_luks_cleanup(opened_luks.take(), exit_code::ARG_ERROR, error.to_string());
        }
    };
    for warning in &plan.warnings {
        eprintln!("catos-chroot: warning: {warning}");
    }

    let session = match ChrootSessionRoot::create() {
        Ok(session) => session,
        Err(message) => {
            return fail_with_luks_cleanup(opened_luks.take(), exit_code::PROBE_FAILED, message);
        }
    };
    let mut effects = SystemChrootEffects;
    let report = execute_plan(&plan, authorization, session.path(), &mut effects);
    let session_cleanup = session.cleanup();
    let luks_cleanup = opened_luks.take().map(OpenedLuks::close).transpose();

    if let Some(failure) = &report.failure {
        eprintln!("catos-chroot: {failure}");
    }
    if let Err(error) = &session_cleanup {
        eprintln!("catos-chroot: session cleanup failed: {error}");
    }
    if let Err(error) = &luks_cleanup {
        eprintln!("catos-chroot: LUKS cleanup failed: {error}");
    }

    if report.outcome == ChrootExecutionOutcome::Entered
        && report.cleanup_complete
        && session_cleanup.is_ok()
        && luks_cleanup.is_ok()
    {
        exit_code::SUCCESS
    } else {
        exit_code::PROBE_FAILED
    }
}

fn fail_with_luks_cleanup(opened_luks: Option<OpenedLuks>, code: i32, message: String) -> i32 {
    eprintln!("catos-chroot: {message}");
    if let Some(opened) = opened_luks {
        if let Err(error) = opened.close() {
            eprintln!("catos-chroot: LUKS cleanup failed: {error}");
            return exit_code::PROBE_FAILED;
        }
    }
    code
}

fn target_inventory_for_chroot() -> Vec<BlockDevice> {
    crate::target::discovery::discover_inventory()
        .into_iter()
        .filter_map(|device| Some(BlockDevice {
            name: device.dev_path?.display().to_string(),
            fs_type: device.filesystem,
            uuid: device.uuid,
            partuuid: device.part_uuid,
            label: device.label,
            partlabel: device.part_label,
        }))
        .collect()
}

fn target_block_to_chroot(device: &crate::target::model::BlockDevice) -> Option<BlockDevice> {
    Some(BlockDevice {
        name: device.dev_path.as_ref()?.display().to_string(), fs_type: device.filesystem.clone(), uuid: device.uuid.clone(),
        partuuid: device.part_uuid.clone(), label: device.label.clone(), partlabel: device.part_label.clone(),
    })
}

fn find_selected_device(devices: &[BlockDevice], selected: &std::path::Path) -> Option<BlockDevice> {
    devices.iter().find(|device| std::path::Path::new(&device.name) == selected).cloned()
}

fn resolve_after_luks<D, S, I, C>(discover: D, select: S, inventory: I, close: C) -> Result<(crate::target::discovery::TargetCandidate, Vec<BlockDevice>), String>
where
    D: FnOnce() -> crate::target::discovery::DiscoveryReport,
    S: FnOnce(&crate::target::discovery::DiscoveryReport) -> crate::selection_ui::Selection,
    I: FnOnce() -> Vec<BlockDevice>,
    C: FnOnce() -> Result<(), String>,
{
    let report = discover();
    let candidate = match select(&report) {
        crate::selection_ui::Selection::Selected(candidate) => candidate,
        crate::selection_ui::Selection::Declined => return close_after_luks_failure(close, "target selection declined"),
        crate::selection_ui::Selection::Unavailable(reason) => return close_after_luks_failure(close, &format!("unlocked mapper did not yield a CatOS candidate: {reason}")),
    };
    let fresh = inventory();
    if find_selected_device(&fresh, &candidate.root_device).is_none() {
        return close_after_luks_failure(close, "selected mapper is absent from fresh shared inventory");
    }
    Ok((candidate, fresh))
}

fn close_after_luks_failure<T, C>(close: C, reason: &str) -> Result<T, String>
where C: FnOnce() -> Result<(), String> {
    match close() { Ok(()) => Err(reason.into()), Err(error) => Err(format!("{reason}; LUKS cleanup failed: {error}")) }
}

pub fn print_help() {
    let version = crate::PROGRAM_VERSION;
    print!(
        "catos-chroot {version} - CatOS interactive chroot helper\n\nUSAGE:\n    catos-chroot [OPTIONS]\n\nDESCRIPTION:\n    Diagnoses the selected target read-only, builds a typed mount plan,\n    assembles the target in a private session root, verifies it, and then\n    enters arch-chroot. All mounts and LUKS mappings opened by this command\n    are cleaned up before exit.\n\nOPTIONS:\n    --skip-root-check          Explicitly authorise non-root execution (dangerous).\n    --no-auto-mount            Do not plan target mounts from /etc/fstab.\n    --no-systemd-chroot        Drop the -S flag passed to arch-chroot.\n    --show-btrfs-dot-snapshots Include .snapshots/* subvolumes in the picker.\n    -h, --help                 Show this help message and exit.\n    -V, --version              Print program version and exit.\n\nEXIT CODES:\n    0   Shell exited and cleanup completed.\n    2   Argument, plan, or selection error.\n    4   Chroot execution was not authorised.\n    5   Diagnosis, mount, verification, shell, or cleanup failed.\n"
    );
}

fn parse_argv(argv: &[String]) -> Result<ChrootOptions, String> {
    let mut options = ChrootOptions::default();
    for argument in argv {
        match argument.as_str() {
            "--skip-root-check" => options.skip_root_check = true,
            "--no-auto-mount" => options.no_auto_mount = true,
            "--no-systemd-chroot" => options.no_systemd_chroot = true,
            "--show-btrfs-dot-snapshots" => options.show_btrfs_dot_snapshots = true,
            other => {
                return Err(format!(
                    "unknown option {other:?}; expected --skip-root-check, --no-auto-mount, --no-systemd-chroot, --show-btrfs-dot-snapshots"
                ))
            }
        }
    }
    Ok(options)
}

fn prompt_extra_mounts(devices: &[BlockDevice]) -> Vec<ExtraMountSelection> {
    if !std::io::stdin().is_terminal() {
        return Vec::new();
    }
    let mut selections = Vec::new();
    while prompt_yes_no("Mount an additional partition?", false) {
        let Some(mount_point) = prompt_mount_point() else {
            continue;
        };
        if mount_point.eq_ignore_ascii_case("skip") {
            continue;
        }
        let Some(device) = prompt_select_device(&mount_point, devices, true) else {
            continue;
        };
        selections.push(ExtraMountSelection {
            device,
            mount_point,
        });
    }
    selections
}

fn prompt_select_device(
    role: &str,
    devices: &[BlockDevice],
    allow_skip: bool,
) -> Option<BlockDevice> {
    if devices.is_empty() {
        eprintln!("catos-chroot: no devices available to pick {role} from");
        return None;
    }
    println!("\nAvailable devices for {role}:");
    let offset = usize::from(allow_skip);
    if allow_skip {
        println!("  0: Skip");
    }
    for (index, device) in devices.iter().enumerate() {
        println!("  {}: {device}", index + offset);
    }
    let upper = devices.len() - 1 + offset;
    loop {
        print!("catos-chroot: pick device [0-{upper}] (default 0): ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        let index = if line.trim().is_empty() {
            0
        } else {
            match line.trim().parse::<usize>() {
                Ok(index) => index,
                Err(_) => {
                    eprintln!("catos-chroot: not a number: {:?}", line.trim());
                    continue;
                }
            }
        };
        if allow_skip && index == 0 {
            return None;
        }
        let candidate = if allow_skip {
            index.saturating_sub(1)
        } else {
            index
        };
        if let Some(device) = devices.get(candidate) {
            return Some(device.clone());
        }
        eprintln!("catos-chroot: index out of range");
    }
}

fn prompt_mount_point() -> Option<String> {
    print!("catos-chroot: mount point (e.g. /boot) or 'skip' to cancel: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    let value = line.trim().to_string();
    if value.is_empty() {
        return None;
    }
    if !value.starts_with('/') && !value.eq_ignore_ascii_case("skip") {
        eprintln!("catos-chroot: mount point must start with /");
        return None;
    }
    Some(value)
}

fn prompt_yes_no(prompt: &str, default: bool) -> bool {
    print!("catos-chroot: {prompt} [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let value = line.trim().to_ascii_lowercase();
    if value.is_empty() {
        return default;
    }
    matches!(value.as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_flags() {
        let options = parse_argv(&[
            "--skip-root-check".into(),
            "--no-auto-mount".into(),
            "--no-systemd-chroot".into(),
            "--show-btrfs-dot-snapshots".into(),
        ])
        .unwrap();
        assert!(options.skip_root_check);
        assert!(options.no_auto_mount);
        assert!(options.no_systemd_chroot);
        assert!(options.show_btrfs_dot_snapshots);
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        assert!(parse_argv(&["--unknown".into()]).is_err());
    }

    #[test]
    fn empty_argv_is_default() {
        assert_eq!(parse_argv(&[]).unwrap(), ChrootOptions::default());
    }

    #[test]
    fn mapper_selected_after_unlock_is_resolved_from_fresh_inventory() {
        let old = BlockDevice { name: "/dev/sda2".into(), fs_type: Some("crypto_LUKS".into()), uuid: Some("luks".into()), partuuid: None, label: None, partlabel: None };
        let fresh = BlockDevice { name: "/dev/mapper/luks-luks".into(), fs_type: Some("btrfs".into()), uuid: Some("root".into()), partuuid: None, label: None, partlabel: None };
        assert!(find_selected_device(&[old], std::path::Path::new("/dev/mapper/luks-luks")).is_none());
        assert_eq!(find_selected_device(&[fresh.clone()], std::path::Path::new("/dev/mapper/luks-luks")).unwrap(), fresh);
    }

    fn mapper_candidate() -> crate::target::discovery::TargetCandidate {
        crate::target::discovery::TargetCandidate { root_device: "/dev/mapper/luks-id".into(), root_fstype: "ext4".into(), root_uuid: Some("root".into()), root_subvolume: None, root_subvolume_id: None, filesystem_id: None, label: None, os_release: Default::default(), fstab_identity: None, currently_mounted: false, running_environment_member: false, confidence: crate::target::model::RootCandidateConfidence::High, evidence: Vec::new() }
    }

    #[test]
    fn luks_resolution_consumes_rediscovered_mapper_inventory() {
        let candidate = mapper_candidate();
        let result = resolve_after_luks(
            || crate::target::discovery::DiscoveryReport { candidates: vec![candidate.clone()], excluded: Vec::new(), rejected: Vec::new(), cleanup: Vec::new() },
            |report| crate::selection_ui::Selection::Selected(report.candidates[0].clone()),
            || vec![BlockDevice { name: "/dev/mapper/luks-id".into(), fs_type: Some("ext4".into()), uuid: Some("root".into()), partuuid: None, label: None, partlabel: None }],
            || panic!("successful rediscovery must not close mapper"),
        ).unwrap();
        assert_eq!(result.0.root_device, std::path::PathBuf::from("/dev/mapper/luks-id"));
        assert_eq!(result.1.len(), 1);
    }

    #[test]
    fn luks_resolution_closes_and_reports_close_failure_after_rediscovery_error() {
        let error = resolve_after_luks(
            crate::target::discovery::DiscoveryReport::default,
            |_| crate::selection_ui::Selection::Unavailable("no mapper candidate".into()),
            Vec::new,
            || Err("close failed".into()),
        ).unwrap_err();
        assert!(error.contains("no mapper candidate"));
        assert!(error.contains("LUKS cleanup failed: close failed"));
    }
}
