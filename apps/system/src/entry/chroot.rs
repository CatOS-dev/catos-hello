//! `catos-chroot` CLI application orchestration.

use std::io::Write;

use crate::chroot::diagnose::block::list_block_devices;
use crate::chroot::diagnose::btrfs::list_subvolumes;
use crate::chroot::diagnose::fstab::read_from_device;
use crate::chroot::execute::{
    authorize, execute_plan, open_luks, ChrootPrivilegeEvidence, OpenedLuks, SystemChrootEffects,
};
use crate::chroot::model::{BlockDevice, ChrootExecutionOutcome, Subvolume};
use crate::chroot::plan::{build_plan, ChrootPlanInputs, ExtraMountSelection};
use crate::chroot::session::{establish_private_namespace, ChrootSessionRoot};
use crate::shared::error::exit_code;

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

    let mut devices = match list_block_devices() {
        Ok(devices) if devices.is_empty() => {
            eprintln!("catos-chroot: no usable block devices found");
            return exit_code::PROBE_FAILED;
        }
        Ok(devices) => devices,
        Err(message) => {
            eprintln!("catos-chroot: {message}");
            return exit_code::PROBE_FAILED;
        }
    };

    let mut root_device = match prompt_select_device("root", &devices, false) {
        Some(device) => device,
        None => {
            eprintln!("catos-chroot: no root partition selected");
            return exit_code::ARG_ERROR;
        }
    };

    let mut opened_luks: Option<OpenedLuks> = None;
    if root_device.is_crypto_luks() {
        let opened = match open_luks(&root_device, authorization) {
            Ok(opened) => opened,
            Err(message) => {
                eprintln!("catos-chroot: {message}");
                return exit_code::PROBE_FAILED;
            }
        };
        let mapper = opened.mapper_path().to_path_buf();
        devices = match list_block_devices() {
            Ok(devices) => devices,
            Err(message) => {
                eprintln!("catos-chroot: {message}");
                return exit_code::PROBE_FAILED;
            }
        };
        root_device = match devices
            .iter()
            .find(|device| device.name == mapper.to_string_lossy())
        {
            Some(device) => device.clone(),
            None => {
                eprintln!(
                    "catos-chroot: unlocked mapper {} was not reported by lsblk",
                    mapper.display()
                );
                return exit_code::PROBE_FAILED;
            }
        };
        opened_luks = Some(opened);
    }

    let selected_subvolume = if root_device.is_btrfs() {
        let subvolumes = match list_subvolumes(&root_device, options.show_btrfs_dot_snapshots) {
            Ok(subvolumes) => subvolumes,
            Err(message) => {
                eprintln!("catos-chroot: {message}");
                return exit_code::PROBE_FAILED;
            }
        };
        match prompt_select_subvolume(&root_device.name, &subvolumes) {
            Some(subvolume) => Some(subvolume),
            None => {
                eprintln!("catos-chroot: no subvolume selected");
                return exit_code::ARG_ERROR;
            }
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
                eprintln!("catos-chroot: {message}");
                return exit_code::PROBE_FAILED;
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
            eprintln!("catos-chroot: {error}");
            return exit_code::ARG_ERROR;
        }
    };
    for warning in &plan.warnings {
        eprintln!("catos-chroot: warning: {warning}");
    }

    let session = match ChrootSessionRoot::create() {
        Ok(session) => session,
        Err(message) => {
            eprintln!("catos-chroot: {message}");
            return exit_code::PROBE_FAILED;
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

fn prompt_select_subvolume(device_name: &str, subvolumes: &[Subvolume]) -> Option<Subvolume> {
    if subvolumes.is_empty() {
        return None;
    }
    println!("\nBtrfs subvolumes on {device_name}:");
    for (index, subvolume) in subvolumes.iter().enumerate() {
        println!("  {index}: {subvolume}");
    }
    let upper = subvolumes.len() - 1;
    loop {
        print!("catos-chroot: pick subvolume [0-{upper}] (default 0): ");
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
        if let Some(subvolume) = subvolumes.get(index) {
            return Some(subvolume.clone());
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
}
