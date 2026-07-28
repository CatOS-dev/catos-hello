//! `catos-chroot` CLI application orchestration.

use std::io::{self, BufRead, IsTerminal, Write};

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
    no_auto_mount: bool,
    no_systemd_chroot: bool,
    show_btrfs_dot_snapshots: bool,
}

pub fn run(argv: &[String], program: &str) -> i32 {
    let options = match parse_argv(argv) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{program}: {message}");
            return exit_code::ARG_ERROR;
        }
    };

    if let Some(exit) = super::elevation::require_root_or_reexec("chroot", argv, program) {
        return exit;
    }
    let evidence = ChrootPrivilegeEvidence::EffectiveUid(super::elevation::effective_uid());
    let authorization = match authorize(evidence) {
        Ok(authorization) => authorization,
        Err(message) => {
            eprintln!("{program}: {message}");
            return exit_code::PERMISSION_DENIED;
        }
    };

    if let Err(message) = establish_private_namespace() {
        eprintln!("{program}: cannot establish private mount namespace: {message}");
        return exit_code::PROBE_FAILED;
    }

    let discovery = crate::target::discovery::discover_targets_with_options(
        crate::target::discovery::DiscoveryOptions {
            include_dot_snapshots: options.show_btrfs_dot_snapshots,
        },
    );
    if let Err(error) = validate_discovery_cleanup(&discovery) {
        eprintln!("{program}: {error}");
        return exit_code::PROBE_FAILED;
    }
    let (mut devices, inventory_warnings) = target_inventory_for_chroot(&discovery.inventory);
    for warning in inventory_warnings {
        eprintln!("{program}: warning: {warning}");
    }
    if devices.is_empty() {
        eprintln!("{program}: no usable block devices found");
        return exit_code::PROBE_FAILED;
    }

    let mut opened_luks: Option<OpenedLuks> = None;
    let selected_target = match crate::selection_ui::select_target_with_policy(
        &discovery,
        program,
        crate::selection_ui::TargetSelectionPolicy::OfflineOnly,
    ) {
        crate::selection_ui::Selection::Selected(candidate) => *candidate,
        crate::selection_ui::Selection::Declined => return exit_code::SUCCESS,
        crate::selection_ui::Selection::Unavailable(reason) if discovery.candidates.is_empty() => {
            let encrypted =
                match crate::selection_ui::select_luks_device(&discovery.inventory, program) {
                    Ok(crate::selection_ui::LuksSelection::Selected(device)) => *device,
                    Ok(crate::selection_ui::LuksSelection::Declined) => {
                        return exit_code::SUCCESS;
                    }
                    Ok(crate::selection_ui::LuksSelection::Unavailable) => {
                        eprintln!("{program}: {reason}");
                        return exit_code::PROBE_FAILED;
                    }
                    Err(error) => {
                        eprintln!("{program}: {error}");
                        return exit_code::PROBE_FAILED;
                    }
                };
            let Some(luks_device) = target_block_to_chroot(&encrypted) else {
                eprintln!("{program}: encrypted inventory device has no path");
                return exit_code::PROBE_FAILED;
            };
            let opened = match open_luks(&luks_device, authorization) {
                Ok(opened) => opened,
                Err(error) => {
                    eprintln!("{program}: {error}");
                    return exit_code::PROBE_FAILED;
                }
            };
            let mut opened = Some(opened);
            match resolve_after_luks(
                || {
                    crate::target::discovery::discover_targets_with_options(
                        crate::target::discovery::DiscoveryOptions {
                            include_dot_snapshots: options.show_btrfs_dot_snapshots,
                        },
                    )
                },
                |report| {
                    crate::selection_ui::select_target_with_policy(
                        report,
                        program,
                        crate::selection_ui::TargetSelectionPolicy::OfflineOnly,
                    )
                },
                || opened.take().expect("opened LUKS token").close(),
            ) {
                Ok(Some(resolved)) => {
                    for warning in resolved.warnings {
                        eprintln!("{program}: warning: {warning}");
                    }
                    devices = resolved.inventory;
                    opened_luks = opened;
                    resolved.candidate
                }
                Ok(None) => return exit_code::SUCCESS,
                Err(error) => {
                    eprintln!("{program}: {error}");
                    return exit_code::PROBE_FAILED;
                }
            }
        }
        crate::selection_ui::Selection::Unavailable(reason) => {
            eprintln!("{program}: {reason}");
            return exit_code::PROBE_FAILED;
        }
    };
    let root_device = match find_selected_device(&devices, &selected_target.root_device) {
        Some(device) => device.clone(),
        None => {
            return fail_with_luks_cleanup(
                program,
                opened_luks.take(),
                exit_code::PROBE_FAILED,
                format!(
                    "selected device {} disappeared from fresh shared inventory",
                    selected_target.root_device.display()
                ),
            );
        }
    };

    let selected_subvolume = if root_device.is_btrfs() {
        match (
            selected_target.root_subvolume.as_deref(),
            selected_target.root_subvolume_id,
        ) {
            (Some(path), Some(id)) => Some(Subvolume {
                id,
                name: path.trim_start_matches('/').to_string(),
            }),
            _ => {
                return fail_with_luks_cleanup(
                    program,
                    opened_luks.take(),
                    exit_code::PROBE_FAILED,
                    "selected Btrfs target has incomplete shared subvolume identity".into(),
                )
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
                return fail_with_luks_cleanup(
                    program,
                    opened_luks.take(),
                    exit_code::PROBE_FAILED,
                    message,
                );
            }
        }
    };

    let extra_mounts = match prompt_extra_mounts(program, &devices) {
        Ok(selections) => selections,
        Err(error) => {
            return fail_with_luks_cleanup(
                program,
                opened_luks.take(),
                exit_code::PROBE_FAILED,
                error,
            )
        }
    };
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
            return fail_with_luks_cleanup(
                program,
                opened_luks.take(),
                exit_code::ARG_ERROR,
                error.to_string(),
            );
        }
    };
    for warning in &plan.warnings {
        eprintln!("{program}: warning: {warning}");
    }

    let session = match ChrootSessionRoot::create() {
        Ok(session) => session,
        Err(message) => {
            return fail_with_luks_cleanup(
                program,
                opened_luks.take(),
                exit_code::PROBE_FAILED,
                message,
            );
        }
    };
    let mut effects = SystemChrootEffects;
    let report = execute_plan(&plan, authorization, session.path(), &mut effects);
    let session_cleanup = session.cleanup();
    let luks_cleanup = opened_luks.take().map(OpenedLuks::close).transpose();

    if let Some(failure) = &report.failure {
        eprintln!("{program}: {failure}");
    }
    if let Err(error) = &session_cleanup {
        eprintln!("{program}: session cleanup failed: {error}");
    }
    if let Err(error) = &luks_cleanup {
        eprintln!("{program}: LUKS cleanup failed: {error}");
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

fn fail_with_luks_cleanup(
    program: &str,
    opened_luks: Option<OpenedLuks>,
    code: i32,
    message: String,
) -> i32 {
    eprintln!("{program}: {message}");
    if let Some(opened) = opened_luks {
        if let Err(error) = opened.close() {
            eprintln!("{program}: LUKS cleanup failed: {error}");
            return exit_code::PROBE_FAILED;
        }
    }
    code
}

fn target_inventory_for_chroot(
    inventory: &[crate::target::model::BlockDevice],
) -> (Vec<BlockDevice>, Vec<String>) {
    let mut devices = Vec::new();
    let mut warnings = Vec::new();
    for device in inventory {
        let Some(path) = device.dev_path.as_ref() else {
            warnings.push(format!(
                "inventory entry {} has no stable device path and cannot be mounted",
                device.name
            ));
            continue;
        };
        devices.push(BlockDevice {
            name: path.display().to_string(),
            fs_type: device.filesystem.clone(),
            uuid: device.uuid.clone(),
            partuuid: device.part_uuid.clone(),
            label: device.label.clone(),
            partlabel: device.part_label.clone(),
        });
    }
    (devices, warnings)
}

fn validate_discovery_cleanup(
    report: &crate::target::discovery::DiscoveryReport,
) -> Result<(), String> {
    let residual = report
        .cleanup
        .iter()
        .filter(|cleanup| !cleanup.is_clean())
        .map(|cleanup| {
            format!(
                "{}: {}",
                cleanup.mountpoint.display(),
                cleanup
                    .error
                    .as_deref()
                    .unwrap_or("probe mountpoint was not fully removed")
            )
        })
        .collect::<Vec<_>>();
    if residual.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "readonly target discovery cleanup incomplete: {}",
            residual.join("; ")
        ))
    }
}

fn target_block_to_chroot(device: &crate::target::model::BlockDevice) -> Option<BlockDevice> {
    Some(BlockDevice {
        name: device.dev_path.as_ref()?.display().to_string(),
        fs_type: device.filesystem.clone(),
        uuid: device.uuid.clone(),
        partuuid: device.part_uuid.clone(),
        label: device.label.clone(),
        partlabel: device.part_label.clone(),
    })
}

fn find_selected_device(
    devices: &[BlockDevice],
    selected: &std::path::Path,
) -> Option<BlockDevice> {
    devices
        .iter()
        .find(|device| std::path::Path::new(&device.name) == selected)
        .cloned()
}

#[derive(Debug)]
struct ResolvedLuksTarget {
    candidate: crate::target::discovery::TargetCandidate,
    inventory: Vec<BlockDevice>,
    warnings: Vec<String>,
}

fn resolve_after_luks<D, S, C>(
    discover: D,
    select: S,
    close: C,
) -> Result<Option<ResolvedLuksTarget>, String>
where
    D: FnOnce() -> crate::target::discovery::DiscoveryReport,
    S: FnOnce(&crate::target::discovery::DiscoveryReport) -> crate::selection_ui::Selection,
    C: FnOnce() -> Result<(), String>,
{
    let report = discover();
    if let Err(error) = validate_discovery_cleanup(&report) {
        return close_after_luks_failure(close, &error);
    }
    let candidate = match select(&report) {
        crate::selection_ui::Selection::Selected(candidate) => *candidate,
        crate::selection_ui::Selection::Declined => {
            close().map_err(|error| format!("LUKS cleanup failed: {error}"))?;
            return Ok(None);
        }
        crate::selection_ui::Selection::Unavailable(reason) => {
            return close_after_luks_failure(
                close,
                &format!("unlocked mapper did not yield a CatOS candidate: {reason}"),
            )
        }
    };
    let (fresh, warnings) = target_inventory_for_chroot(&report.inventory);
    if find_selected_device(&fresh, &candidate.root_device).is_none() {
        return close_after_luks_failure(
            close,
            "selected mapper is absent from fresh shared inventory",
        );
    }
    Ok(Some(ResolvedLuksTarget {
        candidate,
        inventory: fresh,
        warnings,
    }))
}

fn close_after_luks_failure<T, C>(close: C, reason: &str) -> Result<T, String>
where
    C: FnOnce() -> Result<(), String>,
{
    match close() {
        Ok(()) => Err(reason.into()),
        Err(error) => Err(format!("{reason}; LUKS cleanup failed: {error}")),
    }
}

pub fn help_text(program: &str) -> String {
    let version = crate::PROGRAM_VERSION;
    format!(
        r#"{program} {version} - open an installed CatOS system for maintenance

USAGE:
    {program} [OPTIONS]

The command finds installed CatOS systems, lets you choose one, unlocks an
encrypted target when needed, mounts its configured filesystems, and opens
an interactive shell. Everything mounted or unlocked by this command is
cleaned up when the shell exits.

OPTIONS:
    --no-auto-mount            Mount only the selected root filesystem.
    --no-systemd-chroot        Use the offline arch-chroot mode.
    --show-btrfs-dot-snapshots Include historical .snapshots entries.
    -h, --help                 Show this help message.
    -V, --version              Print the program version.

Administrator privileges are requested automatically when an elevation tool
is available.
"#
    )
}

fn parse_argv(argv: &[String]) -> Result<ChrootOptions, String> {
    let mut options = ChrootOptions::default();
    for argument in argv {
        match argument.as_str() {
            "--no-auto-mount" => options.no_auto_mount = true,
            "--no-systemd-chroot" => options.no_systemd_chroot = true,
            "--show-btrfs-dot-snapshots" => options.show_btrfs_dot_snapshots = true,
            other => {
                return Err(format!(
                    "unknown option {other:?}; expected --no-auto-mount, --no-systemd-chroot, --show-btrfs-dot-snapshots"
                ))
            }
        }
    }
    Ok(options)
}

fn prompt_extra_mounts(
    program: &str,
    devices: &[BlockDevice],
) -> Result<Vec<ExtraMountSelection>, String> {
    if !std::io::stdin().is_terminal() {
        return Ok(Vec::new());
    }
    let mut selections = Vec::new();
    while prompt_yes_no(program, "Mount an additional partition?", false)? {
        let Some(mount_point) = prompt_mount_point(program)? else {
            continue;
        };
        let Some(device) = prompt_select_device(program, &mount_point, devices, true)? else {
            continue;
        };
        selections.push(ExtraMountSelection {
            device,
            mount_point,
        });
    }
    Ok(selections)
}

fn prompt_select_device(
    program: &str,
    role: &str,
    devices: &[BlockDevice],
    allow_skip: bool,
) -> Result<Option<BlockDevice>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    prompt_select_device_with(
        &mut input,
        &mut output,
        program,
        role,
        devices,
        allow_skip,
    )
}

fn prompt_select_device_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    program: &str,
    role: &str,
    devices: &[BlockDevice],
    allow_skip: bool,
) -> Result<Option<BlockDevice>, String> {
    if devices.is_empty() {
        writeln!(output, "{program}: no devices available to pick {role} from")
            .map_err(prompt_output_error)?;
        return Ok(None);
    }
    writeln!(output, "\nAvailable devices for {role}:").map_err(prompt_output_error)?;
    for (index, device) in devices.iter().enumerate() {
        writeln!(output, "  [{}] {device}", index + 1).map_err(prompt_output_error)?;
    }
    writeln!(output, "  [0] {}", if allow_skip { "Skip" } else { "Back" })
        .map_err(prompt_output_error)?;
    let upper = devices.len();
    loop {
        write!(
            output,
            "{program}: pick device [0-{upper}]{}: ",
            if allow_skip { " (blank to skip)" } else { "" }
        )
        .map_err(prompt_output_error)?;
        output.flush().map_err(prompt_output_error)?;
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(prompt_input_error)?;
        if read == 0 {
            writeln!(output).map_err(prompt_output_error)?;
            return Ok(None);
        }
        if line.trim().is_empty() && allow_skip {
            return Ok(None);
        }
        let Ok(index) = line.trim().parse::<usize>() else {
            writeln!(output, "{program}: enter a number from 0 to {upper}")
                .map_err(prompt_output_error)?;
            continue;
        };
        if index == 0 {
            return Ok(None);
        }
        if let Some(device) = devices.get(index - 1) {
            return Ok(Some(device.clone()));
        }
        writeln!(output, "{program}: enter a number from 0 to {upper}")
            .map_err(prompt_output_error)?;
    }
}

fn prompt_mount_point(program: &str) -> Result<Option<String>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    prompt_mount_point_with(&mut input, &mut output, program)
}

fn prompt_mount_point_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    program: &str,
) -> Result<Option<String>, String> {
    loop {
        write!(
            output,
            "{program}: mount point (for example /boot; blank to cancel): "
        )
        .map_err(prompt_output_error)?;
        output.flush().map_err(prompt_output_error)?;
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(prompt_input_error)?;
        if read == 0 {
            writeln!(output).map_err(prompt_output_error)?;
            return Ok(None);
        }
        let value = line.trim().to_string();
        if value.is_empty() || value.eq_ignore_ascii_case("skip") {
            return Ok(None);
        }
        if value.starts_with('/') {
            return Ok(Some(value));
        }
        writeln!(output, "{program}: mount point must start with /")
            .map_err(prompt_output_error)?;
    }
}

fn prompt_yes_no(program: &str, prompt: &str, default: bool) -> Result<bool, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    prompt_yes_no_with(&mut input, &mut output, program, prompt, default)
}

fn prompt_yes_no_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    program: &str,
    prompt: &str,
    default: bool,
) -> Result<bool, String> {
    loop {
        let choices = if default { "Y/n" } else { "y/N" };
        write!(output, "{program}: {prompt} [{choices}] ").map_err(prompt_output_error)?;
        output.flush().map_err(prompt_output_error)?;
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(prompt_input_error)?;
        if read == 0 {
            writeln!(output).map_err(prompt_output_error)?;
            return Ok(false);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "{program}: enter y or n").map_err(prompt_output_error)?,
        }
    }
}

fn prompt_output_error(error: io::Error) -> String {
    format!("interactive output failed: {error}")
}

fn prompt_input_error(error: io::Error) -> String {
    format!("interactive input failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_flags() {
        let options = parse_argv(&[
            "--no-auto-mount".into(),
            "--no-systemd-chroot".into(),
            "--show-btrfs-dot-snapshots".into(),
        ])
        .unwrap();
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
        let old = BlockDevice {
            name: "/dev/sda2".into(),
            fs_type: Some("crypto_LUKS".into()),
            uuid: Some("luks".into()),
            partuuid: None,
            label: None,
            partlabel: None,
        };
        let fresh = BlockDevice {
            name: "/dev/mapper/luks-luks".into(),
            fs_type: Some("btrfs".into()),
            uuid: Some("root".into()),
            partuuid: None,
            label: None,
            partlabel: None,
        };
        assert!(
            find_selected_device(&[old], std::path::Path::new("/dev/mapper/luks-luks")).is_none()
        );
        assert_eq!(
            find_selected_device(
                std::slice::from_ref(&fresh),
                std::path::Path::new("/dev/mapper/luks-luks")
            )
            .unwrap(),
            fresh
        );
    }

    fn inventory_device(
        name: &str,
        path: Option<&str>,
        filesystem: Option<&str>,
    ) -> crate::target::model::BlockDevice {
        crate::target::model::BlockDevice {
            name: name.into(),
            dev_path: path.map(Into::into),
            major_minor: None,
            parent: String::new(),
            class: crate::target::model::DeviceClass::Partition,
            disk_kind: crate::target::model::DiskKind::Unknown,
            partition_role: crate::target::model::PartitionRole::LinuxFilesystem,
            partition_number: None,
            size_sectors: None,
            read_only: false,
            removable: false,
            filesystem: filesystem.map(str::to_string),
            uuid: None,
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: None,
            mounts: Vec::new(),
            mounted_before_session: false,
            evidence: Vec::new(),
        }
    }

    fn mapper_candidate() -> crate::target::discovery::TargetCandidate {
        crate::target::discovery::TargetCandidate {
            root_device: "/dev/mapper/luks-id".into(),
            root_fstype: "ext4".into(),
            root_uuid: Some("root".into()),
            root_subvolume: None,
            root_subvolume_id: None,
            filesystem_id: None,
            label: None,
            os_release: Default::default(),
            fstab_identity: None,
            currently_mounted: false,
            running_environment_member: false,
            confidence: crate::target::model::RootCandidateConfidence::High,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn luks_resolution_consumes_rediscovered_mapper_inventory() {
        let candidate = mapper_candidate();
        let result = resolve_after_luks(
            || crate::target::discovery::DiscoveryReport {
                inventory: vec![{
                    let mut device =
                        inventory_device("dm-0", Some("/dev/mapper/luks-id"), Some("ext4"));
                    device.uuid = Some("root".into());
                    device
                }],
                candidates: vec![candidate.clone()],
                excluded: Vec::new(),
                rejected: Vec::new(),
                cleanup: Vec::new(),
            },
            |report| {
                crate::selection_ui::Selection::Selected(Box::new(report.candidates[0].clone()))
            },
            || panic!("successful rediscovery must not close mapper"),
        )
        .unwrap()
        .expect("selected mapper must be returned");
        assert_eq!(
            result.candidate.root_device,
            std::path::PathBuf::from("/dev/mapper/luks-id")
        );
        assert_eq!(result.inventory.len(), 1);
    }

    #[test]
    fn declining_after_luks_unlock_closes_mapper_and_is_not_an_error() {
        let closed = std::cell::Cell::new(false);
        let result = resolve_after_luks(
            crate::target::discovery::DiscoveryReport::default,
            |_| crate::selection_ui::Selection::Declined,
            || {
                closed.set(true);
                Ok(())
            },
        )
        .expect("operator cancellation is not a failure");
        assert!(result.is_none());
        assert!(closed.get(), "unlocked mapper must be closed on cancellation");
    }

    #[test]
    fn declining_after_luks_unlock_still_reports_cleanup_failure() {
        let error = resolve_after_luks(
            crate::target::discovery::DiscoveryReport::default,
            |_| crate::selection_ui::Selection::Declined,
            || Err("close failed".into()),
        )
        .expect_err("cleanup failure must not be reported as a clean cancellation");
        assert!(error.contains("LUKS cleanup failed: close failed"));
    }

    #[test]
    fn luks_resolution_closes_and_reports_close_failure_after_rediscovery_error() {
        let error = resolve_after_luks(
            crate::target::discovery::DiscoveryReport::default,
            |_| crate::selection_ui::Selection::Unavailable("no mapper candidate".into()),
            || Err("close failed".into()),
        )
        .unwrap_err();
        assert!(error.contains("no mapper candidate"));
        assert!(error.contains("LUKS cleanup failed: close failed"));
    }

    #[test]
    fn dirty_discovery_cleanup_is_rejected_before_selection() {
        let report = crate::target::discovery::DiscoveryReport {
            cleanup: vec![crate::target::discovery::ProbeCleanup {
                mountpoint: "/tmp/probe".into(),
                unmounted: false,
                removed: false,
                error: Some("busy".into()),
            }],
            ..Default::default()
        };
        let error = validate_discovery_cleanup(&report).unwrap_err();
        assert!(error.contains("cleanup incomplete"));
        assert!(error.contains("/tmp/probe: busy"));
    }

    #[test]
    fn pathless_inventory_entries_are_reported_not_silently_dropped() {
        let inventory = vec![inventory_device("mystery0", None, None)];
        let (devices, warnings) = target_inventory_for_chroot(&inventory);
        assert!(devices.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("mystery0"));
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

    struct FailingReader;

    impl io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("input failed"))
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("input failed"))
        }

        fn consume(&mut self, _amount: usize) {}
    }

    #[test]
    fn prompt_io_failures_are_not_reported_as_user_cancellation() {
        let devices = vec![BlockDevice {
            name: "/dev/sda1".into(),
            fs_type: Some("ext4".into()),
            uuid: None,
            partuuid: None,
            label: None,
            partlabel: None,
        }];
        let mut input = io::Cursor::new(b"1\n".to_vec());
        assert!(prompt_select_device_with(
            &mut input,
            &mut FailingWriter,
            "catos-chroot",
            "/boot",
            &devices,
            true,
        )
        .is_err());

        let mut output = Vec::new();
        assert!(prompt_mount_point_with(&mut FailingReader, &mut output, "catos-chroot").is_err());
        assert!(prompt_yes_no_with(
            &mut FailingReader,
            &mut output,
            "catos-chroot",
            "Mount an additional partition?",
            false,
        )
        .is_err());
    }

    #[test]
    fn extra_mount_device_picker_is_one_based_and_blank_skips() {
        let devices = vec![BlockDevice {
            name: "/dev/sda1".into(),
            fs_type: Some("ext4".into()),
            uuid: None,
            partuuid: None,
            label: None,
            partlabel: None,
        }];
        let mut selected = io::Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_select_device_with(
                &mut selected,
                &mut output,
                "catos-chroot",
                "/boot",
                &devices,
                true,
            )
            .unwrap(),
            Some(devices[0].clone())
        );
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("[1] /dev/sda1"));
        assert!(rendered.contains("[0] Skip"));

        let mut blank = io::Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        assert!(prompt_select_device_with(
            &mut blank,
            &mut output,
            "catos-chroot",
            "/boot",
            &devices,
            true,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn mount_point_and_yes_no_prompts_reprompt_invalid_input() {
        let mut mount_input = io::Cursor::new(b"boot\n/boot\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_mount_point_with(&mut mount_input, &mut output, "catos-chroot").unwrap(),
            Some("/boot".into())
        );
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("mount point must start with /"));

        let mut confirm_input = io::Cursor::new(b"maybe\nyes\n".to_vec());
        let mut output = Vec::new();
        assert!(
            prompt_yes_no_with(
                &mut confirm_input,
                &mut output,
                "catos-chroot",
                "Mount an additional partition?",
                false,
            )
            .unwrap()
        );
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("enter y or n"));
    }
}
