//! Hand-rolled CLI parser. No external CLI framework: the surface is small
//! (three subcommands + a few flags) and a hand-rolled parser keeps the
//! dependency surface minimal, which matters for a static binary intended to
//! run in initramfs.

use crate::error::{exit_code, Error};
use crate::system_root::SystemRoot;
use std::path::{Component, Path, PathBuf};

/// One of the phase-1 or phase-2 commands.
///
/// Phase 1 commands (`environment`, `capabilities`, `inspect`) share a
/// rendering [`View`] over the same underlying inspection report.
///
/// Phase 2 commands are read-only storage discovery and target mount:
///   * `storage scan` — walks sysfs + blkid + mountinfo and emits a
///     [`crate::model::storage::StorageReport`].
///   * `target plan` — reads a target fstab + discovers devices and emits
///     a [`crate::model::mount::MountPlan`] without executing any mount.
///   * `target mount` — same as `target plan` then executes the plan in a
///     private mount namespace, inspects the target, cleans up, and emits
///     the final session/cleanup report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Environment,
    Capabilities,
    Inspect,
    StorageScan,
    TargetPlan,
    TargetMount,
}

impl Command {
    pub fn parse_name(s: &str) -> Option<Command> {
        match s {
            "environment" => Some(Command::Environment),
            "capabilities" => Some(Command::Capabilities),
            "inspect" => Some(Command::Inspect),
            _ => None,
        }
    }

    /// True iff this command emits a phase-1 InspectionReport (vs a
    /// phase-2 StorageReport / MountPlan / MountSession).
    pub fn is_phase1(self) -> bool {
        matches!(
            self,
            Command::Environment | Command::Capabilities | Command::Inspect
        )
    }

    /// The rendering view this command selects. The probe layer always
    /// builds the full report (cheap); the view filters what is emitted.
    /// Panics for phase-2 commands (they do not use View).
    pub fn view(self) -> View {
        match self {
            Command::Environment => View {
                runtime: true,
                capabilities: false,
                target: false,
            },
            Command::Capabilities => View {
                runtime: false,
                capabilities: true,
                target: false,
            },
            Command::Inspect => View {
                runtime: true,
                capabilities: true,
                target: true,
            },
            other => panic!("view() called on phase-2 command {other:?}"),
        }
    }
}

/// Which sections of an [`InspectionReport`] to render. JSON keeps the
/// schemaVersion/programVersion/invocation/targetRoot/warnings keys
/// unconditionally; runtime/capabilities/target are present iff the
/// corresponding flag is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub runtime: bool,
    pub capabilities: bool,
    pub target: bool,
}

/// Parsed CLI invocation.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub command: Command,
    pub root: SystemRoot,
    pub json: bool,
    pub target: TargetSelection,
}

/// Explicit storage choices for a target that is not already mounted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSelection {
    pub root_device: Option<PathBuf>,
    pub root_subvolume: Option<String>,
    pub esp_device: Option<PathBuf>,
}

/// Top-level options that bypass subcommand routing (help/version).
#[derive(Debug, Clone)]
pub enum ParseOutcome {
    Run(CliArgs),
    /// Print this text to stdout and exit 0.
    Help(String),
    /// Print this text to stdout and exit 0.
    Version(String),
}

/// Parse a top-level subcommand, consuming the matching `argv` slots.
/// Handles both single-word phase-1 commands (`environment`, `capabilities`,
/// `inspect`) and two-word phase-2 commands (`storage scan`, `target plan`,
/// `target mount`). Advances `idx` past every consumed token.
///
/// Returns a structured argument error if the leading word is unknown or
/// if a two-word command is missing its required second word.
fn parse_command(first: &str, argv: &[String], idx: &mut usize) -> Result<Command, Error> {
    // Phase-1 single-word commands: consume exactly one token.
    if let Some(c) = Command::parse_name(first) {
        *idx += 1;
        return Ok(c);
    }
    match first {
        "storage" => {
            let sub = argv.get(*idx + 1).ok_or_else(|| Error::InvalidArgument {
                message: "storage requires a subcommand (scan)".to_string(),
            })?;
            if sub != "scan" {
                return Err(Error::InvalidArgument {
                    message: format!("unknown storage subcommand {sub:?}; expected scan"),
                });
            }
            *idx += 2;
            Ok(Command::StorageScan)
        }
        "target" => {
            let sub = argv.get(*idx + 1).ok_or_else(|| Error::InvalidArgument {
                message: "target requires a subcommand (plan|mount)".to_string(),
            })?;
            let cmd = match sub.as_str() {
                "plan" => Command::TargetPlan,
                "mount" => Command::TargetMount,
                other => {
                    return Err(Error::InvalidArgument {
                        message: format!("unknown target subcommand {other:?}; expected plan|mount"),
                    });
                }
            };
            *idx += 2;
            Ok(cmd)
        }
        other => Err(Error::InvalidArgument {
            message: format!(
                "unknown subcommand {other:?}; expected environment|capabilities|inspect|storage scan|target plan|target mount"
            ),
        }),
    }
}

/// Parse `argv[1..]`. argv[0] is handled separately by [`crate::entry`].
///
/// `default_root` is the `SystemRoot` to use when `--root` is not supplied
/// (the caller has already validated that this default exists).
///
/// Flags (`--json`, `--root PATH`, `--root=PATH`) and the subcommand may
/// appear in any order, matching typical Unix tool behaviour.
pub fn parse(argv: &[String], default_root: SystemRoot) -> Result<ParseOutcome, Error> {
    // First pass: scan for top-level help/version flags before any
    // subcommand. These are intentionally allowed to short-circuit even
    // when followed by junk, matching the `--help`-then-anything UX users
    // expect from small Unix tools.
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(ParseOutcome::Help(help_text()));
    }
    if argv.iter().any(|a| a == "--version" || a == "-V") {
        return Ok(ParseOutcome::Version(version_text()));
    }

    let mut command: Option<Command> = None;
    let mut root: Option<SystemRoot> = None;
    let mut json = false;
    let mut target = TargetSelection::default();

    let mut idx = 0;
    while idx < argv.len() {
        let arg = &argv[idx];
        match arg.as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--root" => {
                let val = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--root requires a path argument".to_string(),
                })?;
                root = Some(SystemRoot::from_user_input(val)?);
                idx += 2;
            }
            a if a.starts_with("--root=") => {
                let val = &a["--root=".len()..];
                if val.is_empty() {
                    return Err(Error::InvalidArgument {
                        message: "--root=PATH requires a non-empty path".to_string(),
                    });
                }
                root = Some(SystemRoot::from_user_input(val)?);
                idx += 1;
            }
            "--root-device" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--root-device requires a /dev path".into(),
                })?;
                target.root_device = Some(parse_device_path(value, "--root-device")?);
                idx += 2;
            }
            a if a.starts_with("--root-device=") => {
                target.root_device = Some(parse_device_path(
                    &a["--root-device=".len()..],
                    "--root-device",
                )?);
                idx += 1;
            }
            "--root-subvolume" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--root-subvolume requires a subvolume path".into(),
                })?;
                target.root_subvolume = Some(parse_subvolume(value)?);
                idx += 2;
            }
            a if a.starts_with("--root-subvolume=") => {
                target.root_subvolume = Some(parse_subvolume(&a["--root-subvolume=".len()..])?);
                idx += 1;
            }
            "--esp-device" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--esp-device requires a /dev path".into(),
                })?;
                target.esp_device = Some(parse_device_path(value, "--esp-device")?);
                idx += 2;
            }
            a if a.starts_with("--esp-device=") => {
                target.esp_device = Some(parse_device_path(
                    &a["--esp-device=".len()..],
                    "--esp-device",
                )?);
                idx += 1;
            }
            // First positional (no leading dash) becomes the subcommand.
            positional if !positional.starts_with('-') && command.is_none() => {
                command = Some(parse_command(positional, argv, &mut idx)?);
            }
            // A second positional after we already have the subcommand is an
            // error (no phase-1 subcommand takes a positional argument).
            extra_positional if !extra_positional.starts_with('-') => {
                return Err(Error::InvalidArgument {
                    message: format!(
                        "unexpected positional argument {extra_positional:?} (subcommand already given)"
                    ),
                });
            }
            other => {
                return Err(Error::InvalidArgument {
                    message: format!("unexpected argument {other:?}"),
                });
            }
        }
    }

    let command = command.ok_or_else(|| Error::InvalidArgument {
        message: "no subcommand supplied. Try --help.".to_string(),
    })?;
    if target.root_subvolume.is_some() && target.root_device.is_none() {
        return Err(Error::InvalidArgument {
            message: "--root-subvolume requires --root-device".into(),
        });
    }
    if target != TargetSelection::default()
        && !matches!(command, Command::TargetPlan | Command::TargetMount)
    {
        return Err(Error::InvalidArgument {
            message: "explicit device options are valid only for target plan or target mount"
                .into(),
        });
    }

    Ok(ParseOutcome::Run(CliArgs {
        command,
        root: root.unwrap_or(default_root),
        json,
        target,
    }))
}

fn parse_device_path(value: &str, option: &str) -> Result<PathBuf, Error> {
    let path = Path::new(value);
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal("dev".as_ref()))
    {
        return Err(Error::InvalidArgument {
            message: format!("{option} must be an absolute path below /dev"),
        });
    }
    if value.contains('\0')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(Error::InvalidArgument {
            message: format!("{option} contains an unsafe path component"),
        });
    }
    Ok(path.to_path_buf())
}

fn parse_subvolume(value: &str) -> Result<String, Error> {
    if value.is_empty() || value.contains([',', '\0']) {
        return Err(Error::InvalidArgument {
            message: "--root-subvolume must be a non-empty path without commas or NUL".into(),
        });
    }
    let normalized = if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    };
    if Path::new(&normalized)
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(Error::InvalidArgument {
            message: "--root-subvolume cannot contain parent components".into(),
        });
    }
    Ok(normalized)
}

pub fn help_text() -> String {
    format!(
        "\
catos-system {version} - CatOS read-only system backend (phase 1 + phase 2)

USAGE:
    catos-system <SUBCOMMAND> [OPTIONS]

PHASE-1 SUBCOMMANDS (read-only environment + target inspection):
    environment   Print detected runtime environment facts.
    capabilities  Print detected capabilities (read-only).
    inspect       Print combined runtime + capabilities + target inspection.

PHASE-2 SUBCOMMANDS (read-only storage discovery + safe RO target mount):
    storage scan  Walk sysfs + blkid + mountinfo; emit a StorageReport.
                  Pure read. No mounts, no writes.
    target plan   Read --root's /etc/fstab + discover devices; emit a
                  MountPlan WITHOUT executing any mount.
    target mount  Same as 'target plan' then execute the plan in a private
                  mount namespace (read-only mounts only).

OPTIONS:
    --root PATH   Inspect a different target root (default: /).
                  PATH must be an absolute path to an existing directory.
    --root-device /dev/...
                  Explicit root block device for an unmounted target.
    --root-subvolume PATH
                  Explicit Btrfs root subvolume (requires --root-device).
    --esp-device /dev/...
                  Override the EFI System Partition for the target plan.
    --json        Emit a stable JSON report on stdout instead of human text.
    -h, --help    Show this help message and exit.
    -V, --version Print program version and exit.

EXIT CODES:
    {ok}   success
    {arg}   argument error
    {root} target root invalid (does not exist, not a directory, etc.)
    {perm} permission denied reading a critical path
    {probe} environment probe could not produce a report
    {ser}  JSON serialisation failed

NOTES:
    * This is a read-only tool. It never writes to the target root.
    * 'target mount' enters a private mount namespace (CLONE_NEWNS) and
      flips / to MS_REC|MS_PRIVATE so its mounts do NOT propagate to the
      host. Pre-existing mounts are never unmounted.
    * Phase 2 mounts are read-only with filesystem-specific safety options
      (ext4 noload, xfs norecovery, btrfs rescue=nologreplay, etc.) so journal replay
      and superblock updates are suppressed.
    * argv[0] is honoured only for the JSON 'invocation' field and for help
      text. The three symlinks catos-update / catos-recovery / catos-doctor
      all accept the same subcommands and produce identical probe results.
",
        version = crate::PROGRAM_VERSION,
        ok = exit_code::SUCCESS,
        arg = exit_code::ARG_ERROR,
        root = exit_code::INVALID_ROOT,
        perm = exit_code::PERMISSION_DENIED,
        probe = exit_code::PROBE_FAILED,
        ser = exit_code::SERIALIZE_FAILED,
    )
}

pub fn version_text() -> String {
    format!("catos-system {}\n", crate::PROGRAM_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_root() -> SystemRoot {
        SystemRoot::from_absolute_unchecked("/").unwrap()
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_inspect_default() {
        let r = parse(&args(&["inspect"]), default_root()).unwrap();
        match r {
            ParseOutcome::Run(c) => {
                assert_eq!(c.command, Command::Inspect);
                assert!(!c.json);
                assert_eq!(c.root.as_str(), "/");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parses_json_flag_in_any_position() {
        let r = parse(&args(&["inspect", "--json"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert!(c.json);
        } else {
            panic!();
        }
        let r = parse(&args(&["--json", "inspect"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert!(c.json);
        } else {
            panic!();
        }
    }

    #[test]
    fn rejects_unknown_subcommand_with_arg_error() {
        let err = parse(&args(&["frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_unknown_flag_with_arg_error() {
        let err = parse(&args(&["inspect", "--frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_root_without_value() {
        let err = parse(&args(&["inspect", "--root"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_relative_root_with_invalid_root_code() {
        let err = parse(&args(&["inspect", "--root", "mnt"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::INVALID_ROOT);
    }

    #[test]
    fn rejects_nonexistent_root_with_invalid_root_code() {
        let err = parse(
            &args(&["inspect", "--root", "/definitely/not/here/12345"]),
            default_root(),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), exit_code::INVALID_ROOT);
    }

    #[test]
    fn help_short_circuits() {
        let r = parse(&args(&["--help"]), default_root()).unwrap();
        assert!(matches!(r, ParseOutcome::Help(_)));
    }

    #[test]
    fn version_short_circuits() {
        let r = parse(&args(&["inspect", "--version"]), default_root()).unwrap();
        assert!(matches!(r, ParseOutcome::Version(_)));
    }

    #[test]
    fn empty_args_is_arg_error() {
        let err = parse(&[], default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn root_equals_form_is_accepted() {
        // Use existing directory for this case.
        let r = parse(&args(&["inspect", "--root=/"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.root.as_str(), "/");
        } else {
            panic!();
        }
    }

    #[test]
    fn parses_storage_scan_two_word_subcommand() {
        let r = parse(&args(&["storage", "scan"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.command, Command::StorageScan);
        } else {
            panic!("expected Run");
        }
    }

    #[test]
    fn parses_target_plan_two_word_subcommand() {
        let r = parse(&args(&["target", "plan"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.command, Command::TargetPlan);
        } else {
            panic!("expected Run");
        }
    }

    #[test]
    fn parses_explicit_target_devices() {
        let r = parse(
            &args(&[
                "target",
                "plan",
                "--root-device",
                "/dev/nvme0n1p2",
                "--root-subvolume",
                "@",
                "--esp-device=/dev/nvme0n1p1",
            ]),
            default_root(),
        )
        .unwrap();
        let ParseOutcome::Run(args) = r else {
            panic!("expected run");
        };
        assert_eq!(
            args.target.root_device.as_deref(),
            Some(Path::new("/dev/nvme0n1p2"))
        );
        assert_eq!(args.target.root_subvolume.as_deref(), Some("/@"));
        assert_eq!(
            args.target.esp_device.as_deref(),
            Some(Path::new("/dev/nvme0n1p1"))
        );
    }

    #[test]
    fn explicit_device_options_are_rejected_for_storage_scan() {
        let error = parse(
            &args(&["storage", "scan", "--root-device", "/dev/sda2"]),
            default_root(),
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn subvolume_requires_root_device_and_rejects_escape() {
        let missing_device = parse(
            &args(&["target", "plan", "--root-subvolume", "@"]),
            default_root(),
        )
        .unwrap_err();
        assert_eq!(missing_device.exit_code(), exit_code::ARG_ERROR);

        let escape = parse(
            &args(&[
                "target",
                "plan",
                "--root-device",
                "/dev/sda2",
                "--root-subvolume",
                "../host",
            ]),
            default_root(),
        )
        .unwrap_err();
        assert_eq!(escape.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn parses_target_mount_two_word_subcommand() {
        let r = parse(&args(&["target", "mount"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.command, Command::TargetMount);
        } else {
            panic!("expected Run");
        }
    }

    #[test]
    fn rejects_storage_without_subcommand() {
        let err = parse(&args(&["storage"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_target_without_subcommand() {
        let err = parse(&args(&["target"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_storage_with_invalid_subcommand() {
        let err = parse(&args(&["storage", "frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn rejects_target_with_invalid_subcommand() {
        let err = parse(&args(&["target", "frobnicate"]), default_root()).unwrap_err();
        assert_eq!(err.exit_code(), exit_code::ARG_ERROR);
    }

    #[test]
    fn storage_scan_accepts_flags_after_subcommand() {
        let r = parse(&args(&["storage", "scan", "--json"]), default_root()).unwrap();
        if let ParseOutcome::Run(c) = r {
            assert_eq!(c.command, Command::StorageScan);
            assert!(c.json);
        } else {
            panic!("expected Run");
        }
    }

    #[test]
    fn is_phase1_classification_is_correct() {
        assert!(Command::Environment.is_phase1());
        assert!(Command::Capabilities.is_phase1());
        assert!(Command::Inspect.is_phase1());
        assert!(!Command::StorageScan.is_phase1());
        assert!(!Command::TargetPlan.is_phase1());
        assert!(!Command::TargetMount.is_phase1());
    }
}
