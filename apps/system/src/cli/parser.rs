use super::help::{help_text, version_text};
use super::types::*;
use crate::error::Error;
use crate::target::diagnose::system_root::SystemRoot;
use std::path::{Component, Path, PathBuf};

/// Parse a top-level subcommand, consuming the matching `argv` slots.
/// Handles single-word inspection commands (`environment`, `capabilities`,
/// `inspect`) and two-word storage commands (`storage scan`, `target plan`,
/// `target mount`). Advances `idx` past every consumed token.
///
/// Returns a structured argument error if the leading word is unknown or
/// if a two-word command is missing its required second word.
fn parse_command(first: &str, argv: &[String], idx: &mut usize) -> Result<Command, Error> {
    // Single-word inspection commands consume exactly one token.
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
        "recovery" => {
            let sub = argv.get(*idx + 1).ok_or_else(|| Error::InvalidArgument {
                message: "recovery requires a subcommand (list|inspect|plan|apply|status|resume|revert)"
                    .to_string(),
            })?;
            let recovery_sub = RecoverySubcommand::parse_name(sub.as_str()).ok_or_else(|| {
                Error::InvalidArgument {
                    message: format!(
                        "unknown recovery subcommand {sub:?}; expected list|inspect|plan|apply|status|resume|revert"
                    ),
                }
            })?;
            *idx += 2;
            Ok(Command::Recovery(recovery_sub))
        }
        other => Err(Error::InvalidArgument {
            message: format!(
                "unknown subcommand {other:?}; expected environment|capabilities|inspect|storage scan|target plan|target mount|recovery <sub>"
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
    let mut recovery_args = RecoveryArgs::default();

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
                root = Some(SystemRoot::from_user_input(val).map_err(root_error)?);
                idx += 2;
            }
            a if a.starts_with("--root=") => {
                let val = &a["--root=".len()..];
                if val.is_empty() {
                    return Err(Error::InvalidArgument {
                        message: "--root=PATH requires a non-empty path".to_string(),
                    });
                }
                root = Some(SystemRoot::from_user_input(val).map_err(root_error)?);
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
            "--snapshot-subvolume" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--snapshot-subvolume requires a subvolume path".into(),
                })?;
                recovery_args.snapshot_subvolume = Some(parse_subvolume(value)?);
                idx += 2;
            }
            a if a.starts_with("--snapshot-subvolume=") => {
                recovery_args.snapshot_subvolume =
                    Some(parse_subvolume(&a["--snapshot-subvolume=".len()..])?);
                idx += 1;
            }
            "--plan-id" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--plan-id requires a plan id".into(),
                })?;
                recovery_args.plan_id = Some(parse_opaque_id(value, "--plan-id")?);
                idx += 2;
            }
            a if a.starts_with("--plan-id=") => {
                recovery_args.plan_id =
                    Some(parse_opaque_id(&a["--plan-id=".len()..], "--plan-id")?);
                idx += 1;
            }
            "--confirm" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--confirm requires a token".into(),
                })?;
                recovery_args.confirm = Some(parse_opaque_id(value, "--confirm")?);
                idx += 2;
            }
            a if a.starts_with("--confirm=") => {
                recovery_args.confirm =
                    Some(parse_opaque_id(&a["--confirm=".len()..], "--confirm")?);
                idx += 1;
            }
            "--transaction" => {
                let value = argv.get(idx + 1).ok_or_else(|| Error::InvalidArgument {
                    message: "--transaction requires a transaction id".into(),
                })?;
                recovery_args.transaction = Some(parse_opaque_id(value, "--transaction")?);
                idx += 2;
            }
            a if a.starts_with("--transaction=") => {
                recovery_args.transaction = Some(parse_opaque_id(
                    &a["--transaction=".len()..],
                    "--transaction",
                )?);
                idx += 1;
            }
            // First positional (no leading dash) becomes the subcommand.
            positional if !positional.starts_with('-') && command.is_none() => {
                command = Some(parse_command(positional, argv, &mut idx)?);
            }
            // A second positional after we already have the subcommand is an
            // error (none of these commands accepts another positional argument).
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
    let recovery = match command {
        Command::Recovery(sub) => {
            recovery_args.subcommand = sub;
            recovery_args.target = target.clone();
            Some(recovery_args)
        }
        Command::TargetPlan | Command::TargetMount => None,
        _ => {
            if target != TargetSelection::default() {
                return Err(Error::InvalidArgument {
                    message: "explicit device options are valid only for target plan, target mount, or recovery subcommands"
                        .into(),
                });
            }
            None
        }
    };

    Ok(ParseOutcome::Run(Box::new(CliArgs {
        command,
        root: root.unwrap_or(default_root),
        json,
        target,
        recovery,
    })))
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

fn parse_opaque_id(value: &str, option: &str) -> Result<String, Error> {
    if value.is_empty() || value.contains('\0') {
        return Err(Error::InvalidArgument {
            message: format!("{option} must be a non-empty string without NUL"),
        });
    }
    let cleaned = value.trim_matches(|c: char| c.is_whitespace());
    if cleaned.is_empty() {
        return Err(Error::InvalidArgument {
            message: format!("{option} must contain non-whitespace characters"),
        });
    }
    Ok(cleaned.to_string())
}

fn root_error(error: catos_target::diagnose::system_root::RootError) -> crate::error::Error {
    use catos_target::diagnose::system_root::RootError;
    match error {
        RootError::PermissionDenied(path) => crate::error::Error::PermissionDenied {
            path: path.into(),
            detail: "cannot stat target root".into(),
        },
        other => crate::error::Error::InvalidRoot {
            path: match &other {
                RootError::Relative(path)
                | RootError::DoesNotExist(path)
                | RootError::NotADirectory(path)
                | RootError::PermissionDenied(path)
                | RootError::EscapeAttempt(path) => path.into(),
            },
            reason: other.to_string(),
        },
    }
}
