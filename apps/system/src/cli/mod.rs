//! Hand-rolled CLI parser for the catos-system multicall. No external CLI
//! framework: the surface is small and a hand-rolled parser keeps the
//! dependency surface minimal, which matters for a static binary intended
//! to run in initramfs.

pub mod help;
pub mod parser;
pub mod types;

pub use help::*;
pub use parser::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::exit_code;
    use crate::target::diagnose::system_root::SystemRoot;
    use std::path::Path;

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
