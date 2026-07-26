//! Filesystem repair layer.
//!
//! `catos-repair fs` orchestrates third-party fsck tools (e2fsck,
//! fsck.fat, fsck.f2fs, xfs_repair, btrfs check). This module is the
//! only place in the crate that spawns those tools.
//!
//! ## Architecture
//!
//! ```text
//!   entry::run_repair("fs", argv)
//!     |
//!     v
//!   repair::orchestrator::run_fs_repair
//!     |
//!     +-- repair::safety   : target selection + safety refusals
//!     +-- repair::runner   : CommandRunner trait (real + fake)
//!     +-- repair::fs_flows  : per-fstype flows built on CommandRunner
//!     +-- repair::verify   : read-only post-repair verification mount
//! ```
//!
//! ## Hard rules
//!
//! * The CommandRunner trait is the *only* interface the orchestrator
//!   uses to spawn tools. The default implementation
//!   (`TrustedRunner`) goes through [`crate::shared::process::run_trusted_tool`]
//!   with the existing fixed-path, minimal-env, bounded-output,
//!   deadline-bound contract. Tests inject a fake runner so behaviour
//!   tests do NOT need root, loop devices, or even the tools
//!   installed.
//! * No shell. Every argv is a `Vec<String>` passed to the runner.
//! * No format. No partition-table edit. No LUKS. No LVM. No mdraid.
//! * The target is never mounted by us when the repair tool runs;
//!   the orchestrator refuses a mounted target before invoking any
//!   tool.
//! * The only mount we create is a single read-only verification
//!   mount after a successful repair, in a private namespace, and it
//!   is unmounted before we return.

pub mod boot_repair;
pub mod fstab_edit;
pub mod mount_repair;
pub mod orchestrator;
pub mod path_safety;
pub mod runner;
pub mod fs_flows;
pub mod safety;
pub mod subvol_decision;
pub mod verify;

pub use boot_repair::run_boot_repair;
pub use mount_repair::{
    build_plan, diagnose, run_mount_repair_diagnosis, run_mount_repair_via_cli, MountRepairInputs,
};

pub use orchestrator::run_fs_repair;
pub use runner::{
    CommandRunner, RecordedInvocation, RecordedRunner, RepairInvocation, RepairRunnerError,
    TrustedRunner,
};
pub use fs_flows::{
    btrfs_check_only, check_only_for, e2fsck_check_only, f2fs_check_only, fat_check_only,
    xfs_check_only, ReadonlyOutcome, ReadonlyResult,
};
pub use fs_flows::{
    btrfs_flow, btrfs_topology, e2fsck_flow, f2fs_flow, fat_flow, supports_filesystem, xfs_flow,
    BtrfsTopology, FlowOutcome,
};
pub use safety::{SafetyDecision, SafetyVerdict};
pub use verify::VerificationOutcome;
