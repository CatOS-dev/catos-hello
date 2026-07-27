//! Repair application orchestration.
//!
//! `catos-repair fs` orchestrates third-party fsck tools (e2fsck,
//! fsck.fat, fsck.f2fs, xfs_repair, btrfs check) while delegating
//! filesystem effects to the `fs` capability.
//!
//! ## Architecture
//!
//! ```text
//!   entry::run_repair("fs", argv)
//!     |
//!     v
//!   repair::orchestrator::run_fs_repair
//!     |
//!     +-- fs::safety   : target selection + safety refusals
//!     +-- fs::command   : FsCommandRunner trait (real + fake)
//!     +-- fs::{plan,execute}  : per-fstype flows built on CommandRunner
//!     +-- fs::verify   : read-only post-repair verification mount
//! ```
//!
//! ## Hard rules
//!
//! * The FsCommandRunner trait is the *only* interface the orchestrator
//!   uses to spawn tools. The default implementation
//!   (`RepairRunner`) goes through [`crate::shared::process::run_trusted_tool`]
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

pub mod boot;
pub mod boot_output;
pub mod mount;
pub mod orchestrator;

pub use mount::{
    build_plan, diagnose, run_mount_repair_diagnosis, run_mount_repair_via_cli, MountRepairInputs,
};

pub use orchestrator::run_fs_repair;
