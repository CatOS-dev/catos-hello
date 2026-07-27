//! Provider trait and shared helpers. Port of `providers/base.py`.
//!
//! Each provider implementation owns:
//!
//! * `execute` — write target-local config files + invoke the fixed
//!   allow-list of target commands.
//! * `verify` — call the provider's own verification surface
//!   (`grub-mkconfig`-generated `grub.cfg` inspection, `bootctl
//!   is-installed`, `limine-list`, `catos-firmware-boot-update
//!   --verify`). Verification must reflect real tool output, not
//!   just file presence.
//! * `setup_snapshots` (provider-specific) — only when the target
//!   root is Btrfs and the registry declares snapshot support for
//!   this provider.
//!
//! The trait is intentionally NOT generic over filesystem access.
//! Providers receive a [`crate::repair::boot_repair::ProviderCtx`]
//! handle that exposes the confined target root, the target command
//! runner, and the kernel cmdline.

use crate::shared::model::boot_repair::{BootAction, BootVerification, ProviderId, TargetCommandResult};
use crate::mount::model::MountTargetIdentity;
use crate::repair::boot_repair::target_exec::{TargetRequest, TargetRunner};

/// Shared read-only context every provider receives. Built by the
/// orchestrator after detection and cmdline generation.
#[derive(Debug, Clone)]
pub struct ProviderCtx<'a> {
    pub target: &'a MountTargetIdentity,
    pub provider: ProviderId,
    /// Kernel cmdline the recipe will write to `/etc/kernel/cmdline`
    /// (Limine, systemd-boot, UKI, EFI Stub) or embed in
    /// `/etc/default/grub.d/00-catos.cfg` (GRUB).
    pub cmdline: String,
    /// ESP mount point as the target sees it (e.g. `/boot/efi`).
    /// `None` for BIOS GRUB.
    pub esp_mount_point: Option<String>,
    /// BIOS install path when applicable (whole disk device path).
    /// Required by BIOS GRUB.
    pub bios_install_path: Option<String>,
    /// Detected architecture.
    pub architecture: crate::shared::model::boot_repair::Architecture,
    /// Branding name (bootloader label). Mirrors bootloadu
    /// `branding_name`; defaults to "CatOS".
    pub branding_name: String,
    /// Whether the target root is Btrfs.
    pub root_is_btrfs: bool,
}

/// Result of running one provider recipe. Built by each provider's
/// `execute` / `verify` methods and folded into the final
/// [`crate::shared::model::boot_repair::BootRepairReport`] by the
/// orchestrator.
#[derive(Debug, Clone, Default)]
pub struct ProviderRecipeResult {
    pub actions: Vec<BootAction>,
    pub verification: BootVerification,
    /// `true` when the recipe's verify step passed.
    pub verified: bool,
    /// Failure message, when execute or verify failed partway.
    pub failure: Option<String>,
    /// Recorded commands the orchestrator should add to the audit
    /// trail alongside file-write actions. Kept separate so the
    /// orchestrator can interleave them with config-write actions
    /// in chronological order.
    pub command_results: Vec<TargetCommandResult>,
}

impl ProviderRecipeResult {
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            failure: Some(message.into()),
            verified: false,
            ..Self::default()
        }
    }
}

/// The provider trait. Each variant implements `execute` and
/// `verify`. The orchestrator decides when each runs.
///
/// Methods take `&dyn TargetRunner` rather than `<R: TargetRunner>`
/// so the trait stays object-safe and the orchestrator can drive
/// every provider through one `Box<dyn BootProvider>` code path.
pub trait BootProvider {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderRecipeResult;
    fn verify(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderRecipeResult;
    /// Snapshot setup. Default implementation refuses; providers
    /// that support bootable snapshots override.
    fn setup_snapshots(
        &self,
        _ctx: &ProviderCtx<'_>,
        _runner: &dyn TargetRunner,
    ) -> ProviderRecipeResult {
        ProviderRecipeResult::failed("provider does not support bootable snapshots")
    }
}

/// Run a target command through the runner and wrap the result so
/// the provider can record it as a [`BootAction::TargetCommand`].
pub fn run_target(
    runner: &dyn TargetRunner,
    binary: &str,
    argv: Vec<String>,
    description: &str,
) -> (TargetCommandResult, Option<BootAction>) {
    let request = TargetRequest::new(binary, argv, description);
    let result = runner.invoke(&request);
    let action = BootAction::TargetCommand {
        result: result.clone(),
    };
    (result, Some(action))
}

/// Convenience: run a target command, append the result to `actions`
/// and `command_results`, and return whether it succeeded.
pub fn record_target_command(
    runner: &dyn TargetRunner,
    actions: &mut Vec<BootAction>,
    command_results: &mut Vec<TargetCommandResult>,
    binary: &str,
    argv: Vec<String>,
    description: &str,
) -> bool {
    let (result, action) = run_target(runner, binary, argv, description);
    let success = !result.binary_missing && !result.timed_out && result.exit_code == 0;
    if let Some(action) = action {
        actions.push(action);
    }
    command_results.push(result);
    success
}

/// Append a recorded config-write action.
pub fn record_config_write(
    actions: &mut Vec<BootAction>,
    target_path: &str,
    backup_path: Option<&str>,
    bytes: usize,
) {
    actions.push(BootAction::ConfigWritten {
        target_path: target_path.to_string(),
        backup_path: backup_path.map(str::to_string),
        bytes,
    });
}

/// Append a recorded "config already correct" action.
pub fn record_config_unchanged(actions: &mut Vec<BootAction>, target_path: &str) {
    actions.push(BootAction::ConfigUnchanged {
        target_path: target_path.to_string(),
    });
}
