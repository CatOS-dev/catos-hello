//! Provider trait and shared helpers. Port of `providers/base.py`.
//!
//! Each provider implementation owns two deliberately separate surfaces:
//!
//! * `execute` — write target-local config files + invoke the fixed
//!   allow-list of target commands.
//! * `verify` — call the provider's own verification surface
//!   (`grub-mkconfig`-generated `grub.cfg` inspection, `bootctl
//!   is-installed`, `limine-list`, `catos-firmware-boot-update
//!   --verify`). Verification must reflect real tool output, not
//!   just file presence.
//!
//! The trait is intentionally NOT generic over filesystem access.
//! Providers receive a [`crate::boot::execute::providers::base::ProviderCtx`]
//! handle that exposes the confined target root, the target command
//! runner, and the kernel cmdline.

use crate::boot::execute::target::{TargetRequest, TargetRunner};
use crate::boot::model::{BootAction, BootVerification, ProviderId, TargetCommandResult};
use crate::mount::model::MountTargetIdentity;

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
    pub architecture: crate::boot::model::Architecture,
    /// Branding name (bootloader label). Mirrors bootloadu
    /// `branding_name`; defaults to "CatOS".
    pub branding_name: String,
    /// Whether the target root is Btrfs.
    pub root_is_btrfs: bool,
}

/// Result of the authorised effect stage for one provider.
#[derive(Debug, Clone, Default)]
pub struct ProviderExecutionResult {
    pub actions: Vec<BootAction>,
    /// Failure message when execution stopped partway.
    pub failure: Option<String>,
    pub command_results: Vec<TargetCommandResult>,
}

impl ProviderExecutionResult {
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            failure: Some(message.into()),
            ..Self::default()
        }
    }
}

/// Result of the read-only provider verification stage.
#[derive(Debug, Clone, Default)]
pub struct ProviderVerificationResult {
    pub actions: Vec<BootAction>,
    pub verification: BootVerification,
    pub passed: bool,
    pub command_results: Vec<TargetCommandResult>,
}

/// Authorised provider effects only.
pub trait BootProviderExecutor {
    fn execute(&self, ctx: &ProviderCtx<'_>, runner: &dyn TargetRunner) -> ProviderExecutionResult;
}

/// Read-only provider postcondition checks only.
pub trait BootProviderVerifier {
    fn verify(
        &self,
        ctx: &ProviderCtx<'_>,
        runner: &dyn TargetRunner,
    ) -> ProviderVerificationResult;
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
