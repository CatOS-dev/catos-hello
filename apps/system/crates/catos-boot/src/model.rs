//! Boot-provider repair data model. Pure data + serde, no I/O.
//!
//! This is the structured result of `catos-repair boot`. It is NOT a
//! [`catos_mount::model::MountRepairReport`] and NOT a
//! [`crate::snapshot::model::RecoveryPlan`]; boot repair is the
//! re-application of an existing bootloader provider recipe, not a
//! generic bootloader-transaction framework.
//!
//! ## Design rules
//!
//! * The provider is **detected** from the target's own configuration
//!   and deployed artefacts — never selected by the live environment
//!   or guessed from a single stale ESP file.
//! * Each fixed command the orchestrator ran is audited in
//!   [`BootAction::TargetCommand`], including argv, exit code, signal,
//!   timeout, and truncation state. Sensitive command output is redacted
//!   before it enters the report.
//! * `final_outcome` is the single source of truth. Bootloader
//!   installs, EFI variable writes, and signature operations are NOT
//!   atomic; partial success MUST surface as
//!   [`BootRepairOutcome::PartiallyRepaired`] or
//!   [`BootRepairOutcome::ManualInterventionRequired`], never as
//!   `Repaired`.
//! * The model reuses [`catos_mount::model::MountTargetIdentity`]
//!   and [`catos_mount::model::MountRepairCleanup`] so the
//!   stage 1–3 device-lock, mount-session, and cleanup contracts
//!   remain the single source for those concerns.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use catos_mount::model::{MountRepairCleanup, MountTargetIdentity};
use catos_target::model::Warning;
use catos_target::Evidence;

/// A value that must never be emitted by serde or exposed through `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl std::ops::Deref for SensitiveString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.expose()
    }
}

// ---------------------------------------------------------------------------
// Boot resource topology
// ---------------------------------------------------------------------------

/// Layout of boot resources for a mounted target or snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootLayout {
    /// `/boot` is a directory inside the root subvolume.
    pub boot_inside_root: bool,
    /// `/boot` is mounted from a separate filesystem.
    pub boot_separate_filesystem: bool,
    /// `/boot` is a separate Btrfs subvolume.
    pub boot_separate_subvolume: bool,
    /// ESP location, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_mount_point: Option<String>,
    /// Block device path of the ESP, if separately identified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_device: Option<String>,
    /// UKI files observed in the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uki_paths: Vec<String>,
    /// Kernel versions visible under `/usr/lib/modules`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_versions: Vec<String>,
    /// Whether the target appears to contain an initramfs.
    pub has_initramfs: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BootConsistencyStatus {
    Consistent,
    Inconsistent,
    #[default]
    Unknown,
    Unsupported,
}

/// Read-only assessment of whether a root-only operation preserves all
/// observed boot resources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootConsistencyReport {
    pub status: BootConsistencyStatus,
    pub checked_read_only: bool,
    pub root_switch_covers_all_boot_resources: bool,
    pub external_boot: bool,
    pub external_esp: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Provider identity
// ---------------------------------------------------------------------------

/// The five user-visible bootloader providers `catos-repair boot`
/// recognises. Internally `uki` and `efistub` share a single
/// [`crate::execute::providers::firmware`] implementation
/// parameterised by [`FirmwareMethod`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderId {
    #[default]
    Grub,
    Limine,
    SystemdBoot,
    Uki,
    Efistub,
}

impl ProviderId {
    /// Stable identifier matching the bootloadu registry and
    /// `/etc/catos/firmware-boot.conf`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderId::Grub => "grub",
            ProviderId::Limine => "limine",
            ProviderId::SystemdBoot => "systemd-boot",
            ProviderId::Uki => "uki",
            ProviderId::Efistub => "efistub",
        }
    }

    /// Parse a provider id from its registry form. Used by detection
    /// when reading target-side configuration files.
    pub fn from_registry_str(value: &str) -> Option<ProviderId> {
        match value.trim() {
            "grub" => Some(ProviderId::Grub),
            "limine" => Some(ProviderId::Limine),
            "systemd-boot" => Some(ProviderId::SystemdBoot),
            "uki" => Some(ProviderId::Uki),
            "efistub" => Some(ProviderId::Efistub),
            _ => None,
        }
    }

    /// All five providers, in registry order. Used by detection to
    /// iterate evidence without privileging one provider.
    pub fn all() -> &'static [ProviderId] {
        &[
            ProviderId::Grub,
            ProviderId::Limine,
            ProviderId::SystemdBoot,
            ProviderId::Uki,
            ProviderId::Efistub,
        ]
    }
}

/// The two firmware methods [`ProviderId::Uki`] and
/// [`ProviderId::Efistub`] share. Mirrors `method = ...` in
/// `/etc/catos/firmware-boot.conf`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirmwareMethod {
    Uki,
    Efistub,
}

impl FirmwareMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            FirmwareMethod::Uki => "uki",
            FirmwareMethod::Efistub => "efistub",
        }
    }

    pub fn parse_registry_str(value: &str) -> Option<FirmwareMethod> {
        match value.trim() {
            "uki" => Some(FirmwareMethod::Uki),
            "efistub" => Some(FirmwareMethod::Efistub),
            _ => None,
        }
    }
}

/// Firmware class observed for the target. Detection is descriptive;
/// `BIOS` and `UEFI` map to the bootloadu registry's `bios` / `efi`
/// platform names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirmwareClass {
    #[default]
    Bios,
    Efi,
}

impl FirmwareClass {
    pub fn as_registry_str(self) -> &'static str {
        match self {
            FirmwareClass::Bios => "bios",
            FirmwareClass::Efi => "efi",
        }
    }
}

/// Architecture detected for the target. Mirrors the bootloadu
/// `normalize_architecture` aliases (`amd64`/`arm64` collapse to
/// `x86_64`/`aarch64`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    #[default]
    X86_64,
    Aarch64,
}

impl Architecture {
    pub fn as_str(self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
        }
    }

    /// Normalise uname-style aliases. Returns `None` for an
    /// architecture the registry does not list at all.
    pub fn from_uname(value: &str) -> Option<Architecture> {
        match value.trim() {
            "x86_64" | "amd64" => Some(Architecture::X86_64),
            "aarch64" | "arm64" => Some(Architecture::Aarch64),
            _ => None,
        }
    }
}

/// Partition table observed for the target disk. Required because the
/// registry marks `limine`, `systemd-boot`, `uki`, and `efistub` as
/// GPT-only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PartitionTable {
    #[default]
    Unknown,
    Gpt,
    Msdos,
}

/// Snapshot of the target platform facts the registry is checked
/// against. All fields are required; missing facts fail closed as
/// [`BootRepairOutcome::AmbiguousTarget`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformFacts {
    pub firmware: FirmwareClass,
    pub architecture: Architecture,
    pub partition_table: PartitionTable,
}

// ---------------------------------------------------------------------------
// Outcome taxonomy
// ---------------------------------------------------------------------------

/// Single source of truth for "what happened" during a boot repair.
///
/// Where a variant has the same meaning as
/// [`catos_mount::model::MountRepairOutcome`], the snake_case
/// code is identical so consumers can reuse rendering logic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BootRepairOutcome {
    /// Bootloader already installed and verified; no command needed.
    Clean,
    /// Provider recipe re-applied end to end; verify passed.
    Repaired,
    /// Some steps completed but external side effects (EFI variables,
    /// signatures, bootloader install) cannot be cleanly reverted.
    /// User inspection required.
    PartiallyRepaired,
    /// Target platform is not supported by the detected provider
    /// (e.g. Limine on aarch64, GRUB BIOS on aarch64, GPT-only
    /// provider on an MBR disk).
    Unsupported,
    /// Target could not be uniquely identified. Same code as
    /// mount-repair's variant so consumers share logic.
    AmbiguousTarget,
    /// Bootloader provider could not be uniquely identified from the
    /// target's own configuration and deployed artefacts.
    AmbiguousProvider,
    /// Provider recipe ran but verification (e.g. `bootctl
    /// is-installed`, `limine-list`, `catos-firmware-boot-update
    /// --verify`, GRUB menuentry inspection) failed.
    VerificationFailed,
    /// Boot files were written but cleanup of session-created mounts
    /// did not complete cleanly.
    CleanupIncomplete,
    /// An external side effect (EFI NVRAM write, MOK enrollment,
    /// signature, bootloader install) failed or partially completed
    /// and the orchestrator cannot reach a clean end state without
    /// operator intervention.
    ManualInterventionRequired,
    /// Catch-all for an internal error that prevented producing a
    /// meaningful result.
    #[default]
    Unknown,
}

impl BootRepairOutcome {
    /// Stable snake_case code, identical to the serde form.
    pub fn code(self) -> &'static str {
        match self {
            BootRepairOutcome::Clean => "clean",
            BootRepairOutcome::Repaired => "repaired",
            BootRepairOutcome::PartiallyRepaired => "partially_repaired",
            BootRepairOutcome::Unsupported => "unsupported",
            BootRepairOutcome::AmbiguousTarget => "ambiguous_target",
            BootRepairOutcome::AmbiguousProvider => "ambiguous_provider",
            BootRepairOutcome::VerificationFailed => "verification_failed",
            BootRepairOutcome::CleanupIncomplete => "cleanup_incomplete",
            BootRepairOutcome::ManualInterventionRequired => "manual_intervention_required",
            BootRepairOutcome::Unknown => "unknown",
        }
    }

    /// `true` iff the outcome represents a successful end state.
    pub fn is_success(self) -> bool {
        matches!(
            self,
            BootRepairOutcome::Clean
                | BootRepairOutcome::Repaired
                | BootRepairOutcome::PartiallyRepaired
        )
    }

    /// `true` iff the orchestrator deliberately refused to act.
    pub fn is_refusal(self) -> bool {
        matches!(
            self,
            BootRepairOutcome::AmbiguousTarget
                | BootRepairOutcome::AmbiguousProvider
                | BootRepairOutcome::Unsupported
        )
    }
}

// ---------------------------------------------------------------------------
// Kernel cmdline target facts
// ---------------------------------------------------------------------------

/// One verified dm-crypt mapping used by the target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LuksMapping {
    pub luks_uuid: String,
    pub mapper_name: String,
}

/// The single resume target emitted on the kernel command line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResumeTarget {
    /// A normal swap partition identified by its swap UUID.
    Uuid { uuid: String },
    /// An already-defined encrypted swap mapping.
    Mapper { mapper_name: String },
    /// A swap file whose backing block device and physical offset were
    /// established from the mounted target.
    SwapFile { device: String, offset: u64 },
}

/// Fully diagnosed inputs for kernel command-line construction. Empty values
/// here are negative facts established by inspecting the target fstab and
/// block topology, not caller-supplied defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootCmdlineFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub luks_root: Option<LuksMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Failure to establish a complete, unambiguous cmdline identity. Boot repair
/// must refuse before writing provider configuration when this is returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootCmdlineFactsError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl std::fmt::Display for BootCmdlineFactsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BootCmdlineFactsError {}

// ---------------------------------------------------------------------------
// Kernel cmdline conflict reporting
// ---------------------------------------------------------------------------

/// A conflict the cmdline builder refused to silently resolve.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CmdlineConflict {
    /// Same key supplied with different values (e.g. `root=` pointing
    /// at two different devices).
    ConflictingValue {
        key: String,
        existing: String,
        proposed: String,
    },
}

// ---------------------------------------------------------------------------
// Detection evidence summary
// ---------------------------------------------------------------------------

/// One observed signal used to detect (or rule out) a provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderEvidence {
    /// Which provider this signal supports.
    pub provider: ProviderId,
    /// Stable machine code, e.g. `ETC_DEFAULT_GRUB_D_PRESENT`.
    pub code: String,
    /// Path or probe that produced the signal.
    pub source: String,
    /// Human-readable explanation.
    pub message: String,
    /// `true` if this signal alone would be enough to identify the
    /// provider (e.g. `/etc/catos/firmware-boot.conf` with a known
    /// method). Stale ESP files are NOT authoritative.
    pub authoritative: bool,
}

// ---------------------------------------------------------------------------
// Target command audit
// ---------------------------------------------------------------------------

/// One invocation of a fixed-whitelist target command. The argv is
/// captured verbatim so consumers can audit "did we really pass
/// `--recheck` and not shell-expand anything?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetCommand {
    /// Bare tool name, resolved from the trusted target binary
    /// directories by the target-command executor.
    pub binary: String,
    /// argv[1..], exactly as passed to the executor.
    pub argv: Vec<String>,
    /// Human-readable description (e.g. "install GRUB for UEFI").
    pub description: String,
}

/// Captured outcome of one target command. Stored verbatim in the
/// final report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetCommandResult {
    pub command: TargetCommand,
    /// True iff the binary was missing from the trusted target
    /// directories.
    pub binary_missing: bool,
    /// True iff the executor killed the process for exceeding the
    /// deadline.
    pub timed_out: bool,
    /// Raw exit code, or `-1` when the process was killed by a signal
    /// or never started.
    pub exit_code: i32,
    /// Captured stdout, already truncated by the executor.
    pub stdout: Vec<u8>,
    /// Captured stderr, already truncated.
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

// ---------------------------------------------------------------------------
// Plan + actions
// ---------------------------------------------------------------------------

/// Per-step action recorded in the final report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootAction {
    /// A target-local configuration file was atomically replaced
    /// (e.g. `/etc/kernel/cmdline`, `/etc/default/limine`).
    ConfigWritten {
        target_path: String,
        backup_path: Option<String>,
        bytes: usize,
    },
    /// A target-local configuration file was inspected and left
    /// unchanged because its content already matched the recipe.
    ConfigUnchanged { target_path: String },
    /// A fixed-whitelist target command was executed.
    TargetCommand { result: TargetCommandResult },
    /// A target command was skipped because a required precondition
    /// (e.g. tool not installed) was not met.
    TargetCommandSkipped {
        command: TargetCommand,
        reason: String,
    },
    /// A snapshot-related target command or service enablement ran.
    SnapshotStep {
        description: String,
        result: Option<TargetCommandResult>,
    },
}

/// Verification result the provider returned after running its recipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootVerification {
    /// `true` iff the provider's own verify step passed (e.g.
    /// `bootctl is-installed` exited 0, GRUB `grub.cfg` contains a
    /// real Linux menuentry, etc.).
    pub passed: bool,
    /// Stable machine codes for each check that ran.
    pub checks: Vec<String>,
    /// Failure message when verification failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

/// Secure Boot finalisation outcome. Repair preserves the target's
/// existing policy; it never auto-enables Secure Boot just because the
/// live host has it on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecureBootReport {
    /// `true` iff the target already had CatOS Secure Boot configured,
    /// proven by a valid persisted state record and complete machine key
    /// material. Repair may re-apply the existing policy in that case.
    pub target_policy_present: bool,
    /// `true` iff repair invoked `catos-secureboot enable ...` to
    /// re-apply the existing target policy.
    pub enable_invoked: bool,
    /// Certificate fingerprint returned by `catos-secureboot`, when
    /// available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_fingerprint: Option<String>,
    /// `true` iff `catos-secureboot` reported that machine enrollment
    /// is still pending.
    #[serde(default)]
    pub enrollment_pending: bool,
    /// `true` iff `catos-secureboot` generated a one-time MokManager password.
    #[serde(default)]
    pub enrollment_password_generated: bool,
    /// Target-relative absolute path where `catos-secureboot` persisted the
    /// one-time password. Safe to expose; the password itself is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_password_path: Option<String>,
    /// One-time MokManager password for human output only. It is skipped by
    /// serde and its `Debug` representation is always redacted.
    #[serde(skip)]
    pub enrollment_password: Option<SensitiveString>,
    /// `true` iff the orchestrator was unable to determine whether
    /// Secure Boot should be re-applied (refuses to guess).
    #[serde(default)]
    pub ambiguous: bool,
    /// Captured JSON or stderr from `catos-secureboot`, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<String>,
    /// Failure message, when Secure Boot finalisation failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

/// Final result of `catos-repair boot`. This struct is the contract:
/// human and JSON output both render it directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BootRepairReport {
    /// Target identity snapshot at detection time. `None` only when
    /// we refused before identifying a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<MountTargetIdentity>,
    /// Platform facts observed for the target. Required for the
    /// platform support matrix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformFacts>,
    /// Detected bootloader provider. `None` when detection was
    /// ambiguous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_provider: Option<ProviderId>,
    /// Firmware method observed in `/etc/catos/firmware-boot.conf`
    /// for the UEFI firmware family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_method: Option<FirmwareMethod>,
    /// All provider evidence collected during detection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_evidence: Vec<ProviderEvidence>,
    /// Generated kernel cmdline. Recorded so consumers can audit
    /// exactly what was written to `/etc/kernel/cmdline` or embedded
    /// in the GRUB defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
    /// Verified LUKS/swap/resume facts used to build `kernel_cmdline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline_facts: Option<BootCmdlineFacts>,
    /// Cmdline conflicts the builder refused to resolve silently.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmdline_conflicts: Vec<CmdlineConflict>,
    /// Per-step actions executed by the provider recipe.
    #[serde(default)]
    pub actions: Vec<BootAction>,
    /// Provider verification outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<BootVerification>,
    /// Secure Boot finalisation outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secureboot: Option<SecureBootReport>,
    /// Cleanup of mounts WE created. Reuses the mount-repair shape.
    #[serde(default)]
    pub cleanup: MountRepairCleanup,
    /// Single source of truth for the final outcome.
    pub final_outcome: BootRepairOutcome,
    /// `true` iff the user must take manual action.
    pub requires_human_action: bool,
    /// `true` iff the repair is fully complete.
    pub fully_complete: bool,
    /// Evidence trail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Non-fatal warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

impl BootRepairReport {
    /// Convenience constructor for a refusal report.
    pub fn refused(outcome: BootRepairOutcome, reason: &str) -> Self {
        debug_assert!(
            outcome.is_refusal() || matches!(outcome, BootRepairOutcome::Unknown),
            "refused() called with non-refusal outcome {outcome:?}"
        );
        Self {
            final_outcome: outcome,
            requires_human_action: true,
            fully_complete: false,
            evidence: vec![Evidence::new("REFUSED", "repair::boot", reason.to_string())],
            ..Default::default()
        }
    }

    /// Convenience constructor for a clean report.
    pub fn clean(target: MountTargetIdentity, provider: ProviderId) -> Self {
        Self {
            target: Some(target),
            detected_provider: Some(provider),
            final_outcome: BootRepairOutcome::Clean,
            requires_human_action: false,
            fully_complete: true,
            evidence: vec![Evidence::new(
                "CLEAN",
                "repair::boot",
                format!("{} deployment already verified", provider.as_str()),
            )],
            ..Default::default()
        }
    }
}

/// Path of a target-local file inside the target root, suitable for
/// the confined writer. Carries both the user-visible absolute path
/// (e.g. `/etc/kernel/cmdline`) and the storage-root-relative path
/// used by the confined writer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetFile {
    pub absolute: PathBuf,
    pub relative: String,
}

impl TargetFile {
    pub fn new(absolute: &str) -> Self {
        let relative = absolute.trim_start_matches('/').to_string();
        Self {
            absolute: PathBuf::from(absolute),
            relative,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_string_is_redacted_from_debug_and_secureboot_json() {
        let report = SecureBootReport {
            enrollment_password_generated: true,
            enrollment_password_path: Some("/var/lib/catos-secureboot/enrollment-password".into()),
            enrollment_password: Some(SensitiveString::new("SEKRET123")),
            ..SecureBootReport::default()
        };

        let debug = format!("{report:?}");
        assert!(!debug.contains("SEKRET123"));
        assert!(debug.contains("<redacted>"));

        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("SEKRET123"));
        assert!(!json.contains("\"enrollment_password\""));
        assert!(json.contains("enrollment_password_generated"));
        assert!(json.contains("enrollment_password_path"));
    }

    #[test]
    fn outcome_code_matches_serde_form() {
        for outcome in [
            BootRepairOutcome::Clean,
            BootRepairOutcome::Repaired,
            BootRepairOutcome::PartiallyRepaired,
            BootRepairOutcome::Unsupported,
            BootRepairOutcome::AmbiguousTarget,
            BootRepairOutcome::AmbiguousProvider,
            BootRepairOutcome::VerificationFailed,
            BootRepairOutcome::CleanupIncomplete,
            BootRepairOutcome::ManualInterventionRequired,
            BootRepairOutcome::Unknown,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let trimmed = json.trim_matches('"');
            assert_eq!(outcome.code(), trimmed, "serde/code drift for {outcome:?}");
        }
    }

    #[test]
    fn provider_id_round_trips_through_registry_string() {
        for provider in ProviderId::all() {
            let s = provider.as_str();
            assert_eq!(ProviderId::from_registry_str(s), Some(*provider));
        }
        assert!(ProviderId::from_registry_str("unknown").is_none());
    }

    #[test]
    fn firmware_method_round_trips() {
        for method in [FirmwareMethod::Uki, FirmwareMethod::Efistub] {
            let s = method.as_str();
            assert_eq!(FirmwareMethod::parse_registry_str(s), Some(method));
        }
        assert!(FirmwareMethod::parse_registry_str("acpi").is_none());
    }

    #[test]
    fn architecture_normalises_aliases() {
        assert_eq!(
            Architecture::from_uname("x86_64"),
            Some(Architecture::X86_64)
        );
        assert_eq!(
            Architecture::from_uname("amd64"),
            Some(Architecture::X86_64)
        );
        assert_eq!(
            Architecture::from_uname("aarch64"),
            Some(Architecture::Aarch64)
        );
        assert_eq!(
            Architecture::from_uname("arm64"),
            Some(Architecture::Aarch64)
        );
        assert!(Architecture::from_uname("riscv64").is_none());
    }

    #[test]
    fn refused_report_marks_requires_human_action() {
        let r = BootRepairReport::refused(
            BootRepairOutcome::AmbiguousProvider,
            "multiple providers detected",
        );
        assert!(r.requires_human_action);
        assert!(!r.fully_complete);
        assert_eq!(r.final_outcome, BootRepairOutcome::AmbiguousProvider);
    }
}
