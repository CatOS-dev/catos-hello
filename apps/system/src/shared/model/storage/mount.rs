//! Mount plan + session + structured error taxonomy. Pure data + serde.
//!
//! Phase 2 supports ONLY read-only mounts. The data model enforces this
//! at every step: there is no `rw` field anywhere; if a future caller
//! needs read-write it must redesign here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::shared::model::evidence::Evidence;
use crate::target::model::Warning;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Structured mount-layer error. Each variant maps to a stable string
/// code in JSON (see `MountError::code`). Distinct from the probe-level
/// `FsError`: this only describes mount operations.
///
/// Design rule: two genuinely different failures MUST NOT share a
/// variant. The variant name IS the API contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountError {
    pub kind: MountErrorKind,
    /// User-readable message (English; no colour escapes).
    pub message: String,
    /// Device or path the error concerns, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_or_path: Option<String>,
    /// Raw errno (negative for libcs `errno`, kept positive for clarity)
    /// when the error originated from a syscall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// Steps that were already completed before this error fired. Used by
    /// the session to report rollback scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_steps: Vec<String>,
    /// Whether the session has finished rolling back after this error.
    pub cleanup_complete: bool,
    /// Mounts still present after rollback (and after a final best-effort
    /// retry). Reported so the user can manually `umount` them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residual_mounts: Vec<String>,
}

impl MountError {
    /// Stable snake_case code; the public JSON contract.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message)?;
        if let Some(d) = &self.device_or_path {
            write!(f, " (device={d})")?;
        }
        Ok(())
    }
}

/// All mount-layer failure modes. Variants are part of the JSON contract;
/// do not rename. Adding a variant is backward-compatible.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountErrorKind {
    /// Caller lacks CAP_SYS_ADMIN.
    CapabilityMissing,
    /// Caller lacks permission to write the target path or open the device.
    PermissionDenied,
    /// unshare(CLONE_NEWNS) failed or was refused by the kernel.
    NamespaceUnavailable,
    /// Device node does not exist.
    DeviceNotFound,
    /// Device or target path is busy.
    DeviceBusy,
    /// Target path already has something mounted on it (and we did not
    /// create that mount in this session).
    AlreadyMounted,
    /// Filesystem type is not in the allow-list for safe read-only mount.
    UnsupportedFilesystem,
    /// Device exists but its on-disk signature does not match the
    /// requested fstype.
    WrongFilesystemType,
    /// One of the mount options is invalid for this fstype.
    InvalidMountOption,
    /// Kernel reports the on-disk superblock is corrupt.
    BadSuperblock,
    /// The mount would be read-only but we cannot guarantee the kernel
    /// won't write (journal replay, recovery, superblock update). Used
    /// instead of silently falling back to plain `ro`.
    UnsafeReadOnlyMode,
    /// A device reference (UUID/PARTUUID/LABEL/PARTLABEL/PATH) resolved
    /// to zero or multiple devices.
    AmbiguousDeviceReference,
    /// Multiple root candidates meet the same confidence threshold; the
    /// caller must pick one.
    AmbiguousRootCandidate,
    /// Target path failed the same validation as `SystemRoot::try_join`
    /// (escapes the controlled session directory).
    UnsafeTargetPath,
    /// Generic mount(2) failure not covered above.
    MountFailed,
    /// Generic umount2(2) failure not covered above.
    UnmountFailed,
    /// One or more mounts could not be rolled back during cleanup.
    CleanupIncomplete,
    /// An external helper tool we attempted to invoke is missing.
    ExternalToolMissing,
    /// An external helper tool exited non-zero.
    ExternalToolFailed,
    /// An external helper tool's output could not be parsed.
    ExternalOutputInvalid,
}

impl MountErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            MountErrorKind::CapabilityMissing => "capability_missing",
            MountErrorKind::PermissionDenied => "permission_denied",
            MountErrorKind::NamespaceUnavailable => "namespace_unavailable",
            MountErrorKind::DeviceNotFound => "device_not_found",
            MountErrorKind::DeviceBusy => "device_busy",
            MountErrorKind::AlreadyMounted => "already_mounted",
            MountErrorKind::UnsupportedFilesystem => "unsupported_filesystem",
            MountErrorKind::WrongFilesystemType => "wrong_filesystem_type",
            MountErrorKind::InvalidMountOption => "invalid_mount_option",
            MountErrorKind::BadSuperblock => "bad_superblock",
            MountErrorKind::UnsafeReadOnlyMode => "unsafe_read_only_mode",
            MountErrorKind::AmbiguousDeviceReference => "ambiguous_device_reference",
            MountErrorKind::AmbiguousRootCandidate => "ambiguous_root_candidate",
            MountErrorKind::UnsafeTargetPath => "unsafe_target_path",
            MountErrorKind::MountFailed => "mount_failed",
            MountErrorKind::UnmountFailed => "unmount_failed",
            MountErrorKind::CleanupIncomplete => "cleanup_incomplete",
            MountErrorKind::ExternalToolMissing => "external_tool_missing",
            MountErrorKind::ExternalToolFailed => "external_tool_failed",
            MountErrorKind::ExternalOutputInvalid => "external_output_invalid",
        }
    }
}

// ---------------------------------------------------------------------------
// Mount namespace
// ---------------------------------------------------------------------------

/// State of the private mount namespace at the start of a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceState {
    /// Session runs in a freshly unshared CLONE_NEWNS namespace, with
    /// MS_PRIVATE|MS_REC propagation on `/`.
    PrivateNamespace,
    /// unshare failed or was refused. By default we refuse to mount in
    /// this state; only an explicit host-namespace opt-in (NOT in phase
    /// 2) would allow this.
    #[default]
    HostNamespaceRefused,
    /// Some intermediate state during setup (used internally before
    /// setns or before the propagation flip succeeds).
    SetupFailed,
}

// ---------------------------------------------------------------------------
// Mount plan
// ---------------------------------------------------------------------------

/// A single ordered mount step. Phase 2 supports only read-only mounts,
/// so there is no `rw` field and no way to express a writable mount.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountStep {
    /// Ordering key. The session mounts in ascending order and unmounts
    /// in descending order.
    pub order: u32,
    /// Source: a `/dev/...` path, a filesystem-specific token
    /// (e.g. `tmpfs`), or `none`.
    pub source: String,
    /// Filesystem type as it will be passed to mount(2). Always one of
    /// the fstype allow-list entries; never arbitrary.
    pub fstype: String,
    /// Target path under the controlled session directory. Absolute.
    pub target: PathBuf,
    /// Mount options to pass to mount(2), joined by commas.
    ///
    /// ALWAYS contains `ro`. Specific fstype-dependent safety options
    /// (e.g. `noload` for ext4) are added by `mount::plan` after
    /// consulting the per-fstype option table.
    pub options: Vec<String>,
    /// Human-readable reason this step is included.
    pub rationale: String,
    /// Steps that MUST complete before this one. Empty for the root step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<u32>,
    /// Known failure modes for this step, derived from the plan builder.
    /// Used by the human renderer to surface risk before the user says
    /// "go".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl MountStep {
    /// Convenience: options joined as the kernel expects them.
    pub fn options_string(&self) -> String {
        self.options.join(",")
    }
}

/// A fully-formed plan: ordered, validated, ready to execute. The phase-2
/// `target plan` subcommand emits this; `target mount` consumes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountPlan {
    /// Controlled session directory all targets will live under.
    pub session_root: PathBuf,
    /// Where the target root will appear (always `session_root/target`).
    pub target_root: PathBuf,
    pub namespace: NamespaceState,
    /// The device backing the root filesystem, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_device: Option<String>,
    /// Btrfs subvolume path (e.g. `/@`) when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subvolume: Option<String>,
    /// Additional partitions to mount under the target root (e.g. ESP).
    #[serde(default)]
    pub extra_partitions: Vec<String>,
    /// Ordered mount steps. The session mounts them in `order` ascending.
    pub steps: Vec<MountStep>,
    /// Why the plan picked what it picked. Surfaced in human output.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selection_rationale: Vec<String>,
    /// Hard safety limits that apply to the whole session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safety_constraints: Vec<String>,
    /// Non-fatal warnings about the plan (e.g. ambiguous references
    /// that were resolved conservatively).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

// ---------------------------------------------------------------------------
// Mount session
// ---------------------------------------------------------------------------

/// A resource mounted by THIS session. Resources that existed before the
/// session are NEVER tracked here, so we never accidentally unmount them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountedResource {
    /// Step order, matching the plan.
    pub order: u32,
    pub source: String,
    pub target: PathBuf,
    pub fstype: String,
    pub options: String,
}

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MountSessionState {
    /// Plan accepted, namespace ready, no mounts yet.
    #[default]
    Ready,
    /// All steps completed successfully.
    Active,
    /// Mid-rollback after a failure.
    RollingBack,
    /// Rollback completed, no mounts remain. Transitioning OUT of this
    /// state is forbidden.
    Cleaned,
    /// Rollback attempted but some mounts remain.
    CleanupIncomplete,
    /// Final state: everything unmounted cleanly.
    Finished,
}

/// A mount session owns its private namespace (when allowed) and tracks
/// exactly the mounts it created. Public JSON shape for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSession {
    /// Opaque session id, used in the on-disk path
    /// `/run/catos-system/sessions/<id>/`.
    pub id: String,
    pub state: MountSessionState,
    pub namespace: NamespaceState,
    pub session_root: PathBuf,
    pub target_root: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountedResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
}

/// Report produced by the cleanup pass. Surfaced in JSON so the user can
/// verify "the session really did unmount everything it mounted".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupReport {
    /// Mounts the session created and successfully unmounted.
    #[serde(default)]
    pub unmounted: Vec<MountedResource>,
    /// Mounts the session created but could NOT unmount. Each carries
    /// the failure reason.
    #[serde(default)]
    pub residual: Vec<ResidualMount>,
    /// Mounts observed before this session started that the session
    /// deliberately did NOT touch. Reported so the user knows we
    /// respected ownership.
    #[serde(default)]
    pub observed_pre_existing: Vec<String>,
    /// Runtime directory cleanup error, if all mounts were gone but the
    /// private session tree could not be removed safely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_cleanup_error: Option<String>,
    /// Whether the final state is clean (no residuals and no runtime
    /// directory cleanup error).
    pub all_clean: bool,
}

impl Default for CleanupReport {
    // Manual Default because #[derive(Default)] would set all_clean=false,
    // which is semantically wrong: a report with zero residuals IS clean.
    fn default() -> Self {
        Self {
            unmounted: Vec::new(),
            residual: Vec::new(),
            observed_pre_existing: Vec::new(),
            directory_cleanup_error: None,
            all_clean: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidualMount {
    pub resource: MountedResource,
    pub reason: String,
    /// Stable MountErrorKind code for the residual.
    pub error_code: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_step_options_string_joins_with_commas() {
        // Guards against a future refactor accidentally switching to
        // space-separated options, which the kernel would treat as one
        // big option string and silently ignore.
        let s = MountStep {
            order: 1,
            source: "/dev/sda1".into(),
            fstype: "ext4".into(),
            target: PathBuf::from("/run/catos-system/sessions/abc/target"),
            options: vec!["ro".into(), "noload".into(), "nosuid".into()],
            rationale: "root fs".into(),
            depends_on: vec![],
            failure_modes: vec![],
            evidence: vec![],
        };
        assert_eq!(s.options_string(), "ro,noload,nosuid");
    }

    #[test]
    fn mount_error_kind_code_matches_serde_variant() {
        // The `code()` method and the serde rename must agree. If they
        // drift, downstream tooling keyed on the JSON code breaks.
        for kind in [
            MountErrorKind::CapabilityMissing,
            MountErrorKind::NamespaceUnavailable,
            MountErrorKind::UnsafeReadOnlyMode,
            MountErrorKind::AmbiguousRootCandidate,
            MountErrorKind::CleanupIncomplete,
        ] {
            let j = serde_json::to_string(&kind).unwrap();
            let s = j.trim_matches('"');
            assert_eq!(kind.code(), s, "serde/code drift for {kind:?}");
        }
    }

    #[test]
    fn namespace_state_default_is_host_namespace_refused() {
        // Safety: the default MUST be "refused", never "private". A
        // session that defaults to host namespace silently would
        // contaminate the caller's mount table.
        assert_eq!(
            NamespaceState::default(),
            NamespaceState::HostNamespaceRefused
        );
    }

    #[test]
    fn mount_session_state_default_is_ready() {
        assert_eq!(MountSessionState::default(), MountSessionState::Ready);
    }
}
