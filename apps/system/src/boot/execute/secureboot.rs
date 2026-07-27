//! Secure Boot finalisation. Port of `secureboot.py` from the
//! bootloadu Calamares module.
//!
//! ## Hard rules (per spec)
//!
//! * Repair **never auto-enables** Secure Boot just because the live
//!   host has it on. The target's own policy is the only authority.
//! * Repair **never silently disables** Secure Boot.
//! * When the target's existing policy is detected (e.g. previously
//!   enrolled CatOS certificate, signed bootloader artefact, or the
//!   `catos-secureboot` package + a configuration marker), repair
//!   may re-apply that existing policy by invoking
//!   `catos-secureboot enable --generate-enrollment-password --json`.
//! * EFI variable writes, MOK enrollment, and signing operations are
//!   NOT atomic. Partial success MUST surface as
//!   [`crate::boot::model::BootRepairOutcome::PartiallyRepaired`]
//!   or
//!   [`crate::boot::model::BootRepairOutcome::ManualInterventionRequired`],
//!   never as `Repaired`.
//! * Secure Boot finalisation runs AFTER the regular boot files are
//!   written and cleanup is in a safe state, mirroring bootloadu's
//!   two-phase order (install first, secureboot second).
//! * EFI Stub is explicitly unsupported: the registry's
//!   `supportedProviders` list omits it. We refuse before invoking
//!   `catos-secureboot`.

use crate::boot::execute::target::{TargetRequest, TargetRunner};
use crate::boot::model::{BootRepairOutcome, ProviderId, SecureBootReport, TargetCommandResult};
use crate::boot::plan::registry;

/// Inputs the orchestrator supplies. All filesystem facts are
/// observed through the confined target reader; this module does no
/// I/O.
#[derive(Debug, Clone, Default)]
pub struct SecureBootInputs {
    /// The provider currently selected for boot repair. Secure Boot
    /// is refused for EFI Stub.
    pub provider: ProviderId,
    /// Whether the target's `/etc/catos/secureboot` marker exists
    /// (bootloadu writes it when `catos-secureboot enable` has been
    /// invoked at least once).
    pub target_marker_present: bool,
    /// Whether the target's pacman DB reports the
    /// `catos-secureboot` package.
    pub package_present: bool,
    /// Whether a signed bootloader artefact was observed on the
    /// target ESP (corroborating evidence; not authoritative alone).
    pub signed_artefact_observed: bool,
    /// Verbatim payload (stdout) captured from `catos-secureboot`
    /// when the orchestrator replayed a previous result for
    /// resumption. `None` for a fresh invocation.
    pub previous_payload: Option<String>,
}

/// Decide whether to invoke `catos-secureboot enable` based on the
/// target's existing policy. Mirrors bootloadu's
/// `prepare_secure_boot` decision but inverted: the live host's
/// `/sys/firmware/efi/efivars/SecureBoot-*` value is NEVER consulted
/// for the target. Only target-side evidence is.
pub fn should_finalize(inputs: &SecureBootInputs) -> FinalizeDecision {
    // Target policy is "present" when bootloadu has previously
    // enrolled a CatOS certificate. We treat the marker as
    // authoritative; the package + signed artefact are corroborating.
    let target_policy_present =
        inputs.target_marker_present || (inputs.package_present && inputs.signed_artefact_observed);
    if !target_policy_present {
        return FinalizeDecision::LeaveUntouched;
    }
    if !registry::secure_boot_supported(inputs.provider) {
        return FinalizeDecision::Unsupported;
    }
    FinalizeDecision::Reapply
}

/// What the orchestrator should do about Secure Boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeDecision {
    /// Re-apply the existing target policy by invoking
    /// `catos-secureboot enable --generate-enrollment-password --json`.
    Reapply,
    /// Target has no existing CatOS Secure Boot policy. Repair does
    /// NOT enable one silently.
    LeaveUntouched,
    /// Provider does not support automatic Secure Boot setup (EFI
    /// Stub). The orchestrator refuses with
    /// [`BootRepairOutcome::Unsupported`] when this is the only
    /// reason; otherwise it leaves Secure Boot alone.
    Unsupported,
}

/// Run Secure Boot finalisation through the target runner. Returns
/// the structured [`SecureBootReport`] and updates the outcome.
///
/// When [`should_finalize`] returns `LeaveUntouched` or
/// `Unsupported`, no command is invoked and the report records the
/// decision without claiming any side effect.
pub fn finalize_secure_boot<R: TargetRunner>(
    runner: &R,
    inputs: &SecureBootInputs,
) -> (
    SecureBootReport,
    Option<BootRepairOutcome>,
    Option<TargetCommandResult>,
) {
    let decision = should_finalize(inputs);
    match decision {
        FinalizeDecision::LeaveUntouched => (
            SecureBootReport {
                target_policy_present: false,
                enable_invoked: false,
                ambiguous: false,
                ..SecureBootReport::default()
            },
            None,
            None,
        ),
        FinalizeDecision::Unsupported => (
            SecureBootReport {
                target_policy_present: inputs.target_marker_present,
                enable_invoked: false,
                ambiguous: false,
                failure_message: Some(format!(
                    "{} does not support automatic Secure Boot setup",
                    inputs.provider.as_str()
                )),
                ..SecureBootReport::default()
            },
            Some(BootRepairOutcome::ManualInterventionRequired),
            None,
        ),
        FinalizeDecision::Reapply => {
            let request = TargetRequest::new(
                "catos-secureboot",
                vec![
                    "enable".into(),
                    "--generate-enrollment-password".into(),
                    "--json".into(),
                ],
                "re-apply existing CatOS Secure Boot policy",
            );
            let result = runner.invoke(&request);
            if result.binary_missing || result.timed_out || result.exit_code != 0 {
                let failure = format!(
                    "catos-secureboot enable failed (exit={}, missing={}, timeout={})",
                    result.exit_code, result.binary_missing, result.timed_out
                );
                return (
                    SecureBootReport {
                        target_policy_present: true,
                        enable_invoked: true,
                        ambiguous: false,
                        failure_message: Some(failure),
                        raw_payload: sanitise_payload(&String::from_utf8_lossy(&result.stdout)),
                        ..SecureBootReport::default()
                    },
                    Some(BootRepairOutcome::ManualInterventionRequired),
                    Some(result),
                );
            }
            let payload = String::from_utf8_lossy(&result.stdout).into_owned();
            match parse_secure_boot_payload(&payload) {
                Ok(parsed) => (
                    SecureBootReport {
                        target_policy_present: true,
                        enable_invoked: true,
                        certificate_fingerprint: parsed.fingerprint,
                        enrollment_pending: parsed.enrollment_pending,
                        raw_payload: sanitise_payload(&payload),
                        ..SecureBootReport::default()
                    },
                    None,
                    Some(result),
                ),
                Err(reason) => (
                    SecureBootReport {
                        target_policy_present: true,
                        enable_invoked: true,
                        ambiguous: true,
                        failure_message: Some(reason),
                        raw_payload: sanitise_payload(&payload),
                        ..SecureBootReport::default()
                    },
                    Some(BootRepairOutcome::ManualInterventionRequired),
                    Some(result),
                ),
            }
        }
    }
}

/// Result of parsing the `catos-secureboot --json` payload.
struct ParsedPayload {
    fingerprint: Option<String>,
    enrollment_pending: bool,
}

/// Parse the JSON payload `catos-secureboot enable` returns. Uses
/// serde_json directly (already a runtime dependency) rather than a
/// fragile substring search.
fn parse_secure_boot_payload(payload: &str) -> Result<ParsedPayload, String> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Err("catos-secureboot returned an empty payload".into());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|error| format!("catos-secureboot returned invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "catos-secureboot returned a non-object JSON payload".to_string())?;
    let fingerprint = object
        .get("fingerprint")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "catos-secureboot did not return a certificate fingerprint".to_string())?;
    let enrollment_pending = object
        .get("enrollment_pending")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| "catos-secureboot did not report enrollment state".to_string())?;
    Ok(ParsedPayload {
        fingerprint: Some(fingerprint.to_string()),
        enrollment_pending,
    })
}

fn sanitise_payload(payload: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let object = value.as_object_mut()?;
    object.retain(|key, _| {
        let key = key.to_ascii_lowercase();
        !key.contains("password") && !key.contains("secret") && !key.contains("token")
    });
    serde_json::to_string(&value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::execute::target::RecordedTargetRunner;

    fn inputs(provider: ProviderId) -> SecureBootInputs {
        SecureBootInputs {
            provider,
            target_marker_present: false,
            package_present: false,
            signed_artefact_observed: false,
            previous_payload: None,
        }
    }

    #[test]
    fn efistub_without_target_policy_is_left_untouched() {
        let decision = should_finalize(&inputs(ProviderId::Efistub));
        assert_eq!(decision, FinalizeDecision::LeaveUntouched);
    }

    #[test]
    fn efistub_with_target_policy_is_unsupported() {
        let mut inputs = inputs(ProviderId::Efistub);
        inputs.target_marker_present = true;
        let decision = should_finalize(&inputs);
        assert_eq!(decision, FinalizeDecision::Unsupported);
    }

    #[test]
    fn efistub_secureboot_unsupported_requires_human_action() {
        let runner = RecordedTargetRunner::new();
        let mut inputs = inputs(ProviderId::Efistub);
        inputs.target_marker_present = true;
        let (report, outcome, action) = finalize_secure_boot(&runner, &inputs);

        assert!(!report.enable_invoked);
        assert_eq!(outcome, Some(BootRepairOutcome::ManualInterventionRequired));
        assert!(action.is_none());
    }

    #[test]
    fn grub_without_target_policy_is_left_untouched() {
        let decision = should_finalize(&inputs(ProviderId::Grub));
        assert_eq!(decision, FinalizeDecision::LeaveUntouched);
    }

    #[test]
    fn target_marker_authorises_reapply() {
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_marker_present: true,
            ..SecureBootInputs::default()
        };
        assert_eq!(should_finalize(&inputs), FinalizeDecision::Reapply);
    }

    #[test]
    fn package_plus_signed_artefact_authorises_reapply() {
        let inputs = SecureBootInputs {
            provider: ProviderId::Uki,
            package_present: true,
            signed_artefact_observed: true,
            ..SecureBootInputs::default()
        };
        assert_eq!(should_finalize(&inputs), FinalizeDecision::Reapply);
    }

    #[test]
    fn package_alone_does_not_authorise_reapply() {
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            package_present: true,
            ..SecureBootInputs::default()
        };
        assert_eq!(should_finalize(&inputs), FinalizeDecision::LeaveUntouched);
    }

    #[test]
    fn successful_reapply_records_fingerprint_and_pending() {
        let runner = RecordedTargetRunner::new().queue_raw(
            0,
            br#"{"fingerprint":"AA:BB","enrollment_pending":true,"enrollment_password":"sekret"}"#
                .to_vec(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_marker_present: true,
            ..SecureBootInputs::default()
        };
        let (report, outcome, action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, None);
        assert!(report.enable_invoked);
        assert_eq!(report.certificate_fingerprint.as_deref(), Some("AA:BB"));
        assert!(report.enrollment_pending);
        assert!(action.is_some());
        assert!(!report
            .raw_payload
            .as_deref()
            .unwrap_or_default()
            .contains("sekret"));
        assert!(runner.invoked_binary("catos-secureboot"));
    }

    #[test]
    fn failed_reapply_reports_manual_intervention() {
        let runner =
            RecordedTargetRunner::new().queue_raw(2, b"".to_vec(), b"enroll failed".to_vec());
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_marker_present: true,
            ..SecureBootInputs::default()
        };
        let (report, outcome, action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, Some(BootRepairOutcome::ManualInterventionRequired));
        assert!(report.enable_invoked);
        assert!(report.failure_message.is_some());
        assert!(action.is_some());
    }

    #[test]
    fn missing_fingerprint_in_payload_reports_manual_intervention() {
        let runner = RecordedTargetRunner::new().queue_raw(
            0,
            br#"{"enrollment_pending":true}"#.to_vec(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_marker_present: true,
            ..SecureBootInputs::default()
        };
        let (_report, outcome, _action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, Some(BootRepairOutcome::ManualInterventionRequired));
    }

    #[test]
    fn argv_for_enable_is_fixed() {
        let runner = RecordedTargetRunner::new().queue_raw(
            0,
            br#"{"fingerprint":"AA:BB","enrollment_pending":false}"#.to_vec(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_marker_present: true,
            ..SecureBootInputs::default()
        };
        let _ = finalize_secure_boot(&runner, &inputs);
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].binary, "catos-secureboot");
        assert_eq!(
            invocations[0].argv,
            vec![
                "enable".to_string(),
                "--generate-enrollment-password".to_string(),
                "--json".to_string(),
            ]
        );
    }
}
