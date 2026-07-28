//! Secure Boot finalisation. Port of `secureboot.py` from the
//! bootloadu Calamares module.
//!
//! ## Hard rules (per spec)
//!
//! * Repair **never auto-enables** Secure Boot just because the live
//!   host has it on. The target's own policy is the only authority.
//! * Repair **never silently disables** Secure Boot.
//! * When the target's existing policy is detected from the persisted
//!   `catos-secureboot` state record and complete machine key material, repair
//!   may re-apply that existing policy by invoking
//!   `catos-secureboot enable --generate-enrollment-password --json`.
//! * EFI variable writes, MOK enrollment, and signing operations are
//!   NOT atomic. Partial success MUST surface as
//!   [`crate::model::BootRepairOutcome::PartiallyRepaired`]
//!   or
//!   [`crate::model::BootRepairOutcome::ManualInterventionRequired`],
//!   never as `Repaired`.
//! * Secure Boot finalisation runs AFTER the regular boot files are
//!   written and cleanup is in a safe state, mirroring bootloadu's
//!   two-phase order (install first, secureboot second).
//! * EFI Stub is explicitly unsupported: the registry's
//!   `supportedProviders` list omits it. We refuse before invoking
//!   `catos-secureboot`.

use crate::execute::target::{TargetRequest, TargetRunner};
use crate::model::{
    BootRepairOutcome, ProviderId, SecureBootReport, SensitiveString, TargetCommandResult,
};
use crate::plan::registry;

/// Inputs the orchestrator supplies. All filesystem facts are
/// observed through the confined target reader; this module does no
/// I/O.
#[derive(Debug, Clone, Default)]
pub struct SecureBootInputs {
    /// The provider currently selected for boot repair. Secure Boot
    /// is refused for EFI Stub.
    pub provider: ProviderId,
    /// Whether the target contains a valid persisted CatOS Secure Boot
    /// state record and complete machine key material. The package config
    /// alone is never policy evidence.
    pub target_policy_present: bool,
    /// Target path configured by `catos-secureboot` for persisting the
    /// one-time MokManager enrollment password.
    pub enrollment_password_path: String,
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
    if !inputs.target_policy_present {
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
                target_policy_present: inputs.target_policy_present,
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
            let payload = String::from_utf8_lossy(&result.stdout).into_owned();
            let audited_result = redact_secure_boot_stdout(result, &payload);
            if audited_result.binary_missing
                || audited_result.timed_out
                || audited_result.exit_code != 0
            {
                let failure = format!(
                    "catos-secureboot enable failed (exit={}, missing={}, timeout={})",
                    audited_result.exit_code,
                    audited_result.binary_missing,
                    audited_result.timed_out
                );
                return (
                    SecureBootReport {
                        target_policy_present: true,
                        enable_invoked: true,
                        ambiguous: false,
                        failure_message: Some(failure),
                        raw_payload: sanitise_payload(&payload),
                        ..SecureBootReport::default()
                    },
                    Some(BootRepairOutcome::ManualInterventionRequired),
                    Some(audited_result),
                );
            }
            match parse_secure_boot_payload(&payload) {
                Ok(parsed) => {
                    let password_generated = parsed.enrollment_password.is_some();
                    let password_path =
                        password_generated.then(|| inputs.enrollment_password_path.clone());
                    let outcome = parsed
                        .enrollment_pending
                        .then_some(BootRepairOutcome::PartiallyRepaired);
                    (
                        SecureBootReport {
                            target_policy_present: true,
                            enable_invoked: true,
                            certificate_fingerprint: parsed.fingerprint,
                            enrollment_pending: parsed.enrollment_pending,
                            enrollment_password_generated: password_generated,
                            enrollment_password_path: password_path,
                            enrollment_password: parsed
                                .enrollment_password
                                .map(SensitiveString::new),
                            raw_payload: sanitise_payload(&payload),
                            ..SecureBootReport::default()
                        },
                        outcome,
                        Some(audited_result),
                    )
                }
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
                    Some(audited_result),
                ),
            }
        }
    }
}

/// Result of parsing the `catos-secureboot --json` payload.
struct ParsedPayload {
    fingerprint: Option<String>,
    enrollment_pending: bool,
    enrollment_password: Option<String>,
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
    if !crate::diagnose::target::certificate_fingerprint_is_valid(fingerprint) {
        return Err("catos-secureboot returned an invalid SHA-256 certificate fingerprint".into());
    }
    let enrollment_pending = object
        .get("enrollment_pending")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| "catos-secureboot did not report enrollment state".to_string())?;
    let enrollment_password = object
        .get("enrollment_password")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    if let Some(password) = enrollment_password.as_deref() {
        if !generated_enrollment_password_is_valid(password) {
            return Err("catos-secureboot returned an invalid generated enrollment password".into());
        }
    }
    if enrollment_pending && enrollment_password.is_none() {
        return Err(
            "catos-secureboot reported pending enrollment without a one-time password".into(),
        );
    }
    if !enrollment_pending && enrollment_password.is_some() {
        return Err(
            "catos-secureboot returned an enrollment password without pending enrollment".into(),
        );
    }
    Ok(ParsedPayload {
        fingerprint: Some(fingerprint.to_string()),
        enrollment_pending,
        enrollment_password,
    })
}

fn generated_enrollment_password_is_valid(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn redact_secure_boot_stdout(
    mut result: TargetCommandResult,
    payload: &str,
) -> TargetCommandResult {
    result.stdout = if payload.trim().is_empty() {
        Vec::new()
    } else if let Some(sanitised) = sanitise_payload(payload) {
        sanitised.into_bytes()
    } else {
        br#"{"redacted":true,"reason":"unparseable catos-secureboot output"}"#.to_vec()
    };
    result
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
    use crate::execute::target::RecordedTargetRunner;

    const FINGERPRINT: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn inputs(provider: ProviderId) -> SecureBootInputs {
        SecureBootInputs {
            provider,
            target_policy_present: false,
            enrollment_password_path: "/var/lib/catos-secureboot/enrollment-password".into(),
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
        inputs.target_policy_present = true;
        let decision = should_finalize(&inputs);
        assert_eq!(decision, FinalizeDecision::Unsupported);
    }

    #[test]
    fn efistub_secureboot_unsupported_requires_human_action() {
        let runner = RecordedTargetRunner::new();
        let mut inputs = inputs(ProviderId::Efistub);
        inputs.target_policy_present = true;
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
    fn persisted_target_policy_authorises_reapply() {
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_policy_present: true,
            ..SecureBootInputs::default()
        };
        assert_eq!(should_finalize(&inputs), FinalizeDecision::Reapply);
    }

    #[test]
    fn pending_enrollment_reports_password_but_redacts_command_audit() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-secureboot",
            ["enable", "--generate-enrollment-password", "--json"],
            0,
            format!(
                r#"{{"fingerprint":"{FINGERPRINT}","enrollment_pending":true,"enrollment_password":"SEKRET1234"}}"#
            )
            .into_bytes(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_policy_present: true,
            enrollment_password_path: "/var/lib/catos-secureboot/enrollment-password".into(),
            ..SecureBootInputs::default()
        };
        let (report, outcome, action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, Some(BootRepairOutcome::PartiallyRepaired));
        assert!(report.enable_invoked);
        assert_eq!(report.certificate_fingerprint.as_deref(), Some(FINGERPRINT));
        assert!(report.enrollment_pending);
        assert!(report.enrollment_password_generated);
        assert_eq!(report.enrollment_password.as_deref(), Some("SEKRET1234"));
        assert_eq!(
            report.enrollment_password_path.as_deref(),
            Some("/var/lib/catos-secureboot/enrollment-password")
        );
        assert!(!report
            .raw_payload
            .as_deref()
            .unwrap_or_default()
            .contains("SEKRET1234"));
        let action = action.expect("secure boot command action");
        let audited_stdout = String::from_utf8(action.stdout).unwrap();
        assert!(!audited_stdout.contains("SEKRET1234"));
        assert!(audited_stdout.contains("fingerprint"));
        assert!(runner.invoked_binary("catos-secureboot"));
        runner.assert_consumed();
    }

    #[test]
    fn enrollment_password_and_pending_state_must_be_consistent() {
        let missing = match parse_secure_boot_payload(
            r#"{"fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enrollment_pending":true}"#,
        ) {
            Ok(_) => panic!("pending enrollment without a password was accepted"),
            Err(error) => error,
        };
        assert!(missing.contains("without a one-time password"));

        let unexpected = match parse_secure_boot_payload(
            r#"{"fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","enrollment_pending":false,"enrollment_password":"SEKRET1234"}"#,
        ) {
            Ok(_) => panic!("a password without pending enrollment was accepted"),
            Err(error) => error,
        };
        assert!(unexpected.contains("without pending enrollment"));
    }

    #[test]
    fn malformed_fingerprint_or_generated_password_is_rejected() {
        let fingerprint = match parse_secure_boot_payload(
            r#"{"fingerprint":"AA:BB","enrollment_pending":false}"#,
        ) {
            Ok(_) => panic!("malformed fingerprint was accepted"),
            Err(error) => error,
        };
        assert!(fingerprint.contains("invalid SHA-256"));

        let password = match parse_secure_boot_payload(&format!(
            r#"{{"fingerprint":"{FINGERPRINT}","enrollment_pending":true,"enrollment_password":"bad\nvalue"}}"#
        )) {
            Ok(_) => panic!("malformed generated password was accepted"),
            Err(error) => error,
        };
        assert!(password.contains("invalid generated enrollment password"));
    }

    #[test]
    fn failed_reapply_reports_manual_intervention() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-secureboot",
            ["enable", "--generate-enrollment-password", "--json"],
            2,
            b"",
            b"enroll failed",
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_policy_present: true,
            ..SecureBootInputs::default()
        };
        let (report, outcome, action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, Some(BootRepairOutcome::ManualInterventionRequired));
        assert!(report.enable_invoked);
        assert!(report.failure_message.is_some());
        assert!(action.is_some());
        runner.assert_consumed();
    }

    #[test]
    fn missing_fingerprint_in_payload_reports_manual_intervention() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-secureboot",
            ["enable", "--generate-enrollment-password", "--json"],
            0,
            br#"{"enrollment_pending":true}"#.to_vec(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_policy_present: true,
            ..SecureBootInputs::default()
        };
        let (_report, outcome, _action) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, Some(BootRepairOutcome::ManualInterventionRequired));
        runner.assert_consumed();
    }

    #[test]
    fn argv_for_enable_is_fixed() {
        let runner = RecordedTargetRunner::new().expect_raw(
            "catos-secureboot",
            ["enable", "--generate-enrollment-password", "--json"],
            0,
            format!(r#"{{"fingerprint":"{FINGERPRINT}","enrollment_pending":false}}"#).into_bytes(),
            b"".to_vec(),
        );
        let inputs = SecureBootInputs {
            provider: ProviderId::Grub,
            target_policy_present: true,
            ..SecureBootInputs::default()
        };
        let (report, outcome, _) = finalize_secure_boot(&runner, &inputs);
        assert_eq!(outcome, None);
        assert!(!report.enrollment_pending);
        assert!(!report.enrollment_password_generated);
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
        runner.assert_consumed();
    }
}
