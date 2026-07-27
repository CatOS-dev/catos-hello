//! Post-action verification hook. Re-reads target state and confirms the
//! identity fingerprint has not drifted.

use crate::fingerprint::TargetFingerprint;
use crate::model::TargetIdentity;

/// Outcome of a verify pass.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// Observed fingerprint matches the planned one.
    Consistent,
    /// Observed fingerprint differs from the planned one. The target
    /// changed between plan and verify; the caller MUST abort.
    Drift {
        planned: TargetFingerprint,
        observed: TargetFingerprint,
    },
}

/// Verify that `observed` matches `planned`. Pure function so it can be
/// unit-tested without I/O.
pub fn verify_identity(planned: &TargetIdentity, observed: &TargetIdentity) -> VerifyOutcome {
    let planned_fp = TargetFingerprint::from_identity(planned);
    let observed_fp = TargetFingerprint::from_identity(observed);
    if planned_fp.matches(&observed_fp) {
        VerifyOutcome::Consistent
    } else {
        VerifyOutcome::Drift {
            planned: planned_fp,
            observed: observed_fp,
        }
    }
}
