//! Explicit snapshot rollback confirmation binding.

use sha2::{Digest, Sha256};

use crate::model::SnapshotError;
use crate::plan::recover::hex_encode;

/// Build the explicit-revert confirmation token. Unlike the apply
/// token, this token is bound to the transaction's current state and
/// the freshly observed filesystem FSID, so a token copied from an
/// earlier status response cannot authorize a later or different
/// revert.
pub fn build_revert_confirmation_token(
    transaction_id: &str,
    plan_digest: &str,
    filesystem_fsid: &str,
    state: &str,
    nonce: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"catos-recovery-revert-confirmation-v1\0");
    digest.update(transaction_id.as_bytes());
    digest.update(b"\0");
    digest.update(plan_digest.as_bytes());
    digest.update(b"\0");
    digest.update(filesystem_fsid.as_bytes());
    digest.update(b"\0");
    digest.update(state.as_bytes());
    digest.update(b"\0");
    digest.update(nonce.as_bytes());
    format!(
        "revert-v1:{transaction_id}:{}",
        hex_encode(&digest.finalize())
    )
}

pub fn verify_revert_confirmation_token(
    transaction_id: &str,
    plan_digest: &str,
    filesystem_fsid: &str,
    state: &str,
    nonce: &str,
    presented: &str,
) -> Result<(), SnapshotError> {
    let expected =
        build_revert_confirmation_token(transaction_id, plan_digest, filesystem_fsid, state, nonce);
    if presented != expected {
        return Err(SnapshotError::new(
            crate::model::SnapshotErrorKind::ConfirmationTokenMismatch,
            "revert confirmation token is not bound to the current transaction state",
        ));
    }
    Ok(())
}
