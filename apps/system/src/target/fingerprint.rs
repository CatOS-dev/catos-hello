//! Target status fingerprint + pre/post identity verification.

use crate::target::model::TargetIdentity;

/// A digest-style fingerprint computed from a target's stable identifying
/// fields. Used to detect "the target changed between plan and apply".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetFingerprint {
    pub root_device: Option<String>,
    pub root_uuid: Option<String>,
    pub root_fstype: Option<String>,
}

impl TargetFingerprint {
    /// Compute a fingerprint from an identity snapshot.
    pub fn from_identity(identity: &TargetIdentity) -> Self {
        TargetFingerprint {
            root_device: identity
                .root_device
                .as_deref()
                .map(|p| p.to_string_lossy().into_owned()),
            root_uuid: identity.root_uuid.clone(),
            root_fstype: identity.root_fstype.clone(),
        }
    }

    /// Two fingerprints match iff every present field agrees.
    pub fn matches(&self, other: &TargetFingerprint) -> bool {
        self == other
    }
}
