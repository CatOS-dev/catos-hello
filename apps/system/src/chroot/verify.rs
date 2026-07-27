//! Read-only validation of an assembled Chroot target.

use std::path::Path;

use crate::chroot::model::ChrootVerification;
use crate::shared::error::FsError;
use crate::target::execute::confined::{read_rooted_file, rooted_regular_file_size};

pub fn verify_target_root(root: &Path) -> ChrootVerification {
    let mut checks = Vec::new();
    let mut reasons = Vec::new();

    let identity = ["/usr/lib/os-release", "/etc/os-release"]
        .into_iter()
        .find_map(|path| match rooted_regular_file_size(root, path) {
            Ok(Some(_)) => match read_rooted_file(root, path) {
                Ok(bytes) if !bytes.is_empty() => Some(path.to_string()),
                Ok(_) => None,
                Err(error) => {
                    reasons.push(format!("cannot read target {path}: {error}"));
                    None
                }
            },
            Ok(None) | Err(FsError::NotFound) => None,
            Err(error) => {
                reasons.push(format!("cannot inspect target {path}: {error}"));
                None
            }
        });
    if let Some(path) = identity {
        checks.push(format!("target identity: {path}"));
    } else if !reasons.iter().any(|reason| reason.contains("os-release")) {
        reasons.push("target os-release was not found".into());
    }

    let shell = ["/usr/bin/bash", "/usr/bin/sh"]
        .into_iter()
        .find_map(|path| match rooted_regular_file_size(root, path) {
            Ok(Some(_)) => Some(path.to_string()),
            Ok(None) | Err(FsError::NotFound) => None,
            Err(error) => {
                reasons.push(format!("cannot inspect target shell {path}: {error}"));
                None
            }
        });
    if let Some(path) = shell {
        checks.push(format!("target shell: {path}"));
    } else if !reasons.iter().any(|reason| reason.contains("target shell")) {
        reasons.push("target shell was not found under /usr/bin".into());
    }

    ChrootVerification {
        ready: reasons.is_empty(),
        checks,
        reasons,
    }
}
