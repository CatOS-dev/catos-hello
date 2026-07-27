//! Trusted write-only btrfs-progs snapshot creation.
//!
//! The public functions expose fixed operations; callers cannot select an
//! arbitrary btrfs subcommand or supply shell text.

use std::path::Path;
use std::time::Duration;

use crate::shared::process::run_trusted_tool;
use crate::snapshot::model::{SnapshotError, SnapshotErrorKind};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

pub fn create_readonly_snapshot(src: &Path, dst: &Path) -> Result<(), SnapshotError> {
    run_snapshot(true, src, dst)
}

pub fn create_writable_snapshot(src: &Path, dst: &Path) -> Result<(), SnapshotError> {
    run_snapshot(false, src, dst)
}

fn run_snapshot(readonly: bool, src: &Path, dst: &Path) -> Result<(), SnapshotError> {
    let src = path_to_str(src)?;
    let dst = path_to_str(dst)?;
    let args: Vec<&str> = if readonly {
        vec!["subvolume", "snapshot", "-r", src.as_str(), dst.as_str()]
    } else {
        vec!["subvolume", "snapshot", src.as_str(), dst.as_str()]
    };
    let output = run_trusted_tool(
        "btrfs",
        &args,
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        MAX_OUTPUT_BYTES,
    )
    .map_err(|message| {
        let mut error = SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!("btrfs subvolume snapshot failed: {message}"),
        );
        error.failed_step = Some("btrfs-subvolume-snapshot".into());
        error
    })?;
    if output.success() {
        return Ok(());
    }
    Err(SnapshotError {
        kind: SnapshotErrorKind::BtrfsToolFailed,
        message: format!(
            "btrfs subvolume snapshot exited non-zero (rc={}): stdout={:?} stderr={:?}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        )
        .into(),
        transaction_id: None,
        current_state: None,
        failed_step: Some("btrfs-subvolume-snapshot".into()),
        errno: None,
        external_exit_code: output.status.code(),
        completed_steps: Box::default(),
        disk_facts: None,
        resume_possible: true,
        revert_possible: true,
        manual_intervention_required: false,
        record_persistence_error: None,
    })
}

fn path_to_str(path: &Path) -> Result<String, SnapshotError> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        SnapshotError::new(
            SnapshotErrorKind::BtrfsToolFailed,
            format!("path {} is not valid UTF-8", path.display()),
        )
    })
}
