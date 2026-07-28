//! Host-side fixture generator for the Doctor QEMU acceptance test.
//!
//! This is not installed. It serialises one valid, non-terminal recovery
//! record through the production snapshot store API before the root tree is
//! packed into a Btrfs image.

use std::path::PathBuf;

use catos_system::boot::diagnose::layout::evaluate_readonly_consistency;
use catos_system::boot::model::BootLayout;
use catos_system::snapshot::model::{
    BtrfsFilesystemIdentity, BtrfsSubvolumeIdentity, CatosIdentity, FstabRootDefinition,
    RecoveryPlan, TransactionRecord, TransactionState, RECOVERY_PLAN_SCHEMA_VERSION,
    TX_RECORD_SCHEMA_VERSION,
};
use catos_system::snapshot::plan::{build_confirmation_token, effective_plan_digest};
use catos_system::snapshot::store;

const TRANSACTION_ID: &str = "tx-00000000000000000000000000000004";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("missing root tree path")?);
    let fsid = args
        .next()
        .ok_or("missing filesystem UUID")?
        .into_string()
        .map_err(|_| "filesystem UUID is not UTF-8")?;
    let major_minor = args
        .next()
        .ok_or("missing expected major:minor")?
        .into_string()
        .map_err(|_| "major:minor is not UTF-8")?;
    let current_root_id = args
        .next()
        .ok_or("missing current root subvolume ID")?
        .into_string()
        .map_err(|_| "current root subvolume ID is not UTF-8")?
        .parse::<u64>()?;
    let current_root_generation = args
        .next()
        .ok_or("missing current root generation")?
        .into_string()
        .map_err(|_| "current root generation is not UTF-8")?
        .parse::<u64>()?;
    let current_root_uuid = args
        .next()
        .ok_or("missing current root UUID")?
        .into_string()
        .map_err(|_| "current root UUID is not UTF-8")?;
    let source_snapshot_id = args
        .next()
        .ok_or("missing source snapshot subvolume ID")?
        .into_string()
        .map_err(|_| "source snapshot subvolume ID is not UTF-8")?
        .parse::<u64>()?;
    let source_snapshot_generation = args
        .next()
        .ok_or("missing source snapshot generation")?
        .into_string()
        .map_err(|_| "source snapshot generation is not UTF-8")?
        .parse::<u64>()?;
    let source_snapshot_uuid = args
        .next()
        .ok_or("missing source snapshot UUID")?
        .into_string()
        .map_err(|_| "source snapshot UUID is not UTF-8")?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }

    let boot_layout = BootLayout::default();
    let mut plan = RecoveryPlan {
        schema_version: RECOVERY_PLAN_SCHEMA_VERSION,
        plan_id: TRANSACTION_ID.into(),
        generated_at_unix: 1,
        generated_on_host: Some("doctor-qemu-fixture".into()),
        filesystem: BtrfsFilesystemIdentity {
            fsid: fsid.clone(),
            device_major_minor: major_minor,
            label: Some("catos-doctor-interrupted".into()),
        },
        current_root: BtrfsSubvolumeIdentity {
            path: "/@".into(),
            subvolume_id: current_root_id,
            generation: current_root_generation,
            uuid: Some(current_root_uuid),
            parent_uuid: None,
            read_only: false,
            evidence: Vec::new(),
        },
        source_snapshot: BtrfsSubvolumeIdentity {
            path: "/@snapshot-source".into(),
            subvolume_id: source_snapshot_id,
            generation: source_snapshot_generation,
            uuid: Some(source_snapshot_uuid),
            parent_uuid: None,
            read_only: true,
            evidence: Vec::new(),
        },
        target_catos_identity: Some(CatosIdentity::default()),
        boot_consistency: evaluate_readonly_consistency(&boot_layout),
        boot_layout,
        backup_root_path: format!("/.catos-recovery/backups/{TRANSACTION_ID}/root-before"),
        staging_root_path: format!("/.catos-recovery/staging/{TRANSACTION_ID}/new-root"),
        fstab_root_definition: FstabRootDefinition {
            source: format!("UUID={fsid}"),
            fstype: "btrfs".into(),
            options: vec!["defaults".into(), "subvol=/@".into()],
        },
        predicted_steps: Vec::new(),
        refusal_conditions: Vec::new(),
        risks_and_warnings: Vec::new(),
        nonce: "00".repeat(32),
        plan_digest: String::new(),
        confirmation_token: String::new(),
        evidence: Vec::new(),
    };
    plan.plan_digest = effective_plan_digest(&plan).map_err(|error| error.to_string())?;
    plan.confirmation_token =
        build_confirmation_token(&plan.plan_id, &plan.plan_digest, &plan.nonce);

    let record = TransactionRecord {
        schema_version: TX_RECORD_SCHEMA_VERSION,
        transaction_id: TRANSACTION_ID.into(),
        created_at_unix: 1,
        last_updated_unix: 1,
        plan,
        state: TransactionState::Planned,
        completed_steps: Vec::new(),
        last_error: None,
        last_disk_facts: None,
        last_cleanup: None,
    };
    let state_path = root
        .join(".catos-recovery/transactions")
        .join(TRANSACTION_ID)
        .join("state.json");
    store::persist_record(&state_path, &record).map_err(|error| error.to_string())?;
    println!("{}", state_path.display());
    Ok(())
}
