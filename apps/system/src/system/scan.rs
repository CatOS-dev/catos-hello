use super::target::read_target_fstab;
use super::util::merge_warnings;
use super::SystemCommandOutcome;
use std::collections::HashSet;

use crate::error::Error;
use crate::mount::plan::session::probe_unmounted_candidates;
use crate::target::diagnose::block::discover_devices;
use crate::target::diagnose::candidate::candidate_ambiguities;
use crate::target::diagnose::candidate::identify_candidates;
use crate::target::diagnose::filesystem::RealFilesystem;
use crate::target::diagnose::system_root::SystemRoot;
use crate::target::model::StorageReport;
use crate::target::model::Warning;

pub fn run_storage_scan(root: &SystemRoot) -> Result<SystemCommandOutcome, Error> {
    let fs = RealFilesystem;
    let (devices, mut dev_warnings) = discover_devices(&fs);
    let fstab = match read_target_fstab(root) {
        Ok((entries, mut warnings)) => {
            dev_warnings.append(&mut warnings);
            entries
        }
        Err(error) => {
            dev_warnings.push(Warning::new(
                "TARGET_FSTAB_UNREADABLE",
                format!("could not read target fstab: {error}"),
            ));
            Vec::new()
        }
    };
    let (mut root_candidates, mut esp_candidates, _, cand_warnings) =
        identify_candidates(&devices, &fstab);
    let mut probed = probe_unmounted_candidates(&devices, &fstab);

    let probed_root_sources: HashSet<&str> = probed
        .roots
        .iter()
        .map(|candidate| candidate.source.as_str())
        .collect();
    root_candidates.retain(|candidate| !probed_root_sources.contains(candidate.source.as_str()));
    root_candidates.append(&mut probed.roots);

    let probed_esp_sources: HashSet<&str> = probed
        .esps
        .iter()
        .map(|candidate| candidate.source.as_str())
        .collect();
    esp_candidates.retain(|candidate| !probed_esp_sources.contains(candidate.source.as_str()));
    esp_candidates.append(&mut probed.esps);

    let ambiguities = candidate_ambiguities(&root_candidates, &esp_candidates);
    let mut warnings = merge_warnings(dev_warnings, cand_warnings);
    warnings.append(&mut probed.warnings);

    Ok(SystemCommandOutcome::StorageScan(StorageReport {
        devices,
        root_candidates,
        esp_candidates,
        btrfs_subvolumes: probed.btrfs_subvolumes,
        warnings,
        ambiguities,
    }))
}
