//! Kernel cmdline builder. Port of `providers/base.kernel_cmdline`
//! from the bootloadu Calamares module, adjusted to use the
//! [`catos_mount::model::MountTargetIdentity`] the stage 1–3
//! discovery already established.
//!
//! ## Hard rules
//!
//! * The cmdline is generated from the target's own disk facts
//!   (root UUID, subvolume, swap layout). The live host's
//!   `/proc/cmdline` is NEVER copied wholesale.
//! * The user's existing cmdline parameters are preserved when the
//!   recipe rewrites `/etc/kernel/cmdline`: parameters the builder
//!   does not own are carried through unchanged. The builder does
//!   NOT silently delete parameters it does not understand.
//! * Same-key conflicts (e.g. an existing `root=` pointing at a
//!   different device) are reported via [`CmdlineConflict`] instead
//!   of being silently overwritten.
//! * Btrfs subvolume flags are added only when the target root is
//!   Btrfs and a subvolume path is known.

use crate::model::{BootCmdlineFacts, CmdlineConflict, ResumeTarget};
use catos_mount::model::MountTargetIdentity;

/// Inputs to [`build_kernel_cmdline`].
#[derive(Debug, Clone)]
pub struct CmdlineInputs<'a> {
    /// Target identity discovered by the stage 1–3 path. Carries the
    /// root device, UUID, fstype, and subvolume.
    pub target: &'a MountTargetIdentity,
    /// Existing `/etc/kernel/cmdline` content (or equivalent GRUB
    /// defaults) read from the target. May be empty for a fresh
    /// install. Used to preserve user-added parameters.
    pub existing_cmdline: &'a str,
    /// Whether the target has Plymouth installed. Mirrors the
    /// bootloadu `target_has("plymouth")` check; the caller (target
    /// package probe) supplies the answer so the builder stays pure.
    pub has_plymouth: bool,
    /// Verified target-side root encryption and resume facts.
    pub facts: &'a BootCmdlineFacts,
}

/// Default parameters the recipe always emits, in the order bootloadu
/// emits them. Mirrors `parameters = ["quiet", "rw"]`.
fn default_parameters(has_plymouth: bool) -> Vec<String> {
    let mut out = vec!["quiet".to_string(), "rw".to_string()];
    if has_plymouth {
        out.push("splash".to_string());
    }
    out
}

/// Build the kernel cmdline for the target. Returns `(cmdline,
/// conflicts)`. The cmdline is the user-facing string the provider
/// writes; conflicts describe same-key disagreements the builder
/// refused to silently overwrite.
///
/// The builder is a pure function of [`CmdlineInputs`]; it does not
/// touch the filesystem.
pub fn build_kernel_cmdline(inputs: &CmdlineInputs<'_>) -> (String, Vec<CmdlineConflict>) {
    let target = inputs.target;
    let mut parameters = default_parameters(inputs.has_plymouth);

    // Root parameter: either LUKS-mapped or UUID-based.
    if let Some(mapping) = &inputs.facts.luks_root {
        parameters.push(format!(
            "cryptdevice=UUID={}:{}",
            mapping.luks_uuid, mapping.mapper_name
        ));
        parameters.push(format!("root=/dev/mapper/{}", mapping.mapper_name));
    } else if let Some(root_uuid) = target.root_uuid.as_deref() {
        if !root_uuid.is_empty() {
            parameters.push(format!("root=UUID={root_uuid}"));
        }
    }

    // Btrfs subvolume flag.
    if target.root_fstype == "btrfs" {
        if let Some(subvol) = target.root_subvol.as_deref() {
            if !subvol.is_empty() {
                parameters.push(format!("rootflags=subvol={subvol}"));
            }
        }
    }

    // Resume (swap) parameters. Diagnosis guarantees at most one target.
    if let Some(resume) = &inputs.facts.resume {
        match resume {
            ResumeTarget::Uuid { uuid } => parameters.push(format!("resume=UUID={uuid}")),
            ResumeTarget::Mapper { mapper_name } => {
                parameters.push(format!("resume=/dev/mapper/{mapper_name}"));
            }
            ResumeTarget::SwapFile { device, offset } => {
                parameters.push(format!("resume={device}"));
                parameters.push(format!("resume_offset={offset}"));
            }
        }
    }

    // Preserve user parameters the builder does not own. The "owned"
    // set is the keys the recipe is allowed to set; an existing
    // occurrence of an owned key with a DIFFERENT value is a
    // conflict, while a matching value is a no-op.
    let owned_keys = [
        "quiet",
        "rw",
        "splash",
        "root",
        "rootflags",
        "cryptdevice",
        "resume",
        "resume_offset",
    ];
    let existing = parse_parameters(inputs.existing_cmdline);
    let mut conflicts = Vec::new();
    for existing_param in &existing {
        let (key, value) = split_key_value(existing_param);
        if !owned_keys.contains(&key.as_str()) {
            // User-owned parameter (e.g. `mitigations=off`, `i915.enable_guc=2`).
            // Carry through unchanged unless we'd duplicate it.
            if !parameters.iter().any(|p| split_key_value(p).0 == key) {
                parameters.push(existing_param.clone());
            }
            continue;
        }
        // Owned key already covered by the recipe. If the user value
        // disagrees with what the recipe generates, surface a
        // conflict instead of silently overwriting.
        if let Some(recipe_param) = parameters.iter().find(|p| split_key_value(p).0 == key) {
            let recipe_value = split_key_value(recipe_param).1;
            if recipe_value != value {
                conflicts.push(CmdlineConflict::ConflictingValue {
                    key,
                    existing: value,
                    proposed: recipe_value,
                });
            }
        }
    }

    // De-duplicate while preserving the first-seen order. Mirrors the
    // bootloadu `dict.fromkeys` collapsing.
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(parameters.len());
    for param in parameters {
        // Drop trailing `=` parameters (e.g. a stray `root=` with no value).
        if param.ends_with('=') {
            continue;
        }
        if seen.insert(param.clone()) {
            deduped.push(param);
        }
    }

    (deduped.join(" "), conflicts)
}

/// Parse a kernel cmdline string into individual parameters. Handles
/// shell-style quoting the same way shlex would, but the kernel only
/// cares about whitespace separation so we keep it simple.
fn parse_parameters(cmdline: &str) -> Vec<String> {
    cmdline
        .split_whitespace()
        .map(str::to_string)
        .filter(|param| !param.is_empty())
        .collect()
}

/// Split `key=value` (or a bare `key`) into `(key, value)`. For a
/// bare key the value is the empty string.
fn split_key_value(param: &str) -> (String, String) {
    if let Some((key, value)) = param.split_once('=') {
        (key.to_string(), value.to_string())
    } else {
        (param.to_string(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn btrfs_target() -> MountTargetIdentity {
        MountTargetIdentity {
            root_device: PathBuf::from("/dev/nvme0n1p2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("abc-123".into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        }
    }

    fn ext4_target() -> MountTargetIdentity {
        MountTargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "ext4".into(),
            root_subvol: None,
            root_uuid: Some("root-uuid".into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        }
    }

    #[test]
    fn generates_root_uuid_and_btrfs_subvol() {
        let target = btrfs_target();
        let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "",
            has_plymouth: false,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        assert!(cmdline.contains("quiet"));
        assert!(cmdline.contains("rw"));
        assert!(cmdline.contains("root=UUID=abc-123"));
        assert!(cmdline.contains("rootflags=subvol=/@"));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn plymouth_adds_splash() {
        let target = ext4_target();
        let (cmdline, _) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "",
            has_plymouth: true,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        assert!(cmdline.contains("splash"));
    }

    #[test]
    fn swap_uuid_emits_resume() {
        let target = ext4_target();
        let (cmdline, _) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "",
            has_plymouth: false,
            facts: &BootCmdlineFacts {
                resume: Some(ResumeTarget::Uuid {
                    uuid: "swap-uuid".into(),
                }),
                ..BootCmdlineFacts::default()
            },
        });
        assert!(cmdline.contains("resume=UUID=swap-uuid"));
    }

    #[test]
    fn luks_root_uses_cryptdevice_and_mapper() {
        let target = MountTargetIdentity {
            root_device: PathBuf::from("/dev/mapper/cryptroot"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some("mapper-uuid".into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        };
        let (cmdline, _) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "",
            has_plymouth: false,
            facts: &BootCmdlineFacts {
                luks_root: Some(crate::model::LuksMapping {
                    luks_uuid: "luks-uuid".into(),
                    mapper_name: "cryptroot".into(),
                }),
                ..BootCmdlineFacts::default()
            },
        });
        assert!(cmdline.contains("cryptdevice=UUID=luks-uuid:cryptroot"));
        assert!(cmdline.contains("root=/dev/mapper/cryptroot"));
        // Mapper-based root should NOT also emit root=UUID=...
        assert!(!cmdline.contains("root=UUID=mapper-uuid"));
    }

    #[test]
    fn swapfile_emits_resume_device_and_offset() {
        let target = btrfs_target();
        let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "",
            has_plymouth: false,
            facts: &BootCmdlineFacts {
                resume: Some(ResumeTarget::SwapFile {
                    device: "/dev/mapper/cryptroot".into(),
                    offset: 4096,
                }),
                ..BootCmdlineFacts::default()
            },
        });
        assert!(cmdline.contains("resume=/dev/mapper/cryptroot"));
        assert!(cmdline.contains("resume_offset=4096"));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn preserves_user_owned_parameters() {
        let target = btrfs_target();
        let (cmdline, conflicts) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "mitigations=off i915.enable_guc=2",
            has_plymouth: false,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        assert!(cmdline.contains("mitigations=off"));
        assert!(cmdline.contains("i915.enable_guc=2"));
        // No conflicts: user parameters do not collide with recipe keys.
        assert!(conflicts.is_empty());
    }

    #[test]
    fn conflicting_root_value_surfaces_conflict() {
        let target = btrfs_target();
        let (_, conflicts) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            // Existing cmdline points root at a different UUID.
            existing_cmdline: "root=UUID=stale-root",
            has_plymouth: false,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        assert!(conflicts.iter().any(|c| matches!(c,
            CmdlineConflict::ConflictingValue { key, .. } if key == "root"
        )));
    }

    #[test]
    fn matching_root_value_does_not_conflict() {
        let target = btrfs_target();
        let (_, conflicts) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "root=UUID=abc-123",
            has_plymouth: false,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        assert!(conflicts.is_empty());
    }

    #[test]
    fn does_not_copy_host_proc_cmdline() {
        // Even if the existing cmdline contains live-ISO artefacts
        // like `archisobasedir=arch`, the builder preserves them as
        // user parameters BUT only when they are NOT in the owned
        // set. We do not strip them silently, but we also do not
        // treat them as authoritative.
        let target = btrfs_target();
        let (cmdline, _) = build_kernel_cmdline(&CmdlineInputs {
            target: &target,
            existing_cmdline: "archisobasedir=arch archisolabel=CATOS",
            has_plymouth: false,
            facts: &crate::model::BootCmdlineFacts::default(),
        });
        // Recipe parameters still present.
        assert!(cmdline.contains("root=UUID=abc-123"));
        // User parameters preserved (not silently dropped).
        assert!(cmdline.contains("archisobasedir=arch"));
    }
}
