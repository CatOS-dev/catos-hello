//! Stage-6 Chroot capability boundary tests.
//!
//! The tests pin the intended ownership and behavior: diagnosis parses
//! observations, planning is pure and rejects unsafe paths, execution requires
//! typed privilege evidence, and cleanup runs even when the interactive shell
//! fails.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use catos_system::chroot::diagnose::block::parse_lsblk_json;
use catos_system::chroot::execute::{
    authorize, execute_plan, ChrootEffects, ChrootPrivilegeEvidence,
};
use catos_system::chroot::model::{
    BlockDevice, ChrootExecutionOutcome, ChrootMountKind, FsTabEntry, Subvolume,
};
use catos_system::chroot::plan::{build_plan, ChrootPlanInputs, ExtraMountSelection};
use catos_system::chroot::session::read_only_mount_options;
use catos_system::chroot::verify::verify_target_root;

fn device(name: &str, fstype: &str, uuid: &str) -> BlockDevice {
    BlockDevice {
        name: name.into(),
        fs_type: Some(fstype.into()),
        uuid: Some(uuid.into()),
        partuuid: None,
        label: None,
        partlabel: None,
    }
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "catos-chroot-capability-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn block_diagnosis_parses_fixture_without_running_lsblk() {
    let json = br#"{
        "blockdevices": [
            {
                "name": "/dev/nvme0n1p2",
                "fstype": "btrfs",
                "uuid": "root-uuid",
                "partuuid": "part-root",
                "label": "CatOS",
                "partlabel": "root"
            }
        ]
    }"#;

    let devices = parse_lsblk_json(json).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "/dev/nvme0n1p2");
    assert!(devices[0].is_btrfs());
}

#[test]
fn readonly_probe_options_prevent_filesystem_replay() {
    let ext4 = read_only_mount_options(&device("/dev/vda2", "ext4", "ext4"), &[]).unwrap();
    assert_eq!(ext4, ["ro", "noload"]);

    let xfs = read_only_mount_options(&device("/dev/vda3", "xfs", "xfs"), &[]).unwrap();
    assert_eq!(xfs, ["ro", "norecovery"]);

    let btrfs = read_only_mount_options(
        &device("/dev/vda4", "btrfs", "btrfs"),
        &["subvolid=5".into()],
    )
    .unwrap();
    assert_eq!(btrfs, ["ro", "rescue=nologreplay", "subvolid=5"]);
}

#[test]
fn chroot_plan_is_pure_and_filters_non_mountable_fstab_entries() {
    let root = device("/dev/nvme0n1p2", "btrfs", "root-uuid");
    let boot = device("/dev/nvme0n1p1", "vfat", "esp-uuid");
    let swap = device("/dev/nvme0n1p3", "swap", "swap-uuid");
    let devices = vec![root.clone(), boot.clone(), swap];
    let fstab = vec![
        FsTabEntry {
            fs_spec: "UUID=root-uuid".into(),
            mountpoint: "/".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=esp-uuid".into(),
            mountpoint: "/boot".into(),
            vfs_type: "vfat".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=swap-uuid".into(),
            mountpoint: "none".into(),
            vfs_type: "swap".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=missing".into(),
            mountpoint: "/srv".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["noauto".into()],
        },
    ];
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.root.kind, ChrootMountKind::Root);
    assert_eq!(plan.root.options, ["subvolid=256"]);
    assert_eq!(plan.mounts.len(), 1);
    assert_eq!(plan.mounts[0].device.name, boot.name);
    assert_eq!(plan.mounts[0].mount_point, "/boot");
    assert!(plan.warnings.is_empty());
}

#[test]
fn chroot_plan_rejects_mountpoint_escape() {
    let root = device("/dev/vda2", "ext4", "root");
    let data = device("/dev/vda3", "ext4", "data");
    let extra = [ExtraMountSelection {
        device: data,
        mount_point: "/var/../../host".into(),
    }];

    let error = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &[],
        devices: std::slice::from_ref(&root),
        extra_mounts: &extra,
        use_systemd_chroot: true,
    })
    .unwrap_err();

    assert!(error.to_string().contains("unsafe mount point"));
}

#[test]
fn chroot_plan_rejects_undiscovered_extra_device() {
    let root = device("/dev/vda2", "ext4", "root");
    let extra = [ExtraMountSelection {
        device: device("/dev/vda3", "ext4", "data"),
        mount_point: "/srv".into(),
    }];

    let error = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &[],
        devices: std::slice::from_ref(&root),
        extra_mounts: &extra,
        use_systemd_chroot: true,
    })
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("not present in the diagnosed device set"));
}

#[test]
fn chroot_plan_rejects_undiscovered_root_device() {
    let root = device("/dev/vda2", "ext4", "root");

    let error = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &[],
        devices: &[],
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("not present in the diagnosed device set"));
}

#[test]
fn chroot_plan_rejects_subvolume_for_non_btrfs_root() {
    let root = device("/dev/vda2", "ext4", "root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };

    let error = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &[],
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap_err();

    assert!(error.to_string().contains("non-Btrfs"));
}

#[test]
fn chroot_plan_orders_parent_mounts_before_children() {
    let root = device("/dev/vda3", "ext4", "root");
    let boot = device("/dev/vda2", "ext4", "boot");
    let esp = device("/dev/vda1", "vfat", "esp");
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=esp".into(),
            mountpoint: "/boot/efi".into(),
            vfs_type: "vfat".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=boot".into(),
            mountpoint: "/boot".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
    ];
    let devices = [root.clone(), boot, esp];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(
        plan.mounts
            .iter()
            .map(|mount| mount.mount_point.as_str())
            .collect::<Vec<_>>(),
        ["/boot", "/boot/efi"]
    );
}

#[test]
fn chroot_plan_prefers_btrfs_subvolume_id_over_name() {
    let root = device("/dev/vda2", "ext4", "root");
    let home = device("/dev/vda3", "btrfs", "home");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=home".into(),
        mountpoint: "/home".into(),
        vfs_type: "btrfs".into(),
        mount_options: vec!["subvol=@home".into(), "subvolid=300".into()],
    }];
    let devices = [root.clone(), home];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts[0].options, ["subvolid=300"]);
}

#[test]
fn chroot_plan_preserves_btrfs_subvolume_name_without_id() {
    let root = device("/dev/vda2", "ext4", "root");
    let home = device("/dev/vda3", "btrfs", "home");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=home".into(),
        mountpoint: "/home".into(),
        vfs_type: "btrfs".into(),
        mount_options: vec!["compress=zstd".into(), "subvol=@home".into()],
    }];
    let devices = [root.clone(), home];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts[0].options, ["subvol=@home"]);
}

#[test]
fn chroot_plan_does_not_forward_non_btrfs_fstab_options() {
    let root = device("/dev/vda2", "ext4", "root");
    let data = device("/dev/vda3", "ext4", "data");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=data".into(),
        mountpoint: "/srv".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["defaults".into(), "suid".into(), "exec".into()],
    }];
    let devices = [root.clone(), data];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert!(plan.mounts[0].options.is_empty());
}

#[test]
fn execution_authorization_refuses_non_root_euid() {
    let error = authorize(ChrootPrivilegeEvidence::EffectiveUid(1000)).unwrap_err();
    assert!(error.contains("not authorised"));
}

#[derive(Default)]
struct RecordedEffects {
    calls: Vec<String>,
    fail_enter: bool,
    fail_cleanup: bool,
}

impl ChrootEffects for RecordedEffects {
    fn mount(
        &mut self,
        device: &BlockDevice,
        session_root: &Path,
        mount_point: &str,
        options: &[String],
    ) -> Result<(), String> {
        self.calls.push(format!(
            "mount:{}:{}:{}",
            device.name,
            session_root
                .join(mount_point.trim_start_matches('/'))
                .display(),
            options.join(",")
        ));
        Ok(())
    }

    fn enter(&mut self, root: &Path, use_systemd_chroot: bool) -> Result<(), String> {
        self.calls
            .push(format!("enter:{}:{use_systemd_chroot}", root.display()));
        if self.fail_enter {
            Err("synthetic shell failure".into())
        } else {
            Ok(())
        }
    }

    fn unmount_recursive(&mut self, root: &Path) -> Result<(), String> {
        self.calls.push(format!("umount:{}", root.display()));
        if self.fail_cleanup {
            Err("synthetic cleanup failure".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn execution_uses_typed_authorization_and_cleans_up_after_shell_failure() {
    let root_device = device("/dev/vda2", "ext4", "root");
    let boot_device = device("/dev/vda1", "vfat", "boot");
    let extra = [ExtraMountSelection {
        device: boot_device.clone(),
        mount_point: "/boot".into(),
    }];
    let plan = build_plan(ChrootPlanInputs {
        root_device: &root_device,
        root_subvolume: None,
        fstab: &[],
        devices: &[root_device.clone(), boot_device.clone()],
        extra_mounts: &extra,
        use_systemd_chroot: true,
    })
    .unwrap();
    let authorization = authorize(ChrootPrivilegeEvidence::EffectiveUid(0)).unwrap();
    let session_root = scratch("execute");
    fs::create_dir_all(session_root.join("etc")).unwrap();
    fs::create_dir_all(session_root.join("usr/bin")).unwrap();
    fs::write(
        session_root.join("etc/os-release"),
        b"ID=catos\nNAME=CatOS\n",
    )
    .unwrap();
    fs::write(session_root.join("usr/bin/bash"), b"synthetic").unwrap();

    let mut effects = RecordedEffects {
        fail_enter: true,
        ..RecordedEffects::default()
    };
    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::ShellFailed);
    assert!(report.cleanup_complete);
    assert!(effects
        .calls
        .iter()
        .any(|call| call == &format!("umount:{}", session_root.display())));
    assert!(
        effects
            .calls
            .iter()
            .position(|call| call.starts_with("enter:"))
            < effects
                .calls
                .iter()
                .position(|call| call.starts_with("umount:"))
    );
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn successful_shell_with_failed_unmount_is_cleanup_incomplete() {
    let root_device = device("/dev/vda2", "ext4", "root");
    let plan = build_plan(ChrootPlanInputs {
        root_device: &root_device,
        root_subvolume: None,
        fstab: &[],
        devices: std::slice::from_ref(&root_device),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();
    let authorization = authorize(ChrootPrivilegeEvidence::EffectiveUid(0)).unwrap();
    let session_root = scratch("cleanup-incomplete");
    fs::create_dir_all(session_root.join("etc")).unwrap();
    fs::create_dir_all(session_root.join("usr/bin")).unwrap();
    fs::write(session_root.join("etc/os-release"), b"ID=catos\n").unwrap();
    fs::write(session_root.join("usr/bin/bash"), b"synthetic").unwrap();

    let mut effects = RecordedEffects {
        fail_cleanup: true,
        ..RecordedEffects::default()
    };
    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::CleanupIncomplete);
    assert!(!report.cleanup_complete);
    assert!(report
        .failure
        .as_deref()
        .is_some_and(|failure| failure.contains("synthetic cleanup failure")));
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn verification_rejects_symlinked_target_identity() {
    use std::os::unix::fs::symlink;

    let root = scratch("verify-symlink");
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::write(root.join("usr/bin/bash"), b"synthetic").unwrap();
    symlink("/etc/os-release", root.join("etc/os-release")).unwrap();

    let verification = verify_target_root(&root);
    assert!(!verification.ready);
    assert!(verification
        .reasons
        .iter()
        .any(|reason| reason.contains("os-release")));
    let _ = fs::remove_dir_all(root);
}
