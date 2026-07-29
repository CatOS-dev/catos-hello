//! Stage-6 Chroot capability boundary tests.
//!
//! The tests pin the intended ownership and behavior: diagnosis parses
//! observations, planning is pure and rejects unsafe paths, execution requires
//! typed privilege evidence, and cleanup runs even when the interactive shell
//! fails.

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use catos_system::chroot::diagnose::block::parse_lsblk_json;
use catos_system::chroot::execute::{
    authorize, execute_plan, execute_plan_with_policy, ChrootEffects, ChrootExecutionPolicy,
    ChrootPrivilegeEvidence,
};
use catos_system::chroot::model::{
    BlockDevice, ChrootExecutionOutcome, ChrootMountKind, ChrootPlan, ChrootRuntimeMount,
    FsTabEntry, Subvolume,
};
use catos_system::chroot::plan::{build_plan, ChrootPlanInputs, ExtraMountSelection};
use catos_system::chroot::session::read_only_mount_options;
use catos_system::chroot::verify::{verify_assembled_target, verify_target_root};

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

fn write_valid_arch_chroot_shell(root: &Path) {
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    if !root.join("bin").exists() {
        symlink("usr/bin", root.join("bin")).unwrap();
    }
    let bash = root.join("usr/bin/bash");
    fs::write(&bash, b"synthetic-bash").unwrap();
    fs::set_permissions(&bash, fs::Permissions::from_mode(0o755)).unwrap();
}

fn mountinfo_for_plan(root: &Path, plan: &ChrootPlan) -> String {
    fn line(
        id: u32,
        root: &str,
        mount_point: &Path,
        fstype: &str,
        source: &str,
        super_options: &str,
    ) -> String {
        format!(
            "{id} 1 0:{id} {root} {} rw - {fstype} {source} {super_options}\n",
            mount_point.display()
        )
    }

    let mut body = String::from(
        "1 0 0:10 / /dev rw - devtmpfs udev rw\n2 0 0:11 / /run rw - tmpfs tmpfs rw\n",
    );
    let mut id = 20;
    let mut push_mount = |mount: &catos_system::chroot::model::ChrootMount| {
        let target = if mount.mount_point == "/" {
            root.to_path_buf()
        } else {
            root.join(mount.mount_point.trim_start_matches('/'))
        };
        let fstype = mount.device.fs_type.as_deref().unwrap();
        let selector = mount.options.first().map(String::as_str);
        let mount_root = selector
            .and_then(|value| value.strip_prefix("subvol="))
            .map(|value| format!("/{}", value.trim_start_matches('/')))
            .unwrap_or_else(|| {
                if mount.mount_point == "/" && fstype == "btrfs" {
                    "/@".into()
                } else {
                    "/".into()
                }
            });
        let super_options = selector
            .map(|value| format!("rw,{value}"))
            .unwrap_or_else(|| "rw".into());
        body.push_str(&line(
            id,
            &mount_root,
            &target,
            fstype,
            &mount.device.name,
            &super_options,
        ));
        id += 1;
    };
    push_mount(&plan.root);
    for mount in &plan.mounts {
        push_mount(mount);
    }
    body.push_str(&line(90, "/", &root.join("proc"), "proc", "proc", "rw"));
    body.push_str(&line(91, "/", &root.join("sys"), "sysfs", "sysfs", "ro"));
    body.push_str(&format!(
        "92 1 0:10 / {} rw - devtmpfs udev rw\n",
        root.join("dev").display()
    ));
    body.push_str(&format!(
        "93 1 0:11 / {} rw - tmpfs tmpfs rw\n",
        root.join("run").display()
    ));
    body
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
fn chroot_plan_skips_unsafe_fstab_mountpoint_and_keeps_rescue_plan_usable() {
    let root = device("/dev/vda2", "ext4", "root");
    let data = device("/dev/vda3", "ext4", "data");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=data".into(),
        mountpoint: "/var/../../host".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["defaults".into()],
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

    assert!(plan.mounts.is_empty());
    assert!(plan.warnings.iter().any(|warning| {
        warning.contains("was skipped") && warning.contains("unsafe mount point")
    }));
}

#[test]
fn chroot_plan_skips_missing_secondary_device_without_nofail() {
    let root = device("/dev/vda2", "ext4", "root");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=missing-data".into(),
        mountpoint: "/srv".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["defaults".into()],
    }];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert!(plan.mounts.is_empty());
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("was not discovered")));
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
fn chroot_plan_mounts_standard_catos_subvolumes_from_one_btrfs_filesystem() {
    let root = device("/dev/nvme0n1p3", "btrfs", "catos-root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=catos-root".into(),
            mountpoint: "/".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@".into(), "subvolid=256".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=catos-root".into(),
            mountpoint: "/home".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@home".into(), "subvolid=257".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=catos-root".into(),
            mountpoint: "/var/log".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@var_log".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=catos-root".into(),
            mountpoint: "/.snapshots".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@snapshots".into()],
        },
    ];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(
        plan.mounts
            .iter()
            .map(|mount| (mount.mount_point.clone(), mount.options.clone()))
            .collect::<Vec<_>>(),
        [
            ("/.snapshots".into(), vec!["subvol=@snapshots".into()]),
            ("/home".into(), vec!["subvolid=257".into()]),
            ("/var/log".into(), vec!["subvol=@var_log".into()]),
        ]
    );
}

#[test]
fn chroot_plan_deduplicates_only_exact_mount_identity() {
    let root = device("/dev/vda3", "ext4", "root");
    let boot = device("/dev/vda2", "ext4", "boot");
    let duplicate = FsTabEntry {
        fs_spec: "UUID=boot".into(),
        mountpoint: "/boot".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["defaults".into()],
    };
    let devices = [root.clone(), boot];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &[duplicate.clone(), duplicate],
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts.len(), 1);
}

#[test]
fn chroot_plan_deduplicates_equivalent_btrfs_subvolume_paths() {
    let root = device("/dev/vda2", "btrfs", "root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/home".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=@home".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/home".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvol=/@home".into()],
        },
    ];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts.len(), 1);
    assert_eq!(plan.mounts[0].options, ["subvol=@home"]);
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("duplicate mount")));
}

#[test]
fn chroot_plan_skips_non_numeric_btrfs_subvolume_id() {
    let root = device("/dev/vda2", "btrfs", "root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [FsTabEntry {
        fs_spec: "UUID=root".into(),
        mountpoint: "/home".into(),
        vfs_type: "btrfs".into(),
        mount_options: vec!["subvolid=not-a-number".into()],
    }];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert!(plan.mounts.is_empty());
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("invalid Btrfs subvolid")));
}

#[test]
fn chroot_plan_keeps_first_conflicting_mount_and_warns_about_the_later_entry() {
    let root = device("/dev/vda3", "ext4", "root");
    let first = device("/dev/vda1", "vfat", "first");
    let second = device("/dev/vda2", "ext4", "second");
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=first".into(),
            mountpoint: "/boot".into(),
            vfs_type: "vfat".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=second".into(),
            mountpoint: "/boot".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
    ];
    let devices = [root.clone(), first, second];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts.len(), 1);
    assert_eq!(plan.mounts[0].device.name, "/dev/vda1");
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("conflicting mount entries")));
}

#[test]
fn chroot_plan_skips_btrfs_selector_for_non_btrfs_filesystem() {
    let root = device("/dev/vda2", "ext4", "root");
    let data = device("/dev/vda3", "ext4", "data");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=data".into(),
        mountpoint: "/srv".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["subvol=@data".into()],
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

    assert!(plan.mounts.is_empty());
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("Btrfs selector")));
}

#[test]
fn chroot_plan_warns_on_root_fstab_identity_mismatch_and_keeps_selected_root() {
    let root = device("/dev/vda2", "ext4", "root");
    let other = device("/dev/vda3", "ext4", "other");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=other".into(),
        mountpoint: "/".into(),
        vfs_type: "ext4".into(),
        mount_options: vec!["defaults".into()],
    }];
    let devices = [root.clone(), other];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.root.device, root);
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("root fstab entry")));
}

#[test]
fn chroot_plan_warns_on_swap_entry_masquerading_as_root() {
    let root = device("/dev/vda2", "ext4", "root");
    let fstab = [FsTabEntry {
        fs_spec: "UUID=root".into(),
        mountpoint: "/".into(),
        vfs_type: "swap".into(),
        mount_options: vec!["defaults".into()],
    }];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.root.device, root);
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("root fstab entry")));
}

#[test]
fn chroot_plan_rejects_stale_root_identity_reusing_device_path() {
    let selected = device("/dev/vda2", "ext4", "stale-root");
    let current = device("/dev/vda2", "ext4", "current-root");

    let error = build_plan(ChrootPlanInputs {
        root_device: &selected,
        root_subvolume: None,
        fstab: &[],
        devices: std::slice::from_ref(&current),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap_err();

    assert!(error.to_string().contains("diagnosed device set"));
}

#[test]
fn chroot_plan_resolves_uuid_partuuid_label_and_device_path() {
    let root = device("/dev/vda4", "ext4", "root");
    let mut boot = device("/dev/vda3", "ext4", "boot");
    boot.partuuid = Some("boot-part".into());
    let mut esp = device("/dev/vda2", "vfat", "esp");
    esp.label = Some("CATOS_ESP".into());
    let data = device("/dev/vdb1", "xfs", "data");
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "PARTUUID=boot-part".into(),
            mountpoint: "/boot".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "LABEL=CATOS_ESP".into(),
            mountpoint: "/boot/efi".into(),
            vfs_type: "vfat".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "/dev/vdb1".into(),
            mountpoint: "/srv".into(),
            vfs_type: "xfs".into(),
            mount_options: vec!["defaults".into()],
        },
    ];
    let devices = [root.clone(), boot, esp, data];

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
            .map(|mount| (mount.mount_point.as_str(), mount.device.name.as_str()))
            .collect::<Vec<_>>(),
        [
            ("/boot", "/dev/vda3"),
            ("/srv", "/dev/vdb1"),
            ("/boot/efi", "/dev/vda2"),
        ]
    );
}

#[test]
fn chroot_plan_skips_ambiguous_label_resolution() {
    let root = device("/dev/vda3", "ext4", "root");
    let mut first = device("/dev/vda1", "vfat", "esp-a");
    first.label = Some("ESP".into());
    let mut second = device("/dev/vda2", "vfat", "esp-b");
    second.label = Some("ESP".into());
    let fstab = [FsTabEntry {
        fs_spec: "LABEL=ESP".into(),
        mountpoint: "/boot/efi".into(),
        vfs_type: "vfat".into(),
        mount_options: vec!["defaults".into()],
    }];
    let devices = [root.clone(), first, second];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: None,
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert!(plan.mounts.is_empty());
    assert!(plan
        .warnings
        .iter()
        .any(|warning| warning.contains("ambiguous across 2")));
}

#[test]
fn chroot_plan_allows_same_btrfs_subvolume_at_distinct_mountpoints() {
    let root = device("/dev/vda2", "btrfs", "root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/mnt/a".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvolid=300".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/mnt/b".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvolid=300".into()],
        },
    ];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: std::slice::from_ref(&root),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.mounts.len(), 2);
}

#[test]
fn chroot_plan_supports_mapper_root_and_separate_btrfs_filesystem() {
    let root = device("/dev/mapper/catos-root", "btrfs", "root");
    let home = device("/dev/mapper/catos-home", "btrfs", "home");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=root".into(),
            mountpoint: "/".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvolid=256".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=home".into(),
            mountpoint: "/home".into(),
            vfs_type: "btrfs".into(),
            mount_options: vec!["subvolid=5".into()],
        },
    ];
    let devices = [root.clone(), home];

    let plan = build_plan(ChrootPlanInputs {
        root_device: &root,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: &devices,
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();

    assert_eq!(plan.root.device.name, "/dev/mapper/catos-root");
    assert_eq!(plan.mounts[0].device.name, "/dev/mapper/catos-home");
    assert_eq!(plan.mounts[0].options, ["subvolid=5"]);
}

#[test]
fn execution_authorization_refuses_non_root_euid() {
    let error = authorize(ChrootPrivilegeEvidence::EffectiveUid(1000)).unwrap_err();
    assert!(error.contains("not authorised"));
}

fn mount_call(device: &BlockDevice, root: &Path, mount_point: &str, options: &[String]) -> String {
    format!(
        "mount:{}:{}:{}",
        device.name,
        root.join(mount_point.trim_start_matches('/')).display(),
        options.join(",")
    )
}

fn runtime_call(root: &Path, runtime: ChrootRuntimeMount) -> String {
    format!(
        "runtime:{}",
        root.join(runtime.mount_point().trim_start_matches('/'))
            .display()
    )
}

fn unmount_call(target: &Path) -> String {
    format!("umount:{}", target.display())
}

fn successful_execution_calls(plan: &ChrootPlan, root: &Path) -> VecDeque<String> {
    let mut calls = VecDeque::new();
    calls.push_back(mount_call(
        &plan.root.device,
        root,
        &plan.root.mount_point,
        &plan.root.options,
    ));
    for mount in &plan.mounts {
        calls.push_back(mount_call(
            &mount.device,
            root,
            &mount.mount_point,
            &mount.options,
        ));
    }
    for runtime in ChrootRuntimeMount::ALL {
        calls.push_back(runtime_call(root, runtime));
    }
    calls.push_back("mountinfo".into());
    calls.push_back(format!(
        "enter:{}:{}",
        root.display(),
        plan.use_systemd_chroot
    ));

    for runtime in ChrootRuntimeMount::ALL.into_iter().rev() {
        calls.push_back(unmount_call(
            &root.join(runtime.mount_point().trim_start_matches('/')),
        ));
    }
    for mount in plan.mounts.iter().rev() {
        calls.push_back(unmount_call(
            &root.join(mount.mount_point.trim_start_matches('/')),
        ));
    }
    calls.push_back(unmount_call(root));
    calls
}

#[derive(Default)]
struct RecordedEffects {
    expected_calls: VecDeque<String>,
    calls: Vec<String>,
    fail_mount_point: Option<String>,
    fail_runtime: Option<ChrootRuntimeMount>,
    fail_enter: bool,
    fail_unmount_paths: Vec<PathBuf>,
    mountinfo: Option<String>,
    confirm_unverified: Option<bool>,
}

impl RecordedEffects {
    fn record(&mut self, call: String) {
        let expected = self
            .expected_calls
            .pop_front()
            .unwrap_or_else(|| panic!("unconfigured external call: {call}"));
        assert_eq!(call, expected, "external call order or arguments changed");
        self.calls.push(call);
    }

    fn assert_consumed(&self) {
        assert!(
            self.expected_calls.is_empty(),
            "unconsumed external calls: {:?}",
            self.expected_calls
        );
    }
}

impl ChrootEffects for RecordedEffects {
    fn mount(
        &mut self,
        device: &BlockDevice,
        session_root: &Path,
        mount_point: &str,
        options: &[String],
    ) -> Result<(), String> {
        self.record(mount_call(device, session_root, mount_point, options));
        if self.fail_mount_point.as_deref() == Some(mount_point) {
            Err(format!("synthetic mount failure at {mount_point}"))
        } else {
            Ok(())
        }
    }

    fn mount_runtime(
        &mut self,
        session_root: &Path,
        runtime: ChrootRuntimeMount,
    ) -> Result<(), String> {
        self.record(runtime_call(session_root, runtime));
        if self.fail_runtime == Some(runtime) {
            Err(format!(
                "synthetic runtime mount failure at {}",
                runtime.mount_point()
            ))
        } else {
            Ok(())
        }
    }

    fn read_mountinfo(&mut self) -> Result<String, String> {
        self.record("mountinfo".into());
        self.mountinfo
            .clone()
            .ok_or_else(|| "synthetic mountinfo was not configured".into())
    }

    fn enter(&mut self, root: &Path, use_systemd_chroot: bool) -> Result<(), String> {
        self.record(format!("enter:{}:{use_systemd_chroot}", root.display()));
        if self.fail_enter {
            Err("synthetic shell failure".into())
        } else {
            Ok(())
        }
    }

    fn unmount(&mut self, target: &Path) -> Result<(), String> {
        self.record(unmount_call(target));
        if self.fail_unmount_paths.iter().any(|path| path == target) {
            Err(format!("synthetic cleanup failure at {}", target.display()))
        } else {
            Ok(())
        }
    }

    fn confirm_unverified(
        &mut self,
        _verification: &catos_system::chroot::model::ChrootVerification,
    ) -> Result<bool, String> {
        match self.confirm_unverified {
            Some(confirmed) => {
                self.record("confirm-unverified".into());
                Ok(confirmed)
            }
            None => Ok(false),
        }
    }
}

#[test]
#[should_panic(expected = "unconfigured external call")]
fn recorded_effects_reject_unconfigured_calls() {
    let mut effects = RecordedEffects::default();
    let _ = effects.read_mountinfo();
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
    write_valid_arch_chroot_shell(&session_root);
    fs::write(
        session_root.join("etc/os-release"),
        b"ID=catos\nNAME=CatOS\n",
    )
    .unwrap();
    let mountinfo = mountinfo_for_plan(&session_root, &plan);

    let mut effects = RecordedEffects {
        expected_calls: successful_execution_calls(&plan, &session_root),
        fail_enter: true,
        mountinfo: Some(mountinfo),
        ..RecordedEffects::default()
    };
    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::ShellFailed);
    assert!(report.cleanup_complete);
    assert!(report.residual_paths.is_empty());
    let runtime_mounts = ChrootRuntimeMount::ALL.map(|runtime| {
        format!(
            "runtime:{}",
            session_root
                .join(runtime.mount_point().trim_start_matches('/'))
                .display()
        )
    });
    for call in runtime_mounts {
        assert!(effects.calls.contains(&call));
    }
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
    effects.assert_consumed();
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
    write_valid_arch_chroot_shell(&session_root);
    fs::write(session_root.join("etc/os-release"), b"ID=catos\n").unwrap();
    let mountinfo = mountinfo_for_plan(&session_root, &plan);

    let mut effects = RecordedEffects {
        expected_calls: successful_execution_calls(&plan, &session_root),
        fail_unmount_paths: vec![session_root.clone()],
        mountinfo: Some(mountinfo),
        ..RecordedEffects::default()
    };
    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::CleanupIncomplete);
    assert!(!report.cleanup_complete);
    assert_eq!(
        report.residual_paths.as_slice(),
        std::slice::from_ref(&session_root)
    );
    assert!(report
        .failure
        .as_deref()
        .is_some_and(|failure| failure.contains("synthetic cleanup failure")));
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn auxiliary_mount_failure_warns_skips_descendants_and_still_enters_chroot() {
    let root_device = device("/dev/vda4", "ext4", "root");
    let boot_device = device("/dev/vda3", "ext4", "boot");
    let home_device = device("/dev/vda2", "ext4", "home");
    let esp_device = device("/dev/vda1", "vfat", "esp");
    let fstab = [
        FsTabEntry {
            fs_spec: "UUID=boot".into(),
            mountpoint: "/boot".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=home".into(),
            mountpoint: "/home".into(),
            vfs_type: "ext4".into(),
            mount_options: vec!["defaults".into()],
        },
        FsTabEntry {
            fs_spec: "UUID=esp".into(),
            mountpoint: "/boot/efi".into(),
            vfs_type: "vfat".into(),
            mount_options: vec!["defaults".into()],
        },
    ];
    let plan = build_plan(ChrootPlanInputs {
        root_device: &root_device,
        root_subvolume: None,
        fstab: &fstab,
        devices: &[root_device.clone(), boot_device, home_device, esp_device],
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();
    let authorization = authorize(ChrootPrivilegeEvidence::EffectiveUid(0)).unwrap();
    let session_root = scratch("auxiliary-mount-failure");
    fs::create_dir_all(session_root.join("etc")).unwrap();
    write_valid_arch_chroot_shell(&session_root);
    fs::write(session_root.join("etc/os-release"), b"ID=catos\n").unwrap();

    let mut effective_plan = plan.clone();
    effective_plan
        .mounts
        .retain(|mount| mount.mount_point == "/home");
    let mountinfo = mountinfo_for_plan(&session_root, &effective_plan);

    let boot = plan
        .mounts
        .iter()
        .find(|mount| mount.mount_point == "/boot")
        .unwrap();
    let home = plan
        .mounts
        .iter()
        .find(|mount| mount.mount_point == "/home")
        .unwrap();
    let mut expected_calls = VecDeque::from([
        mount_call(
            &plan.root.device,
            &session_root,
            &plan.root.mount_point,
            &plan.root.options,
        ),
        mount_call(
            &boot.device,
            &session_root,
            &boot.mount_point,
            &boot.options,
        ),
        mount_call(
            &home.device,
            &session_root,
            &home.mount_point,
            &home.options,
        ),
    ]);
    for runtime in ChrootRuntimeMount::ALL {
        expected_calls.push_back(runtime_call(&session_root, runtime));
    }
    expected_calls.push_back("mountinfo".into());
    expected_calls.push_back(format!(
        "enter:{}:{}",
        session_root.display(),
        plan.use_systemd_chroot
    ));
    for runtime in ChrootRuntimeMount::ALL.into_iter().rev() {
        expected_calls.push_back(unmount_call(
            &session_root.join(runtime.mount_point().trim_start_matches('/')),
        ));
    }
    expected_calls.push_back(unmount_call(&session_root.join("home")));
    expected_calls.push_back(unmount_call(&session_root));

    let mut effects = RecordedEffects {
        expected_calls,
        fail_mount_point: Some("/boot".into()),
        mountinfo: Some(mountinfo),
        ..RecordedEffects::default()
    };

    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::Entered);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("/boot") && warning.contains("failed")));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("/boot/efi") && warning.contains("parent")));
    assert!(!effects.calls.iter().any(|call| call.contains("/boot/efi")));
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn root_mount_failure_remains_fatal() {
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
    let session_root = scratch("root-mount-failure");
    let expected_calls = VecDeque::from([mount_call(
        &plan.root.device,
        &session_root,
        &plan.root.mount_point,
        &plan.root.options,
    )]);
    let mut effects = RecordedEffects {
        expected_calls,
        fail_mount_point: Some("/".into()),
        ..RecordedEffects::default()
    };

    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::MountFailed);
    assert!(report.cleanup_complete);
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn every_runtime_mount_failure_cleans_only_completed_resources_in_reverse_order() {
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

    for (failed_index, failed_runtime) in ChrootRuntimeMount::ALL.into_iter().enumerate() {
        let session_root = scratch(&format!("runtime-failure-{failed_index}"));
        let mut expected_calls = VecDeque::from([mount_call(
            &plan.root.device,
            &session_root,
            &plan.root.mount_point,
            &plan.root.options,
        )]);
        for runtime in &ChrootRuntimeMount::ALL[..=failed_index] {
            expected_calls.push_back(runtime_call(&session_root, *runtime));
        }
        for runtime in ChrootRuntimeMount::ALL[..failed_index].iter().rev() {
            expected_calls.push_back(unmount_call(
                &session_root.join(runtime.mount_point().trim_start_matches('/')),
            ));
        }
        expected_calls.push_back(unmount_call(&session_root));
        let mut effects = RecordedEffects {
            expected_calls,
            fail_runtime: Some(failed_runtime),
            ..RecordedEffects::default()
        };

        let report = execute_plan(&plan, authorization, &session_root, &mut effects);

        assert_eq!(report.outcome, ChrootExecutionOutcome::MountFailed);
        assert!(report.cleanup_complete);
        let mut expected = ChrootRuntimeMount::ALL[..failed_index]
            .iter()
            .rev()
            .map(|runtime| {
                format!(
                    "umount:{}",
                    session_root
                        .join(runtime.mount_point().trim_start_matches('/'))
                        .display()
                )
            })
            .collect::<Vec<_>>();
        expected.push(format!("umount:{}", session_root.display()));
        assert_eq!(
            effects
                .calls
                .iter()
                .filter(|call| call.starts_with("umount:"))
                .cloned()
                .collect::<Vec<_>>(),
            expected,
            "failed runtime mount {}",
            failed_runtime.mount_point()
        );
        effects.assert_consumed();
        let _ = fs::remove_dir_all(session_root);
    }
}

#[test]
fn operator_can_continue_after_failed_final_verification() {
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
    let session_root = scratch("continue-unverified");
    write_valid_arch_chroot_shell(&session_root);
    let mountinfo = mountinfo_for_plan(&session_root, &plan);
    let mut expected_calls = successful_execution_calls(&plan, &session_root);
    let mountinfo_index = expected_calls
        .iter()
        .position(|call| call == "mountinfo")
        .unwrap();
    expected_calls.insert(mountinfo_index + 1, "confirm-unverified".into());
    let mut effects = RecordedEffects {
        expected_calls,
        mountinfo: Some(mountinfo),
        confirm_unverified: Some(true),
        ..RecordedEffects::default()
    };

    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::Entered);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("despite failed verification")));
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn force_unsafe_continues_without_confirmation_callback() {
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
    let session_root = scratch("force-unverified");
    write_valid_arch_chroot_shell(&session_root);
    let mountinfo = mountinfo_for_plan(&session_root, &plan);
    let mut effects = RecordedEffects {
        expected_calls: successful_execution_calls(&plan, &session_root),
        mountinfo: Some(mountinfo),
        ..RecordedEffects::default()
    };

    let report = execute_plan_with_policy(
        &plan,
        authorization,
        &session_root,
        &mut effects,
        ChrootExecutionPolicy {
            allow_unverified: true,
        },
    );

    assert_eq!(report.outcome, ChrootExecutionOutcome::Entered);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("despite failed verification")));
    assert!(!effects
        .calls
        .iter()
        .any(|call| call == "confirm-unverified"));
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn missing_mountinfo_fails_verification_before_entering_chroot() {
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
    let session_root = scratch("missing-mountinfo");
    let mut expected_calls = VecDeque::from([mount_call(
        &plan.root.device,
        &session_root,
        &plan.root.mount_point,
        &plan.root.options,
    )]);
    for runtime in ChrootRuntimeMount::ALL {
        expected_calls.push_back(runtime_call(&session_root, runtime));
    }
    expected_calls.push_back("mountinfo".into());
    for runtime in ChrootRuntimeMount::ALL.into_iter().rev() {
        expected_calls.push_back(unmount_call(
            &session_root.join(runtime.mount_point().trim_start_matches('/')),
        ));
    }
    expected_calls.push_back(unmount_call(&session_root));
    let mut effects = RecordedEffects {
        expected_calls,
        ..RecordedEffects::default()
    };

    let report = execute_plan(&plan, authorization, &session_root, &mut effects);

    assert_eq!(report.outcome, ChrootExecutionOutcome::VerificationFailed);
    assert!(report.cleanup_complete);
    assert!(report
        .failure
        .as_deref()
        .is_some_and(|failure| failure.contains("mountinfo was not configured")));
    assert!(!effects.calls.iter().any(|call| call.starts_with("enter:")));
    effects.assert_consumed();
    let _ = fs::remove_dir_all(session_root);
}

#[test]
fn assembled_verification_rejects_wrong_btrfs_subvolume_identity() {
    let root_device = device("/dev/nvme0n1p3", "btrfs", "root");
    let selected = Subvolume {
        id: 256,
        name: "@".into(),
    };
    let fstab = [FsTabEntry {
        fs_spec: "UUID=root".into(),
        mountpoint: "/home".into(),
        vfs_type: "btrfs".into(),
        mount_options: vec!["subvolid=257".into()],
    }];
    let plan = build_plan(ChrootPlanInputs {
        root_device: &root_device,
        root_subvolume: Some(&selected),
        fstab: &fstab,
        devices: std::slice::from_ref(&root_device),
        extra_mounts: &[],
        use_systemd_chroot: true,
    })
    .unwrap();
    let root = scratch("verify-subvolume");
    fs::create_dir_all(root.join("etc")).unwrap();
    write_valid_arch_chroot_shell(&root);
    fs::write(root.join("etc/os-release"), b"ID=catos\n").unwrap();
    let mountinfo = mountinfo_for_plan(&root, &plan).replace("subvolid=257", "subvolid=999");

    let verification = verify_assembled_target(&root, &plan, &mountinfo);

    assert!(!verification.ready);
    assert!(verification
        .reasons
        .iter()
        .any(|reason| reason.contains("subvolid=257")));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn assembled_verification_rejects_wrong_mount_source() {
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
    let root = scratch("verify-source");
    fs::create_dir_all(root.join("etc")).unwrap();
    write_valid_arch_chroot_shell(&root);
    fs::write(root.join("etc/os-release"), b"ID=catos\n").unwrap();
    let mountinfo = mountinfo_for_plan(&root, &plan).replace("/dev/vda2", "/dev/vda9");

    let verification = verify_assembled_target(&root, &plan, &mountinfo);

    assert!(!verification.ready);
    assert!(verification
        .reasons
        .iter()
        .any(|reason| reason.contains("expected source /dev/vda2")));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn assembled_verification_requires_all_runtime_mounts() {
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
    let root = scratch("verify-runtime");
    fs::create_dir_all(root.join("etc")).unwrap();
    write_valid_arch_chroot_shell(&root);
    fs::write(root.join("etc/os-release"), b"ID=catos\n").unwrap();
    let missing_run = root.join("run").display().to_string();
    let mountinfo = mountinfo_for_plan(&root, &plan)
        .lines()
        .filter(|line| !line.contains(&missing_run))
        .collect::<Vec<_>>()
        .join("\n");

    let verification = verify_assembled_target(&root, &plan, &mountinfo);

    assert!(!verification.ready);
    assert!(verification
        .reasons
        .iter()
        .any(|reason| reason.contains(&missing_run)));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn verification_rejects_symlinked_target_identity() {
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
