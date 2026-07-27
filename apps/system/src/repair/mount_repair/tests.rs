//! Unit tests for mount repair.

    use super::*;
    use crate::repair::subvol_decision::SubvolObservation;

    fn target_root_uuid(uuid: &str) -> TargetIdentity {
        TargetIdentity {
            root_device: PathBuf::from("/dev/sda2"),
            root_fstype: "btrfs".into(),
            root_subvol: Some("/@".into()),
            root_uuid: Some(uuid.into()),
            esp_device: None,
            esp_uuid: None,
            boot_layout: None,
        }
    }

    fn observation_present(subvol: &str) -> SubvolObservation {
        SubvolObservation {
            subvol: subvol.to_string(),
            exists_as_subvol: true,
            exists_as_directory: false,
            exists_as_other: false,
            mount_point_entry_count: Some(0),
        }
    }

    fn observation_missing(subvol: &str) -> SubvolObservation {
        SubvolObservation {
            subvol: subvol.to_string(),
            exists_as_subvol: false,
            exists_as_directory: false,
            exists_as_other: false,
            mount_point_entry_count: None,
        }
    }

    fn all_standard_present() -> Vec<SubvolObservation> {
        crate::shared::model::mount_repair::CATOS_STANDARD_SUBVOLS
            .iter()
            .map(|s| observation_present(s.subvol))
            .collect()
    }

    fn selection_device(path: &str, mount_point: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("device")
                .to_string(),
            dev_path: Some(PathBuf::from(path)),
            major_minor: Some("8:2".into()),
            parent: "sda".into(),
            class: DeviceClass::Partition,
            disk_kind: crate::shared::model::storage::DiskKind::Gpt,
            partition_role: PartitionRole::LinuxFilesystem,
            partition_number: Some(2),
            size_sectors: Some(1_000_000),
            read_only: false,
            removable: false,
            filesystem: Some("ext4".into()),
            uuid: Some("root-uuid".into()),
            part_uuid: None,
            label: None,
            part_label: None,
            mount_point: mount_point.map(PathBuf::from),
            mounts: mount_point
                .map(|point| {
                    vec![crate::shared::model::storage::MountObservation {
                        mount_point: PathBuf::from(point),
                        root: PathBuf::from("/"),
                        fstype: "ext4".into(),
                        read_only: false,
                    }]
                })
                .unwrap_or_default(),
            mounted_before_session: mount_point.is_some(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn boot_runtime_bind_recurses_only_for_dev_and_proc() {
        for source in ["/dev", "/proc"] {
            assert_ne!(boot_runtime_bind_flags(source) & ms_flags::MS_REC, 0);
        }
        for source in ["/sys", "/run"] {
            assert_eq!(boot_runtime_bind_flags(source), ms_flags::MS_BIND);
        }
    }

    #[test]
    fn explicit_running_root_is_selectable_but_other_mounted_device_is_not() {
        let running = selection_device("/dev/sda2", Some("/"));
        let data = selection_device("/dev/sdb1", Some("/data"));
        assert!(is_running_root_device(&running));
        assert!(!is_running_root_device(&data));
        assert!(select_cli_root(&[running], Some("/dev/sda2")).is_some());
        assert!(select_cli_root(&[data], Some("/dev/sdb1")).is_none());
    }

    // ---- Spec § 十一 → fstab 修复 ----

    #[test]
    fn clean_fstab_diagnoses_no_problems() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: all_standard_present(),
            },
            mount_point_observations: HashMap::new(),
        };
        let problems = diagnose(&inputs);
        // /@ and /@home present; other standard subvols are missing
        // but they are not CatOS-confirmed and have no fstab history,
        // so they do NOT surface as problems.
        let root_problems: Vec<_> = problems
            .iter()
            .filter(|p| matches!(p, MountProblem::RootWrongSubvol { .. }))
            .collect();
        assert!(root_problems.is_empty());
    }

    #[test]
    fn directory_plan_never_contains_the_target_root() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root / btrfs defaults,subvol=/@ 0 0\n".into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: all_standard_present(),
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .directories
            .iter()
            .all(|directory| directory.mount_point != "/"));
    }

    #[test]
    fn wrong_root_uuid_surfaces_problem() {
        let fstab = "UUID=wrong  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("correct"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let problems = diagnose(&inputs);
        assert!(problems
            .iter()
            .any(|p| matches!(p, MountProblem::RootUuidMismatch { .. })));
    }

    #[test]
    fn wrong_root_subvol_surfaces_problem_and_plan_fixes_it() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@wrong  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::RootWrongSubvol { .. })));
        // The plan must include a full entry replace for the root.
        assert!(plan
            .fstab_edits
            .iter()
            .any(|e| matches!(e, PlannedFstabEdit::ReplaceEntry { line: 1, .. })));
    }

    #[test]
    fn missing_standard_entry_on_confirmed_catos_surfaces_and_appends() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_missing("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::MissingStandardEntry { mount_point, .. } if mount_point == "/home")));
        assert!(plan.fstab_edits.iter().any(|e| matches!(
            e,
            PlannedFstabEdit::AppendEntry { new_line, .. } if new_line.contains("/home")
        )));
    }

    #[test]
    fn duplicate_mount_point_surfaces_and_no_append() {
        let fstab = "UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|p| matches!(p, MountProblem::DuplicateMountPoint { mount_point } if mount_point == "/home")));
        // We must NOT append a third entry.
        assert!(!plan
            .fstab_edits
            .iter()
            .any(|e| matches!(e, PlannedFstabEdit::AppendEntry { .. })));
    }

    #[test]
    fn swap_entries_are_never_modified() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                     UUID=swap  none  swap  defaults  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        // No edit targets the swap line.
        assert!(!plan.fstab_edits.iter().any(|e| matches!(
            e,
            PlannedFstabEdit::ReplaceSource { line: 2, .. }
                | PlannedFstabEdit::ReplaceEntry { line: 2, .. }
                | PlannedFstabEdit::DropDuplicate { line: 2, .. }
        )));
    }

    // ---- Spec § 十一 → 事务 / 回滚 at model level ----

    #[test]
    fn detect_drift_flags_device_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let mut new_target = inputs.target.clone();
        new_target.root_uuid = Some("different".into());
        let drift = detect_drift(&plan, &new_target, &plan.fstab_digest);
        assert_eq!(drift, Some(MountRepairOutcome::DeviceChanged));
    }

    #[test]
    fn detect_drift_flags_fstab_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let new_digest = digest_of("UUID=changed  /  btrfs  defaults  0 0\n");
        let drift = detect_drift(&plan, &inputs.target, &new_digest);
        assert_eq!(drift, Some(MountRepairOutcome::FstabChanged));
    }

    #[test]
    fn detect_drift_returns_none_when_no_change() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n".into(),
            target: target_root_uuid("root"),
            ..Default::default()
        };
        let plan = build_plan(&inputs);
        let drift = detect_drift(&plan, &inputs.target, &plan.fstab_digest);
        assert!(drift.is_none());
    }

    #[test]
    fn apply_in_memory_preserves_comments_and_fixes_root_subvol() {
        let fstab = "# header\n\
                     UUID=root  /  btrfs  defaults,subvol=/@wrong  0 0\n\
                     \n\
                     # home\n\
                     UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_present("/@home")],
            },
            mount_point_observations: HashMap::new(),
        };
        let plan = build_plan(&inputs);
        let new_text = apply_in_memory(&inputs.fstab_text, &plan).unwrap();
        // Comments preserved.
        assert!(new_text.contains("# header"));
        assert!(new_text.contains("# home"));
        // Blank line preserved.
        assert!(new_text.contains("\n\n"));
        // Root subvol fixed.
        assert!(new_text.contains("subvol=/@  0 0"));
        assert!(!new_text.contains("@wrong"));
        // /home untouched.
        assert!(new_text.contains("UUID=root  /home  btrfs  defaults,subvol=/@home  0 0"));
    }

    #[test]
    fn root_entry_fix_retains_the_discovered_uuid_when_subvol_is_also_wrong() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=old  /  btrfs  defaults,compress=zstd:3,subvol=/wrong  0 1\n".into(),
            target: target_root_uuid("new"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };

        let rewritten = apply_in_memory(&inputs.fstab_text, &build_plan(&inputs)).unwrap();

        assert!(rewritten.contains("UUID=new  /  btrfs  defaults,compress=zstd:3,subvol=/@  0 1"));
        assert!(!rewritten.contains("UUID=old"));
    }

    #[test]
    fn snapshots_wrong_subvol_rewrites_the_snapshots_entry() {
        let inputs = MountRepairInputs {
            fstab_text: "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n\
                         UUID=root  /.snapshots  btrfs  defaults,subvol=/@wrong  0 0\n"
                .into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![
                    observation_present("/@"),
                    observation_present("/@snapshots"),
                ],
            },
            mount_point_observations: HashMap::new(),
        };

        let plan = build_plan(&inputs);
        assert!(plan
            .problems
            .iter()
            .any(|problem| matches!(problem, MountProblem::SnapshotsWrongSubvol { .. })));

        let rewritten = apply_in_memory(&inputs.fstab_text, &plan).unwrap();
        assert!(rewritten.contains("/.snapshots  btrfs  defaults,subvol=/@snapshots  0 0"));
        assert!(!rewritten.contains("subvol=/@wrong"));
    }

    #[test]
    fn run_diagnosis_marks_clean_when_no_problems() {
        let fstab = "UUID=root  /  btrfs  defaults,subvol=/@  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let report = run_mount_repair_diagnosis(inputs, true);
        assert_eq!(report.final_outcome, MountRepairOutcome::Clean);
        assert!(report.fully_complete);
    }

    #[test]
    fn run_diagnosis_marks_data_conflict_as_partial() {
        // Spec § 五 / § 十一: when mount-point has data, the result
        // MUST NOT be reported as fully repaired.
        let fstab = "UUID=root  /home  btrfs  defaults,subvol=/@home  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("root"),
            catos_confirmation: CatosConfirmation::NotConfirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@"), observation_missing("/@home")],
            },
            mount_point_observations: {
                let mut m = HashMap::new();
                m.insert(
                    "/home".to_string(),
                    MountPointObservation {
                        exists: true,
                        is_directory: true,
                        entry_count: Some(5),
                        ..Default::default()
                    },
                );
                m
            },
        };
        let report = run_mount_repair_diagnosis(inputs, true);
        assert_eq!(report.final_outcome, MountRepairOutcome::PartiallyRepaired);
        assert!(!report.fully_complete);
        assert!(report.requires_human_action);
    }

    #[test]
    fn unauthorised_run_does_not_attempt_apply() {
        let fstab = "UUID=wrong  /  btrfs  defaults,subvol=/@wrong  0 0\n";
        let inputs = MountRepairInputs {
            fstab_text: fstab.into(),
            target: target_root_uuid("correct"),
            catos_confirmation: CatosConfirmation::Confirmed,
            subvol_facts: SubvolFacts {
                observations: vec![observation_present("/@")],
            },
            mount_point_observations: HashMap::new(),
        };
        let report = run_mount_repair_diagnosis(inputs, false);
        // Diagnosis-only path: outcome is Clean (we didn't change
        // anything) but requires_human_action reflects that problems
        // exist.
        assert_eq!(report.final_outcome, MountRepairOutcome::Clean);
        assert!(report.requires_human_action);
        assert!(!report.fully_complete);
        assert!(report.actions.is_empty());
    }
