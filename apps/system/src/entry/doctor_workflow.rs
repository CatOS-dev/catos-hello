//! Interactive Doctor recommendation execution and automatic recheck.
//!
//! Standalone `catos-doctor` remains read-only. Only the aggregate interactive
//! maintenance entry invokes typed, allow-listed actions from a completed
//! Doctor report. Human command strings are never parsed or executed.

use super::*;

pub(super) const ACTION: &str = "workflow";
pub(super) const MENU_ACTIONS: &[&str] = &[ACTION];

enum DoctorPresentation {
    Completed {
        report: Box<crate::doctor::model::DoctorReport>,
        exit: i32,
    },
    Declined,
    Failed(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorWorkflowChoice {
    action: crate::doctor::model::DoctorAction,
    message: String,
    label: String,
}

pub(super) fn run_standalone(context: CommandContext) -> i32 {
    match present_doctor(context) {
        DoctorPresentation::Completed { exit, .. } | DoctorPresentation::Failed(exit) => exit,
        DoctorPresentation::Declined => exit_code::SUCCESS,
    }
}

fn present_doctor(context: CommandContext) -> DoctorPresentation {
    let report = match crate::doctor::run_doctor() {
        crate::doctor::DoctorRunOutcome::Completed(report) => report,
        crate::doctor::DoctorRunOutcome::Declined => return DoctorPresentation::Declined,
    };
    let mut exit = crate::output::doctor_exit_code_for(&report);
    let mut rendered = Vec::new();
    if let Err(error) = crate::output::render_doctor_human_with_columns(
        &report,
        &mut rendered,
        pager::output_columns(),
    ) {
        eprintln!("{}: {error}", context.program);
        return DoctorPresentation::Failed(error.exit_code());
    }
    let rendered = match String::from_utf8(rendered) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("{}: rendered report is not UTF-8: {error}", context.program);
            return DoctorPresentation::Failed(crate::error::exit_code::SERIALIZE_FAILED);
        }
    };
    if let Err(error) = pager::present(&rendered) {
        eprintln!("{}: stdout write failed: {error}", context.program);
        return DoctorPresentation::Failed(crate::error::exit_code::PROBE_FAILED);
    }
    if matches!(
        report.target.kind,
        crate::doctor::model::DoctorTargetKind::None
    ) {
        exit = crate::error::exit_code::PROBE_FAILED;
    }
    DoctorPresentation::Completed { report, exit }
}

pub(super) fn run(context: CommandContext) -> i32 {
    let continuation = vec![INTERACTIVE_MENU_MARKER.to_string(), ACTION.to_string()];
    if let Some(exit) =
        elevation::elevate_interactive_if_needed("doctor", &continuation, context.program)
    {
        return exit;
    }
    run_elevated(context)
}

pub(super) fn run_elevated(context: CommandContext) -> i32 {
    loop {
        let (report, report_exit) = match present_doctor(context) {
            DoctorPresentation::Completed { report, exit } => (report, exit),
            DoctorPresentation::Declined => return exit_code::SUCCESS,
            DoctorPresentation::Failed(exit) => return exit,
        };
        if report_exit != exit_code::SUCCESS {
            return report_exit;
        }

        let choices = executable_doctor_actions(&report);
        if choices.is_empty() {
            if let Err(error) =
                write_interactive_text("No directly executable Doctor recommendations remain.\n")
            {
                eprintln!("{}: {error}", context.program);
                return exit_code::PROBE_FAILED;
            }
            return exit_code::SUCCESS;
        }

        loop {
            let labels = choices
                .iter()
                .map(|choice| choice.label.as_str())
                .collect::<Vec<_>>();
            let selected = match menu::choose("Doctor Recommended Actions", &labels) {
                Ok(selected) => selected,
                Err(error) => {
                    eprintln!("{}: {error}", context.program);
                    return exit_code::PROBE_FAILED;
                }
            };
            let Some(selected) = selected else {
                return exit_code::SUCCESS;
            };
            let choice = &choices[selected];
            match execute_doctor_action(&report, choice) {
                Ok(None) => continue,
                Ok(Some(exit)) => {
                    if exit != exit_code::SUCCESS {
                        eprintln!(
                            "{}: recommended action failed with exit status {exit}",
                            context.program
                        );
                    }
                    if let Err(error) = write_interactive_text(
                        "Re-running Doctor to verify the selected target...\n",
                    ) {
                        eprintln!("{}: {error}", context.program);
                        return exit_code::PROBE_FAILED;
                    }
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "{}: recommended action could not start: {error}",
                        context.program
                    );
                    if let Err(output_error) = write_interactive_text(
                        "Re-running Doctor to verify the selected target...\n",
                    ) {
                        eprintln!("{}: {output_error}", context.program);
                        return exit_code::PROBE_FAILED;
                    }
                    break;
                }
            }
        }
    }
}

fn executable_doctor_actions(
    report: &crate::doctor::model::DoctorReport,
) -> Vec<DoctorWorkflowChoice> {
    use crate::doctor::model::{DoctorAction, DoctorTargetKind};
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut choices = Vec::new();
    for recommendation in &report.recommendations {
        let Some(action) = recommendation.action.clone() else {
            continue;
        };
        let target_is_safe = match action {
            DoctorAction::RepairFilesystem
            | DoctorAction::ResumeRecovery { .. }
            | DoctorAction::RevertRecovery { .. } => {
                report.target.kind == DoctorTargetKind::Offline
            }
            DoctorAction::RepairMountLayout | DoctorAction::RepairBootSetup => {
                report.target.kind != DoctorTargetKind::None
            }
        };
        if !target_is_safe || !seen.insert(action.clone()) {
            continue;
        }
        choices.push(DoctorWorkflowChoice {
            label: doctor_action_label(report, &action),
            action,
            message: recommendation.message.clone(),
        });
    }
    choices
}

fn doctor_action_label(
    report: &crate::doctor::model::DoctorReport,
    action: &crate::doctor::model::DoctorAction,
) -> String {
    use crate::doctor::model::DoctorAction;
    let device = report
        .target
        .root_device
        .as_deref()
        .map(crate::selection_ui::terminal_text)
        .unwrap_or_else(|| "unknown target".into());
    match action {
        DoctorAction::RepairFilesystem => format!("Repair filesystem on {device}"),
        DoctorAction::RepairMountLayout => format!("Repair mount layout on {device}"),
        DoctorAction::RepairBootSetup => format!("Repair boot setup on {device}"),
        DoctorAction::ResumeRecovery { transaction_id } => format!(
            "Resume recovery transaction {}",
            crate::selection_ui::terminal_text(transaction_id)
        ),
        DoctorAction::RevertRecovery { transaction_id } => format!(
            "Revert recovery transaction {}",
            crate::selection_ui::terminal_text(transaction_id)
        ),
    }
}

fn doctor_report_target(
    report: &crate::doctor::model::DoctorReport,
) -> Result<InteractiveTarget, String> {
    let device = report.target.root_device.clone().ok_or_else(|| {
        "Doctor recommendation has no selected root device; refusing execution".to_string()
    })?;
    if !validate_repair_device_arg(std::path::Path::new(&device)) {
        return Err(format!(
            "Doctor selected an unsafe root device path {:?}",
            crate::selection_ui::terminal_text(&device)
        ));
    }
    if let Some(esp) = report.target.esp_device.as_deref() {
        if !validate_repair_device_arg(std::path::Path::new(esp)) {
            return Err(format!(
                "Doctor selected an unsafe ESP device path {:?}",
                crate::selection_ui::terminal_text(esp)
            ));
        }
    }
    Ok(InteractiveTarget::Explicit {
        device,
        root_subvolume: report.target.root_subvolume.clone(),
        esp_device: report.target.esp_device.clone(),
    })
}

fn execute_doctor_action(
    report: &crate::doctor::model::DoctorReport,
    choice: &DoctorWorkflowChoice,
) -> Result<Option<i32>, String> {
    use crate::doctor::model::DoctorAction;

    let target = doctor_report_target(report)?;
    let include_esp = matches!(
        choice.action,
        DoctorAction::RepairMountLayout | DoctorAction::RepairBootSetup
    );
    write_interactive_text(&format!(
        "Recommendation: {}\n{}",
        crate::selection_ui::terminal_text(&choice.message),
        interactive_target_summary(&target, include_esp)
    ))?;
    let confirmation = match choice.action {
        DoctorAction::RepairFilesystem => "Repair this filesystem now?",
        DoctorAction::RepairMountLayout => "Repair this target's mount layout now?",
        DoctorAction::RepairBootSetup => "Repair this target's boot setup now?",
        DoctorAction::ResumeRecovery { .. } => "Resume this recovery transaction now?",
        DoctorAction::RevertRecovery { .. } => "Revert this recovery transaction now?",
    };
    if !menu::confirm(confirmation)? {
        return Ok(None);
    }

    let exit = match &choice.action {
        DoctorAction::RepairFilesystem => run_repair(
            CommandContext::aggregate(Invocation::CatosRepair),
            &repair_args("fs", &target),
        ),
        DoctorAction::RepairMountLayout => run_repair(
            CommandContext::aggregate(Invocation::CatosRepair),
            &repair_args("mount", &target),
        ),
        DoctorAction::RepairBootSetup => run_repair(
            CommandContext::aggregate(Invocation::CatosRepair),
            &repair_args("boot", &target),
        ),
        DoctorAction::ResumeRecovery { transaction_id } => {
            let mut args = vec!["resume".to_string()];
            append_recovery_target_args(&mut args, &target);
            args.extend(["--transaction".into(), transaction_id.clone()]);
            run_context(CommandContext::aggregate(Invocation::CatosRecovery), &args)
        }
        DoctorAction::RevertRecovery { transaction_id } => {
            let status = load_recovery_status(&target, transaction_id)?;
            let token = status.revert_confirmation_token.ok_or_else(|| {
                format!(
                    "transaction {:?} cannot be reverted from state {}",
                    crate::selection_ui::terminal_text(transaction_id),
                    status.reconciled_state.code()
                )
            })?;
            let mut args = vec!["revert".to_string()];
            append_recovery_target_args(&mut args, &target);
            args.extend([
                "--transaction".into(),
                transaction_id.clone(),
                "--confirm".into(),
                token,
            ]);
            run_context(CommandContext::aggregate(Invocation::CatosRecovery), &args)
        }
    };
    Ok(Some(exit))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doctor_report_with_target(
        kind: crate::doctor::model::DoctorTargetKind,
    ) -> crate::doctor::model::DoctorReport {
        let mut report = crate::doctor::model::DoctorReport::default();
        report.target.kind = kind;
        report.target.root_device = Some("/dev/vda2".into());
        report.target.root_subvolume = Some("/@".into());
        report.target.esp_device = Some("/dev/vda1".into());
        report
    }

    #[test]
    fn doctor_workflow_ignores_untyped_command_text() {
        let mut report = doctor_report_with_target(crate::doctor::model::DoctorTargetKind::Offline);
        report.recommendations.push(
            crate::doctor::model::DoctorRecommendation::new("UNTRUSTED", "text only")
                .with_command("catos-repair mount; echo should-not-run"),
        );
        assert!(executable_doctor_actions(&report).is_empty());
    }

    #[test]
    fn doctor_workflow_deduplicates_typed_actions() {
        use crate::doctor::model::{DoctorAction, DoctorRecommendation, DoctorTargetKind};
        let mut report = doctor_report_with_target(DoctorTargetKind::Offline);
        for message in ["first", "second"] {
            report.recommendations.push(
                DoctorRecommendation::new("RUN_CATOS_REPAIR_MOUNT", message)
                    .with_action(DoctorAction::RepairMountLayout),
            );
        }
        let choices = executable_doctor_actions(&report);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].action, DoctorAction::RepairMountLayout);
        assert_eq!(choices[0].message, "first");
    }

    #[test]
    fn doctor_workflow_filters_offline_only_actions_on_running_root() {
        use crate::doctor::model::{DoctorAction, DoctorRecommendation, DoctorTargetKind};
        let mut report = doctor_report_with_target(DoctorTargetKind::RunningRoot);
        for action in [
            DoctorAction::RepairFilesystem,
            DoctorAction::ResumeRecovery {
                transaction_id: "tx-00000000000000000000000000000004".into(),
            },
            DoctorAction::RepairMountLayout,
            DoctorAction::RepairBootSetup,
        ] {
            report
                .recommendations
                .push(DoctorRecommendation::new("RUN", "action").with_action(action));
        }
        let actions = executable_doctor_actions(&report)
            .into_iter()
            .map(|choice| choice.action)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            [
                DoctorAction::RepairMountLayout,
                DoctorAction::RepairBootSetup
            ]
        );
    }

    #[test]
    fn doctor_target_preserves_execution_identity_and_rejects_missing_device() {
        let report = doctor_report_with_target(crate::doctor::model::DoctorTargetKind::Offline);
        assert_eq!(
            doctor_report_target(&report).unwrap(),
            InteractiveTarget::Explicit {
                device: "/dev/vda2".into(),
                root_subvolume: Some("/@".into()),
                esp_device: Some("/dev/vda1".into()),
            }
        );
        let mut missing = report;
        missing.target.root_device = None;
        assert!(doctor_report_target(&missing)
            .unwrap_err()
            .contains("no selected root device"));
    }

    #[test]
    fn doctor_action_label_escapes_terminal_controls() {
        let report = doctor_report_with_target(crate::doctor::model::DoctorTargetKind::Offline);
        let action = crate::doctor::model::DoctorAction::ResumeRecovery {
            transaction_id: "tx-1\nspoof\x1b[2J".into(),
        };
        let label = doctor_action_label(&report, &action);
        assert!(!label.contains('\n'));
        assert!(!label.contains('\x1b'));
        assert!(label.contains("tx-1\\nspoof\\u{1b}[2J"));
    }
}
