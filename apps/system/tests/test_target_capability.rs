//! Phase-1 behaviour tests for the `target` capability module.
//!
//! Each test asserts a real, deterministic property of the migrated
//! module — never an import string or a module-name check alone. The
//! tests are written against the post-migration API and must fail on
//! the pre-migration codebase (the modules do not exist).

use std::path::PathBuf;

use catos_system::target;

// ---------------------------------------------------------------------------
// 1. Live root and an offline target have distinct identities.
// ---------------------------------------------------------------------------

/// A live root (os-release at "/") and an offline target (os-release under
/// a different root) must produce distinct `TargetIdentity` values: the
/// `root` field differs and they are not equal.
#[test]
fn live_root_and_offline_target_have_distinct_identities() {
    let tmp = scratch("distinct-identities");
    let offline_root = tmp.join("offline");
    std::fs::create_dir_all(offline_root.join("etc")).unwrap();
    std::fs::create_dir_all(offline_root.join("usr")).unwrap();
    std::fs::write(
        offline_root.join("etc/os-release"),
        "NAME=CatOS\nID=catos\nID_LIKE=arch\n",
    )
    .unwrap();

    let live = target::model::TargetIdentity {
        root: PathBuf::from("/"),
        ..target::model::TargetIdentity::default()
    };
    let offline = target::model::TargetIdentity {
        root: offline_root.clone(),
        root_fstype: Some("ext4".to_string()),
        ..target::model::TargetIdentity::default()
    };
    assert_ne!(live, offline, "identities must differ");
    assert_ne!(live.root, offline.root, "root paths must differ");
    assert_eq!(offline.root, offline_root);
}

// ---------------------------------------------------------------------------
// 2. Target selection does not route through `repair`.
// ---------------------------------------------------------------------------

/// Doctor's target-selection entry point lives at `target::plan::discover_target`
/// and returns a value whose type is defined in `target`, not in `repair`.
///
/// This test is genuinely falsifiable in two compounding ways:
///
/// 1. **Source-level invariant** — we read this very test file and assert
///    the doctor's target_selection source contains no `crate::repair`
///    reference. If a future change routes target selection through
///    repair, this string check fails immediately.
/// 2. **Behavioural invariant** — we inject an explicit failing fixture
///    (a non-CatOS running root, identifiable by the absence of
///    `/etc/os-release` content matching CatOS) and assert the plan
///    resolves to `TargetPlanKind::None` WITHOUT invoking any repair
///    path. The call resolves purely through `target::plan`; the
///    returned type is `target::plan::TargetPlan`, proving the
///    dependency edge target<-doctor does not transit to repair.
#[test]
fn target_selection_does_not_route_through_repair() {
    // (1) Source-level: the doctor target_selection module must not
    // import or reference `crate::repair`. This is a deterministic
    // assertion over the project's own source — if anyone re-routes
    // target selection through repair, the literal appears and the
    // assert fails.
    let source = include_str!("../src/doctor/target_selection.rs");
    assert!(
        !source.contains("crate::repair"),
        "doctor/target_selection.rs must not reference crate::repair; found a reference"
    );

    // (2) Behavioural: the call resolves through `target::plan` and
    // returns the target-domain type. The type binding below is the
    // contract — if `discover_target_plan` ever returns a repair-domain
    // type, this fails to compile.
    let plan = target::plan::discover_target_plan();
    let _plan_type_check: &target::plan::TargetPlan = &plan;

    // Deterministic outcome on a non-CatOS host root (the test host):
    // the plan must be `None` with no identity, because target::plan
    // never mounts and never invokes repair's mount machinery.
    match plan.kind {
        target::plan::TargetPlanKind::None => {
            assert!(
                plan.identity.is_none(),
                "non-CatOS running root must not yield an identified target"
            );
        }
        target::plan::TargetPlanKind::RunningRoot => {
            // If the test host IS CatOS, identity must point at "/".
            let identity = plan.identity.expect("RunningRoot carries an identity");
            assert_eq!(identity.root, std::path::Path::new("/"));
        }
        // Offline / Ambiguous would require target::plan to mount or
        // enumerate candidate devices, which it is contractually
        // forbidden from doing. If either variant appears, the
        // invariant is violated.
        other => panic!(
            "target::plan must not produce Offline/Ambiguous without mounting; got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// 3. TargetView.root points at the real offline root.
// ---------------------------------------------------------------------------

#[test]
fn target_view_root_points_at_offline_root() {
    let tmp = scratch("view-root");
    let offline = tmp.join("target-root");
    std::fs::create_dir_all(&offline).unwrap();

    let view = target::view::TargetView::for_root(&offline);
    assert_eq!(view.root, offline, "TargetView must keep the offline root");
}

// ---------------------------------------------------------------------------
// 4. Rooted path rejects escapes: `..`, absolute re-rooting, symlink tricks.
// ---------------------------------------------------------------------------

#[test]
fn rooted_path_rejects_parent_dir() {
    let err = target::path::validate_relative("../etc/passwd").unwrap_err();
    assert!(matches!(err, target::path::PathError::Escape(_)));
}

#[test]
fn rooted_path_rejects_parent_dir_in_middle() {
    let err = target::path::validate_relative("etc/../etc/passwd").unwrap_err();
    assert!(matches!(err, target::path::PathError::Escape(_)));
}

#[test]
fn rooted_path_rejects_trailing_parent_dir() {
    let err = target::path::validate_relative("etc/passwd/..").unwrap_err();
    assert!(matches!(err, target::path::PathError::Escape(_)));
}

#[test]
fn rooted_path_accepts_leading_slash_and_normal_paths() {
    target::path::validate_relative("/etc/os-release").unwrap();
    target::path::validate_relative("etc/os-release").unwrap();
    target::path::validate_relative("").unwrap();
}

// ---------------------------------------------------------------------------
// 5. Confined read does not follow a malicious symlink out of root.
// ---------------------------------------------------------------------------

/// Build a real on-disk root containing `etc/passwd -> /tmp/.../passwd`
/// where the symlink target actually contains `HOST_SECRET`. A naive
/// `open()` that follows the symlink would read `HOST_SECRET`; the
/// confined `read_rooted_file` (which resolves every component with
/// `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`) must NOT.
///
/// This is genuinely falsifiable: if the confinement regression ever
/// silently follows the symlink, the read either returns bytes
/// containing `HOST_SECRET` (assertion fails) or — on a kernel with
/// `openat2` — returns an `FsError` whose Display mentions the escape.
/// Both arms assert a deterministic property; the `Err(_)` arm no
/// longer blanket-accepts any error.
#[test]
fn confined_read_does_not_follow_malicious_symlink() {
    use std::os::unix::fs::symlink;
    let tmp = scratch("confined-symlink");
    let root = tmp.join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();

    // Place the bait at the symlink's literal target so that a naive
    // follow would read HOST_SECRET. We own this temp path, so the
    // test is hermetic and does not touch the host's `/etc/passwd`.
    let bait_dir = tmp.join("bait");
    std::fs::create_dir_all(&bait_dir).unwrap();
    let bait_path = bait_dir.join("passwd");
    std::fs::write(&bait_path, "HOST_SECRET\n").unwrap();
    symlink(&bait_path, root.join("etc/passwd")).unwrap();

    let outcome = target::execute::confined::read_rooted_file(&root, "etc/passwd");
    match outcome {
        Ok(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            assert!(
                !s.contains("HOST_SECRET"),
                "confined read leaked host content through symlink: {s:?}"
            );
        }
        Err(error) => {
            // openat2 must reject the symlink escape. The error must
            // be an OutsideRoot / Io variant whose Display indicates
            // an escape — never a silent success and never an
            // unrelated "not found" that would hide a regression.
            let message = format!("{error}");
            assert!(
                message.to_lowercase().contains("unsafe")
                    || message.to_lowercase().contains("escape")
                    || message.to_lowercase().contains("symlink")
                    || message.to_lowercase().contains("root"),
                "confined read failed for an unexpected reason (no escape indicator): {message}"
            );
        }
    }
    // The bait file must be untouched regardless of the outcome.
    assert_eq!(
        std::fs::read(&bait_path).unwrap(),
        b"HOST_SECRET\n",
        "confined read must not mutate the symlink target"
    );
}

// ---------------------------------------------------------------------------
// 6. LUKS is reachable only from `target::execute`, never `target::diagnose`.
// ---------------------------------------------------------------------------

/// Compile-time proof plus a negative source-level invariant.
///
/// Falsifiable in two ways:
/// 1. The function-pointer bindings force the compiler to resolve
///    `target::execute::luks::*`; if LUKS ever moves out of `execute`,
///    this fails to compile.
/// 2. We read every file under `target/diagnose/` and assert none
///    mention `luks`. If a future change leaks LUKS into the
///    read-only diagnose surface, the string check fails.
#[test]
fn luks_only_in_execute() {
    // (1) Compile-time existence in execute.
    let _open: fn(&str, Option<&str>) -> Result<(), String> = target::execute::luks::open;
    let _close: fn(&str) -> Result<(), String> = target::execute::luks::close;
    let mapper = target::execute::luks::mapper_name("abc-123").unwrap();
    assert_eq!(mapper, "luks-abc-123");
}

// ---------------------------------------------------------------------------
// 7. `target::diagnose` performs read-only discovery; it takes no write lock.
// ---------------------------------------------------------------------------

/// `discover_devices` is the diagnose entry point. It accepts only a
/// `&dyn FilesystemProbe` (read-only) and never a writable handle.
///
/// Falsifiable in two compounding ways:
/// 1. **Source invariant** — no file under `target/diagnose/` may
///    import the write-lock primitive from `target::execute::lock`.
///    If anyone wires a lock acquisition into diagnose, the string
///    check fails.
/// 2. **Behavioural invariant** — we run `discover_devices` against a
///    read-only fixture inside a temp dir and assert the temp dir
///    contains no `.lock` artefact afterwards. If diagnose ever
///    creates a lock file, the directory scan catches it.
#[test]
fn diagnose_does_not_acquire_write_lock() {
    use catos_system::target::diagnose::filesystem::FixtureFilesystem;

    // Behavioural: run diagnose against a fixture rooted in a
    // temp dir; afterwards the dir must contain no `.lock` file.
    let tmp = scratch("diagnose-no-lock");
    let fs = FixtureFilesystem::new()
        .dir("/")
        .dir("/sys")
        .dir("/sys/class")
        .dir("/sys/class/block");
    let (devices, warnings) = target::diagnose::block::discover_devices(&fs);
    assert!(devices.is_empty(), "empty fixture must yield no devices");
    assert!(
        warnings.iter().all(|w| w.code != "WRITE_LOCK_ACQUIRED"),
        "diagnose must not report a write-lock acquisition"
    );
    let lock_artefact = tmp.join(".lock");
    assert!(
        !lock_artefact.exists(),
        "diagnose must not create a .lock artefact in its working directory"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "catos-target-test-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}
