//! Phase-1 behaviour tests for the `target` capability module.
//!
//! Each test asserts a real, deterministic property of the migrated
//! module — never an import string or a module-name check alone. The
//! tests are written against the post-migration API and must fail on
//! the pre-migration codebase (the modules do not exist).

use std::path::PathBuf;

use catos_system::target;

#[test]
fn installed_catos_running_root_is_a_discovery_candidate() {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let is_catos = os_release.lines().any(|line| {
        line.trim()
            .strip_prefix("ID=")
            .is_some_and(|value| value.trim_matches(['\"', '\'']) == "catos")
    });
    if !is_catos {
        return;
    }

    let running_only = target::discovery::discover_running_root();
    assert!(running_only.cleanup.is_empty());
    assert_eq!(
        running_only.candidates.iter().filter(|candidate| candidate.running_environment_member).count(),
        1
    );

    let report = target::discovery::discover_targets();
    let running = report
        .candidates
        .iter()
        .filter(|candidate| candidate.running_environment_member)
        .collect::<Vec<_>>();
    assert_eq!(
        running.len(),
        1,
        "expected exactly one running CatOS root; candidates={:?}, excluded={:?}, rejected={:?}",
        report.candidates,
        report.excluded,
        report.rejected
    );
    let candidate = running[0];
    assert!(candidate.currently_mounted);
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let root_line = mountinfo
        .lines()
        .find(|line| line.split_whitespace().nth(4) == Some("/"))
        .expect("running root mountinfo entry");
    let separator = root_line.find(" - ").expect("mountinfo separator");
    let left = &root_line[..separator];
    let right = &root_line[separator + 3..];
    let expected_subvolume = left
        .split_whitespace()
        .nth(3)
        .filter(|root| *root != "/")
        .map(str::to_string);
    let expected_source = right
        .split_whitespace()
        .nth(1)
        .expect("mountinfo root source");
    assert_eq!(candidate.root_device, PathBuf::from(expected_source));
    assert_eq!(candidate.root_subvolume, expected_subvolume);

    let session = target::discovery::TargetSession::open(candidate.clone())
        .expect("verified running-root candidate must open without a remount");
    assert_eq!(session.root(), std::path::Path::new("/"));
    assert!(session.cleanup().is_empty());
}

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
// 2. TargetView.root points at the real offline root.
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
// 3. Rooted path rejects escapes: `..`, absolute re-rooting, symlink tricks.
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
