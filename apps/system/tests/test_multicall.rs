//! Integration test: verify the multicall contract end-to-end by spawning
//! the actual binary.
//!
//! Real risks this guards against:
//! 1. Someone re-introduces three separate binary targets instead of one
//!    multicall binary (defeats size budget + initramfs simplicity).
//! 2. argv[0] handling breaks so invoking via a symlink crashes or gives
//!    a wrong invocation field that downstream tooling keys on.
//! 3. Probe results diverge depending on the entry point (must be identical).

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    // Injected by cargo for the `catos-system` binary target.
    PathBuf::from(env!("CARGO_BIN_EXE_catos-system"))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let mut builder = std::env::temp_dir();
        builder.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&builder)?;
        Ok(Self { path: builder })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Symlink-name -> invocation string. This is the full set of recognised
/// multicall entry points for phase 1.
const ENTRY_POINTS: &[(&str, &str)] = &[
    ("catos-system", "catos-system"),
    ("catos-update", "catos-update"),
    ("catos-recovery", "catos-recovery"),
    ("catos-doctor", "catos-doctor"),
];

#[test]
fn each_symlink_runs_and_reports_correct_invocation() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall").unwrap();
    let mut links = Vec::new();
    for (link_name, _) in ENTRY_POINTS {
        let link_path = tmp.path.join(link_name);
        symlink(&bin, &link_path).unwrap();
        links.push(link_path);
    }

    for (link_path, expected_invocation) in links.iter().zip(ENTRY_POINTS.iter().map(|(_, i)| *i)) {
        let output = Command::new(link_path)
            .arg("inspect")
            .arg("--json")
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", link_path.display()));
        assert!(
            output.status.success(),
            "{} exited with {:?}: stderr={}",
            link_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "invalid JSON from {}: {e}\nraw: {stdout}",
                link_path.display()
            )
        });
        assert_eq!(
            json["invocation"].as_str(),
            Some(expected_invocation),
            "invocation mismatch for {}",
            link_path.display()
        );
    }
}

#[test]
fn core_probe_results_are_identical_across_entry_points() {
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-core").unwrap();

    let mut reports: Vec<serde_json::Value> = Vec::new();
    for (link_name, _) in ENTRY_POINTS {
        let link_path = tmp.path.join(link_name);
        symlink(&bin, &link_path).unwrap();
        let output = Command::new(&link_path)
            .arg("inspect")
            .arg("--json")
            .output()
            .expect("spawn");
        assert!(output.status.success(), "via {}", link_name);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
        // Drop the per-invocation field so we can compare the rest.
        v["invocation"] = serde_json::Value::Null;
        reports.push(v);
    }

    let first = reports[0].to_string();
    for (i, r) in reports.iter().enumerate().skip(1) {
        assert_eq!(
            r.to_string(),
            first,
            "core report differs between entry point 0 and {}",
            i
        );
    }
}

#[test]
fn single_physical_binary_backs_all_entry_points() {
    // Guard against regression where someone adds three `[[bin]]` targets or
    // accidentally produces three files. After following symlinks, all four
    // paths must report the same dev+ino.
    use std::os::unix::fs::MetadataExt;
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-inode").unwrap();

    let mut metas = Vec::new();
    let direct = fs::metadata(&bin).unwrap();
    metas.push((direct.dev(), direct.ino()));
    for (link_name, _) in ENTRY_POINTS {
        let link_path = tmp.path.join(link_name);
        symlink(&bin, &link_path).unwrap();
        let m = fs::metadata(&link_path).unwrap();
        metas.push((m.dev(), m.ino()));
    }
    let first = metas[0];
    for (i, m) in metas.iter().enumerate().skip(1) {
        assert_eq!(
            *m, first,
            "entry point {i} does not share dev/ino with the canonical binary"
        );
    }
}

#[test]
fn unknown_argv0_falls_back_to_canonical_name() {
    // Defends against the case where the binary is invoked under an unknown
    // name (e.g. via a renamed copy). The fallback must be `catos-system`,
    // never a crash.
    let bin = bin_path();
    let tmp = TempDir::new("catos-multicall-unknown").unwrap();
    let link = tmp.path.join("totally-unknown-tool");
    symlink(&bin, &link).unwrap();
    let output = Command::new(&link)
        .arg("inspect")
        .arg("--json")
        .output()
        .expect("spawn");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap();
    assert_eq!(v["invocation"].as_str(), Some("catos-system"));
}
