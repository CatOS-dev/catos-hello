//! Read-only validation of an assembled Chroot target.

use std::path::{Path, PathBuf};

use crate::model::{ChrootMount, ChrootPlan, ChrootVerification};
use catos_target::execute::confined::{
    read_rooted_file, rooted_path_kind, rooted_regular_file_mode, rooted_regular_file_size,
    RootedPathKind,
};
use catos_target::model::OsRelease;
use catos_target::mountinfo::{self, MountInfo};
use catos_target::FsError;

pub fn verify_target_root(root: &Path) -> ChrootVerification {
    let mut checks = Vec::new();
    let mut reasons = Vec::new();

    let identity = ["/usr/lib/os-release", "/etc/os-release"]
        .into_iter()
        .find_map(|path| match rooted_regular_file_size(root, path) {
            Ok(Some(_)) => match read_rooted_file(root, path) {
                Ok(bytes) if !bytes.is_empty() => match std::str::from_utf8(&bytes) {
                    Ok(content) => {
                        let release = OsRelease::parse(content);
                        if release.looks_like_catos() {
                            Some(path.to_string())
                        } else {
                            reasons.push(format!("target {path} does not identify CatOS"));
                            None
                        }
                    }
                    Err(error) => {
                        reasons.push(format!("target {path} is not valid UTF-8: {error}"));
                        None
                    }
                },
                Ok(_) => None,
                Err(error) => {
                    reasons.push(format!("cannot read target {path}: {error}"));
                    None
                }
            },
            Ok(None) | Err(FsError::NotFound) => None,
            Err(error) => {
                reasons.push(format!("cannot inspect target {path}: {error}"));
                None
            }
        });
    if let Some(path) = identity {
        checks.push(format!("target CatOS identity: {path}"));
    } else if !reasons.iter().any(|reason| reason.contains("os-release")) {
        reasons.push("target os-release was not found".into());
    }

    verify_arch_chroot_shell(root, &mut checks, &mut reasons);

    ChrootVerification {
        ready: reasons.is_empty(),
        checks,
        reasons,
    }
}

fn verify_arch_chroot_shell(root: &Path, checks: &mut Vec<String>, reasons: &mut Vec<String>) {
    let bash_path = match rooted_path_kind(root, "/bin") {
        Ok(Some(RootedPathKind::Directory)) => "/bin/bash",
        Ok(Some(RootedPathKind::Symlink)) => {
            let link = match std::fs::read_link(root.join("bin")) {
                Ok(link) => link,
                Err(error) => {
                    reasons.push(format!(
                        "cannot inspect target /bin symlink required by /bin/bash: {error}"
                    ));
                    return;
                }
            };
            if link != Path::new("usr/bin") && link != Path::new("/usr/bin") {
                reasons.push(format!(
                    "target /bin symlink resolves to {}, not usr/bin required for /bin/bash",
                    link.display()
                ));
                return;
            }
            "/usr/bin/bash"
        }
        Ok(Some(_)) => {
            reasons.push("target /bin is neither a directory nor the merged-/usr symlink".into());
            return;
        }
        Ok(None) | Err(FsError::NotFound) => {
            reasons.push("target /bin required for /bin/bash is missing".into());
            return;
        }
        Err(error) => {
            reasons.push(format!("cannot inspect target /bin for /bin/bash: {error}"));
            return;
        }
    };

    let size = match rooted_regular_file_size(root, bash_path) {
        Ok(Some(size)) => size,
        Ok(None) | Err(FsError::NotFound) => {
            reasons.push(format!(
                "target /bin/bash entrypoint is missing ({bash_path} not found)"
            ));
            return;
        }
        Err(error) => {
            reasons.push(format!(
                "cannot inspect target /bin/bash at {bash_path}: {error}"
            ));
            return;
        }
    };
    if size == 0 {
        reasons.push(format!(
            "target /bin/bash entrypoint at {bash_path} is empty"
        ));
        return;
    }
    let mode = match rooted_regular_file_mode(root, bash_path) {
        Ok(Some(mode)) => mode,
        Ok(None) | Err(FsError::NotFound) => {
            reasons.push(format!(
                "target /bin/bash entrypoint at {bash_path} disappeared"
            ));
            return;
        }
        Err(error) => {
            reasons.push(format!(
                "cannot inspect target /bin/bash permissions at {bash_path}: {error}"
            ));
            return;
        }
    };
    if mode & 0o111 == 0 {
        reasons.push(format!(
            "target /bin/bash entrypoint at {bash_path} is not executable"
        ));
        return;
    }
    checks.push(format!("target /bin/bash entrypoint: {bash_path}"));
}

pub fn verify_assembled_target(
    root: &Path,
    plan: &ChrootPlan,
    mountinfo_body: &str,
) -> ChrootVerification {
    let mut verification = verify_target_root(root);
    let mounts = mountinfo::parse_all(mountinfo_body);
    if mounts.is_empty() {
        verification
            .reasons
            .push("mountinfo contained no parseable mount entries".into());
        verification.ready = false;
        return verification;
    }

    verify_block_mount(root, &plan.root, &mounts, &mut verification);
    for mount in &plan.mounts {
        verify_block_mount(root, mount, &mounts, &mut verification);
    }
    verify_runtime_filesystems(root, &mounts, &mut verification);
    verification.ready = verification.reasons.is_empty();
    verification
}

fn verify_block_mount(
    root: &Path,
    expected: &ChrootMount,
    mounts: &[MountInfo],
    verification: &mut ChrootVerification,
) {
    let target = target_path(root, &expected.mount_point);
    let reason_count = verification.reasons.len();
    let Some(actual) = unique_mount_at(&target, mounts, verification) else {
        return;
    };

    if actual.source != expected.device.name {
        verification.reasons.push(format!(
            "{} expected source {}, observed {}",
            expected.mount_point, expected.device.name, actual.source
        ));
    }
    match expected.device.fs_type.as_deref() {
        Some(fstype) if !actual.fstype.eq_ignore_ascii_case(fstype) => {
            verification.reasons.push(format!(
                "{} expected filesystem {}, observed {}",
                expected.mount_point, fstype, actual.fstype
            ));
        }
        None => verification.reasons.push(format!(
            "{} has no expected filesystem identity",
            expected.mount_point
        )),
        Some(_) => {}
    }

    if let Some(selector) = expected.options.first() {
        verify_btrfs_selector(expected, actual, selector, verification);
    }

    if verification.reasons.len() == reason_count {
        verification.checks.push(format!(
            "mounted {} from {} as {}",
            expected.mount_point, actual.source, actual.fstype
        ));
    }
}

fn verify_btrfs_selector(
    expected: &ChrootMount,
    actual: &MountInfo,
    selector: &str,
    verification: &mut ChrootVerification,
) {
    if !actual.fstype.eq_ignore_ascii_case("btrfs") {
        verification.reasons.push(format!(
            "{} expected Btrfs selector {selector}, observed filesystem {}",
            expected.mount_point, actual.fstype
        ));
        return;
    }
    let matches = if let Some(id) = selector.strip_prefix("subvolid=") {
        actual
            .super_options
            .iter()
            .any(|option| option == &format!("subvolid={id}"))
    } else if let Some(name) = selector.strip_prefix("subvol=") {
        let expected_name = normalize_subvolume(name);
        normalize_subvolume(&actual.root) == expected_name
            || actual.super_options.iter().any(|option| {
                option
                    .strip_prefix("subvol=")
                    .is_some_and(|actual_name| normalize_subvolume(actual_name) == expected_name)
            })
    } else {
        false
    };
    if !matches {
        verification.reasons.push(format!(
            "{} expected Btrfs {selector}, observed root {} with options {}",
            expected.mount_point,
            actual.root,
            actual.super_options.join(",")
        ));
    }
}

fn verify_runtime_filesystems(
    root: &Path,
    mounts: &[MountInfo],
    verification: &mut ChrootVerification,
) {
    verify_runtime_type(root, "/proc", "proc", mounts, verification);
    verify_runtime_type(root, "/sys", "sysfs", mounts, verification);
    verify_bind_mount(root, "/dev", mounts, verification);
    verify_bind_mount(root, "/run", mounts, verification);
}

fn verify_runtime_type(
    root: &Path,
    mount_point: &str,
    expected_fstype: &str,
    mounts: &[MountInfo],
    verification: &mut ChrootVerification,
) {
    let target = target_path(root, mount_point);
    let Some(actual) = unique_mount_at(&target, mounts, verification) else {
        return;
    };
    if actual.fstype != expected_fstype {
        verification.reasons.push(format!(
            "runtime {mount_point} expected {expected_fstype}, observed {}",
            actual.fstype
        ));
    } else {
        verification.checks.push(format!(
            "runtime {mount_point} mounted as {expected_fstype}"
        ));
    }
}

fn verify_bind_mount(
    root: &Path,
    mount_point: &str,
    mounts: &[MountInfo],
    verification: &mut ChrootVerification,
) {
    let source_path = Path::new(mount_point);
    let target = target_path(root, mount_point);
    let Some(source) = unique_mount_at(source_path, mounts, verification) else {
        verification
            .reasons
            .push(format!("host source mount {mount_point} is unavailable"));
        return;
    };
    let Some(actual) = unique_mount_at(&target, mounts, verification) else {
        return;
    };
    if actual.major_minor != source.major_minor
        || actual.root != source.root
        || actual.fstype != source.fstype
        || actual.source != source.source
    {
        verification.reasons.push(format!(
            "runtime {mount_point} is not a bind of host {mount_point}: expected {} {} {} {}, observed {} {} {} {}",
            source.major_minor,
            source.root,
            source.fstype,
            source.source,
            actual.major_minor,
            actual.root,
            actual.fstype,
            actual.source
        ));
    } else {
        verification.checks.push(format!(
            "runtime {mount_point} bound from host {mount_point}"
        ));
    }
}

fn unique_mount_at<'a>(
    target: &Path,
    mounts: &'a [MountInfo],
    verification: &mut ChrootVerification,
) -> Option<&'a MountInfo> {
    let matches = mounts
        .iter()
        .filter(|mount| mount.mount_point == target)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [mount] => Some(*mount),
        [] => {
            verification
                .reasons
                .push(format!("mount point {} is not mounted", target.display()));
            None
        }
        _ => {
            verification.reasons.push(format!(
                "mount point {} has {} stacked mounts",
                target.display(),
                matches.len()
            ));
            None
        }
    }
}

fn target_path(root: &Path, mount_point: &str) -> PathBuf {
    if mount_point == "/" {
        root.to_path_buf()
    } else {
        root.join(mount_point.trim_start_matches('/'))
    }
}

fn normalize_subvolume(value: &str) -> &str {
    value.trim_start_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "catos-chroot-verify-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join("usr/lib")).unwrap();
            fs::create_dir_all(path.join("usr/bin")).unwrap();
            fs::write(path.join("usr/lib/os-release"), "ID=catos\nNAME=CatOS\n").unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn usr_bin_sh_does_not_satisfy_arch_chroot_default_entrypoint() {
        let root = TempRoot::new();
        fs::write(root.0.join("usr/bin/sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(root.0.join("usr/bin/sh"), fs::Permissions::from_mode(0o755)).unwrap();

        let verification = verify_target_root(&root.0);
        assert!(!verification.ready);
        assert!(verification
            .reasons
            .iter()
            .any(|reason| reason.contains("/bin/bash")));
    }

    #[test]
    fn merged_usr_bash_must_be_nonempty_and_executable() {
        let root = TempRoot::new();
        symlink("usr/bin", root.0.join("bin")).unwrap();
        fs::write(root.0.join("usr/bin/bash"), b"").unwrap();
        fs::set_permissions(
            root.0.join("usr/bin/bash"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(!verify_target_root(&root.0).ready);

        fs::write(root.0.join("usr/bin/bash"), b"ELF").unwrap();
        fs::set_permissions(
            root.0.join("usr/bin/bash"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(verify_target_root(&root.0).ready);
    }
}
