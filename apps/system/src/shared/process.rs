//! Small, bounded external-command runner for recovery helpers.
//!
//! External tools are optional supplements, never the primary discovery
//! mechanism. Commands are resolved only from a fixed trusted directory
//! list, run with a minimal environment, bounded output, and a deadline.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TRUSTED_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

#[derive(Debug)]
pub struct ToolOutput {
    pub path: PathBuf,
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

impl ToolOutput {
    pub fn success(&self) -> bool {
        self.status.success() && !self.timed_out
    }
}

pub fn trusted_tool_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    select_trusted_tool(name, TRUSTED_DIRS.iter().map(Path::new))
}

fn select_trusted_tool<'a>(
    name: &str,
    directories: impl IntoIterator<Item = &'a Path>,
) -> Option<PathBuf> {
    directories.into_iter().find_map(|directory| {
        let candidate = directory.join(name);
        let metadata = std::fs::metadata(&candidate).ok()?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            Some(candidate)
        } else {
            None
        }
    })
}

pub fn run_trusted_tool(
    name: &str,
    args: &[&str],
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ToolOutput, String> {
    run_trusted_tool_with_optional_timeout(name, args, Some(timeout), max_output_bytes)
}

/// Run a trusted tool with an optional deadline. Callers that perform
/// write-capable filesystem repair pass `None`: terminating an active
/// metadata repair is more dangerous than waiting for it to finish.
pub fn run_trusted_tool_with_optional_timeout(
    name: &str,
    args: &[&str],
    timeout: Option<Duration>,
    max_output_bytes: usize,
) -> Result<ToolOutput, String> {
    let path = trusted_tool_path(name)
        .ok_or_else(|| format!("trusted tool {name:?} not found in fixed system directories"))?;

    let mut command = Command::new(&path);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin");
    run_prepared_command_with_optional_timeout(command, path, timeout, max_output_bytes)
}

/// Execute a command whose argv, environment, and optional `pre_exec` setup
/// have already been constructed by a narrowly-scoped caller. Output handling,
/// timeout behavior, and EOF draining remain identical to trusted tools.
pub(crate) fn run_prepared_command_with_optional_timeout(
    mut command: Command,
    path: PathBuf,
    timeout: Option<Duration>,
    max_output_bytes: usize,
) -> Result<ToolOutput, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn {}: {error}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout pipe unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "child stderr pipe unavailable".to_string())?;

    let stdout_thread = thread::spawn(move || read_capped(stdout, max_output_bytes));
    let stderr_thread = thread::spawn(move || read_capped(stderr, max_output_bytes));

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if timeout.map_or(true, |limit| started.elapsed() < limit) => {
                thread::sleep(Duration::from_millis(10))
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait().map_err(|error| {
                    format!("failed to reap timed-out {}: {error}", path.display())
                })?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed waiting for {}: {error}", path.display()));
            }
        }
    };

    let (stdout, stdout_truncated) = stdout_thread
        .join()
        .map_err(|_| "stdout reader thread panicked".to_string())??;
    let (stderr, stderr_truncated) = stderr_thread
        .join()
        .map_err(|_| "stderr reader thread panicked".to_string())??;

    Ok(ToolOutput {
        path,
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

fn read_capped<R: Read>(reader: R, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut reader = reader;
    let mut output = Vec::with_capacity(limit);
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed reading child output: {error}"))?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(output.len());
        let retained = available.min(read);
        output.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    Ok((output, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "catos-process-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn trusted_selection_requires_executable_regular_file() {
        let dir = temp_dir("select");
        let tool = dir.join("tool");
        fs::write(&tool, b"not executable").unwrap();
        assert!(select_trusted_tool("tool", [&dir as &Path]).is_none());

        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();
        assert_eq!(select_trusted_tool("tool", [&dir as &Path]), Some(tool));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tool_names_with_slashes_are_rejected() {
        assert!(trusted_tool_path("../tmp/fake-blkid").is_none());
        assert!(trusted_tool_path("/tmp/fake-blkid").is_none());
    }

    #[test]
    fn capped_reader_reports_truncation() {
        let (bytes, truncated) = read_capped(&b"abcdef"[..], 3).unwrap();
        assert_eq!(bytes, b"abc");
        assert!(truncated);
    }

    #[test]
    fn capped_reader_keeps_pipe_open_until_writer_finishes() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (reader, mut writer) = UnixStream::pair().unwrap();
        let writer_thread = std::thread::spawn(move || {
            let bytes = vec![b'x'; 1024 * 1024];
            writer.write_all(&bytes).unwrap();
            writer.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let (retained, truncated) = read_capped(reader, 64).unwrap();
        writer_thread
            .join()
            .expect("writer must not receive EPIPE after report cap");
        assert_eq!(retained, vec![b'x'; 64]);
        assert!(truncated);
    }

    #[test]
    fn capped_reader_drains_bytes_after_the_limit() {
        let bytes = vec![b'x'; 128 * 1024];
        let (retained, truncated) = read_capped(&bytes[..], 64).unwrap();
        assert_eq!(retained, vec![b'x'; 64]);
        assert!(truncated);
    }
}
