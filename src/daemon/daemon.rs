use super::worker::run_worker;
use anyhow::{Context, Result};
/// Functions for daemonizing auditrs and managing the PID file.
/// In the future, some work should be done to see if we can get this
/// working with systemctl or similar system services
use std::fs::{self, File};
use std::path::PathBuf;
use std::process::exit;

use crate::daemon::PID_FILE_NAME;

use daemonize::{Daemonize, Outcome};
/// Creates a daemon process that runs in the background.
/// Both the parent (main) and child (daemon) will return up the call stack with a result.
/// The parent process will wait a moment and check if the daemon's PID file exists.
pub fn start_daemon() -> Result<(), anyhow::Error> {
    let pid = pid_file_path();
    if let Some(parent) = pid.parent() {
        fs::create_dir_all(parent)?;
    }
    let stdout = File::create("/tmp/daemon.out")?;
    let stderr = File::create("/tmp/daemon.err")?;

    let daemonize = Daemonize::new()
        .pid_file(&pid)
        .stdout(stdout)
        .stderr(stderr);

    // Use execute() instead of start() so we can report the result before the parent process is killed.
    match daemonize.execute() {
        Outcome::Parent(Ok(_)) => {
            // We're in the parent process - daemon was forked successfully.
            // However, we'll see if it encountered any errors after launching.
            std::thread::sleep(std::time::Duration::from_millis(100));

            if pid.exists() {
                Ok(())
            } else {
                Err(anyhow::anyhow!(format!(
                    "Daemon failed to initialize. See /tmp/daemon.err for details."
                )))
            }
        }
        Outcome::Parent(Err(e)) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),

        Outcome::Child(res) => {
            // We're in the child process - we are daemon!
            // First, acquire the guard on the daemon's PID file so it gets deleted.
            let _guard = FileGuard::new(pid);

            // Now see if we were actually created successfully.
            match res {
                Ok(_) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(run_worker())
                }
                Err(e) => Err(anyhow::anyhow!("Failed to daemonize: {}", e)),
            }
        }
    }
}

/// Send SIGTERM to the daemon (used by `auditrs stop`).
pub fn stop_daemon() -> Result<()> {
    let path = pid_file_path();
    let contents = fs::read_to_string(&path).context("No PID file found. Is AuditRS running?")?;
    let pid: i32 = contents
        .trim()
        .parse()
        .with_context(|| format!("invalid PID in {}", path.display()))?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// True if the PID file exists and that process is still running.
pub fn is_running() -> bool {
    let path = pid_file_path();
    let Ok(contents) = fs::read_to_string(&path) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return false;
    };
    unsafe { libc::kill(pid, 0) == 0 }
}

fn pid_file_path() -> PathBuf {
    unsafe {
        if libc::geteuid() == 0 {
            return PathBuf::from("/var/run").join(PID_FILE_NAME);
        }
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join(PID_FILE_NAME);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("auditrs")
            .join(PID_FILE_NAME);
    }
    PathBuf::from(".").join(PID_FILE_NAME)
}

// This is a file guard that will wrap the daemon's pid file.
// Once it falls out of scope (i.e., daemon exits), the Drop trait will make sure the pid file gets deleted.
struct FileGuard {
    file: std::fs::File,
    path: PathBuf,
}

impl FileGuard {
    fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = std::fs::File::create(&path)?;
        Ok(Self { file, path })
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        println!("Cleaning up PID file: {:?}", self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_pid_path_xdg() {
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/tmp/xdg"); }
        let path = pid_file_path();
        assert!(path.starts_with("/tmp/xdg"));
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR"); }
    }

    #[test]
    fn test_pid_path_home() {
        unsafe {
            std::env::remove_var("XDG_RUNTIME_DIR");
            std::env::set_var("HOME", "/tmp/home");
        }
        let path = pid_file_path();
        assert!(path.starts_with("/tmp/home/.cache/auditrs"));
        unsafe { std::env::remove_var("HOME"); }
    }

    #[test]
    fn test_no_pid_file() {
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/tmp/xdg"); }
        // NOTE: Not calling pid_file_path()
        assert!(!is_running());
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR"); }
    }

    #[test]
    fn test_corrupted_pid_file() {
        let dir = TempDir::new().unwrap();
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/tmp/xdg"); }
        let pid_path = dir.path().join(crate::daemon::PID_FILE_NAME);
        fs::write(&pid_path, "blahblahblah").unwrap();
        assert!(!is_running());
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR"); }
    }

    fn test_file_guard_deletes_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pid");
        // NOTE: Using brackets to create a scope block. After leaving scope block, should delete file
        {
            let _guard = FileGuard::new(path.clone()).unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    #[test]
    fn test_stop_daemon_no_pid_file() {
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/tmp/definitely_does_not_exist_xyz"); }
        let result = stop_daemon();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No PID file found"));
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR"); }
    }
}
