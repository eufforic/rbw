#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

#[cfg(unix)]
pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

#[cfg(unix)]
impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

#[cfg(unix)]
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        let mut pidfile = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(rbw::dirs::pid_file())
            .context("failed to open pid file")?;
        rustix::fs::flock(
            &pidfile,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .context("failed to lock pid file")?;
        writeln!(pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    let daemonize = daemonize::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonize::Outcome::Parent(_) => {
            drop(w);
            let mut buf = [0; 1];
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            rustix::io::read(&r, &mut buf).unwrap();
            drop(r);
            std::process::exit(0);
        }
        daemonize::Outcome::Child(res) => res,
    };

    drop(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            // XXX super gross, but daemonize removed the ability to match
            // on specific error types for some reason?
            if e.to_string().contains("unable to lock pid file") {
                // this means that there is already an agent running, so
                // return a special exit code to allow the cli to detect
                // this case and not error out
                std::process::exit(23);
            }
            panic!("failed to daemonize: {e}");
        }
    }

    Ok(Some(StartupAck { writer: w }))
}

#[cfg(windows)]
pub struct StartupAck;

#[cfg(windows)]
impl StartupAck {
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub fn ack(self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The argument the detached copy of the agent is started with.
#[cfg(windows)]
const DETACHED: &str = "--detached";

/// Windows has no fork, so the agent starts a detached copy of itself and
/// returns once that copy is listening (or has exited, for example because
/// another agent already was).
#[cfg(windows)]
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        return Ok(None);
    }
    if std::env::args().nth(1).as_deref() == Some(DETACHED) {
        log_to_files()?;
        return Ok(None);
    }
    if rbw::windows::pipe_exists(0) {
        std::process::exit(crate::sock::ALREADY_RUNNING);
    }

    let child = spawn_detached()?;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(code) = child.exit_code() {
            std::process::exit(code);
        }
        if rbw::windows::pipe_exists(0) {
            std::process::exit(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::bail!("the background agent did not start listening")
}

/// Points the detached agent's stdout and stderr at its log files, since it
/// starts with none.
#[cfg(windows)]
fn log_to_files() -> anyhow::Result<()> {
    use std::os::windows::io::IntoRawHandle as _;
    use windows_sys::Win32::System::Console::{
        SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    for (std_handle, path) in [
        (STD_OUTPUT_HANDLE, rbw::dirs::agent_stdout_file()),
        (STD_ERROR_HANDLE, rbw::dirs::agent_stderr_file()),
    ] {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        // safety: the handle is valid and deliberately never closed, since
        // it stays the process's standard handle until exit
        unsafe { SetStdHandle(std_handle, file.into_raw_handle()) };
    }
    Ok(())
}

#[cfg(windows)]
struct Process(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Process {
    fn exit_code(&self) -> Option<i32> {
        use windows_sys::Win32::Foundation::STILL_ACTIVE;
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;

        let mut code = 0;
        // safety: the handle is a process we started and still own
        let ok = unsafe { GetExitCodeProcess(self.0, &raw mut code) };
        if ok == 0 || code == u32::try_from(STILL_ACTIVE).unwrap() {
            return None;
        }
        Some(i32::from_ne_bytes(code.to_ne_bytes()))
    }
}

#[cfg(windows)]
impl Drop for Process {
    fn drop(&mut self) {
        // safety: closed exactly once
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// Starts the agent again with `DETACHED`, inheriting no handles at all.
///
/// std's Command always lets the child inherit every inheritable handle, and
/// whoever ran us usually has handed us their stdout and stderr pipes (often
/// several times over, as duplicates). A caller reading those pipes to the
/// end, as scripts and agent hosts capturing output do, would then wait for
/// as long as the agent lives.
#[cfg(windows)]
fn spawn_detached() -> anyhow::Result<Process> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP,
        DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let exe = std::env::current_exe()?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
    let spawn = |flags| -> std::io::Result<Process> {
        // CreateProcessW may write to the command line buffer
        let mut cmdline: Vec<u16> = std::ffi::OsString::from(format!(
            "\"{}\" {DETACHED}",
            exe.display()
        ))
        .encode_wide()
        .chain([0])
        .collect();
        // safety: zeroed STARTUPINFOW/PROCESS_INFORMATION are valid inputs
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap();
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // safety: all pointers are valid for the call; bInheritHandles is 0
        let ok = unsafe {
            CreateProcessW(
                exe_w.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &raw const si,
                &raw mut pi,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // safety: returned by CreateProcessW and not used again
        unsafe { CloseHandle(pi.hThread) };
        Ok(Process(pi.hProcess))
    };
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // A caller that runs commands inside a job object (as some terminals and
    // agent hosts do) would kill the agent along with the command. Leave the
    // job when it allows that; otherwise CreateProcess refuses the flag.
    spawn(flags | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(flags))
        .context("failed to start the agent in the background")
}
