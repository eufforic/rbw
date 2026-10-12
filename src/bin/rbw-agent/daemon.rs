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
            } else {
                panic!("failed to daemonize: {e}");
            }
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

/// Windows has no fork, so the agent starts a detached copy of itself and
/// returns once that copy is listening (or has exited, for example because
/// another agent already was).
#[cfg(windows)]
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    use std::os::windows::process::CommandExt as _;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    if no_daemonize {
        return Ok(None);
    }
    if rbw::windows::pipe_exists(0) {
        std::process::exit(crate::sock::ALREADY_RUNNING);
    }

    let spawn = |flags| -> std::io::Result<std::process::Child> {
        let stdout = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(rbw::dirs::agent_stdout_file())?;
        let stderr = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(rbw::dirs::agent_stderr_file())?;
        std::process::Command::new(std::env::current_exe()?)
            .arg("--no-daemonize")
            .stdin(std::process::Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .creation_flags(flags)
            .spawn()
    };
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // A caller that runs commands inside a job object (as some terminals and
    // agent hosts do) would kill the agent along with the command. Leave the
    // job when it allows that; otherwise CreateProcess refuses the flag.
    let mut child = spawn(flags | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(flags))
        .context("failed to start the agent in the background")?;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            std::process::exit(status.code().unwrap_or(1));
        }
        if rbw::windows::pipe_exists(0) {
            std::process::exit(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    anyhow::bail!("the background agent did not start listening")
}
