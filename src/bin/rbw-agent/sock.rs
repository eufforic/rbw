use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeServer;

pub struct Sock(Stream);

impl Sock {
    pub fn new(s: Stream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<std::result::Result<rbw::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line)
            .map_err(|e| format!("failed to parse message '{line}': {e}")))
    }
}

#[cfg(unix)]
pub type Listener = tokio::net::UnixListener;

#[cfg(unix)]
pub fn incoming(
    listener: Listener,
) -> futures_util::stream::BoxStream<'static, std::io::Result<Stream>> {
    use futures_util::StreamExt as _;
    tokio_stream::wrappers::UnixListenerStream::new(listener).boxed()
}

#[cfg(unix)]
pub fn listen() -> anyhow::Result<Listener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

/// The next pipe instance waiting for a client, and the security every
/// instance is created with.
#[cfg(windows)]
pub struct Listener {
    next: Stream,
    security: std::sync::Arc<rbw::windows::PipeSecurity>,
}

#[cfg(windows)]
fn create_instance(
    security: &rbw::windows::PipeSecurity,
    first: bool,
) -> std::io::Result<Stream> {
    // safety: the security attributes outlive the call
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                rbw::windows::pipe_name(),
                security.as_ptr(),
            )
    }
}

/// Exit code that tells the cli an agent was already running.
#[cfg(windows)]
pub const ALREADY_RUNNING: i32 = 23;

#[cfg(windows)]
pub fn listen() -> anyhow::Result<Listener> {
    let security = std::sync::Arc::new(
        rbw::windows::PipeSecurity::new()
            .context("failed to build the pipe security descriptor")?,
    );
    let next = match create_instance(&security, true) {
        Ok(next) => next,
        // first_pipe_instance makes a second agent fail here
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            std::process::exit(ALREADY_RUNNING)
        }
        Err(e) => return Err(e).context("failed to listen on pipe"),
    };
    log::debug!("listening on pipe {}", rbw::windows::pipe_name());
    Ok(Listener { next, security })
}

#[cfg(windows)]
pub fn incoming(
    listener: Listener,
) -> futures_util::stream::BoxStream<'static, std::io::Result<Stream>> {
    use futures_util::StreamExt as _;
    futures_util::stream::unfold(Some(listener), |listener| async move {
        let Listener { next, security } = listener?;
        if let Err(e) = next.connect().await {
            return Some((Err(e), None));
        }
        // the next instance must exist before this one is handed off, or
        // a client arriving in between finds no pipe at all
        match create_instance(&security, false) {
            Ok(new) => Some((
                Ok(next),
                Some(Listener {
                    next: new,
                    security,
                }),
            )),
            Err(e) => Some((Err(e), None)),
        }
    })
    .boxed()
}
