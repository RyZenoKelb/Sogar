//! Unix Domain Socket protocol between `sogar mcp-wrap` (unprivileged, one per
//! MCP server) and the root `sogar watch` daemon.
//!
//! Wire format: one JSON object per line, internally tagged by `"type"`.
//! Wrappers only ever write; the daemon only ever reads. The daemon learns the
//! sender's PID from the kernel (`LOCAL_PEERPID`) so a process cannot claim to
//! be a wrapper it is not.

use std::fs::{self, Permissions};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Default rendezvous point between wrappers and the daemon.
pub const SOCKET_PATH: &str = "/tmp/sogar.sock";

/// Upper bound for a single protocol line; anything larger closes the connection.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// How long a wrapper waits before retrying an unreachable daemon.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// Messages queued in a wrapper before new ones are dropped (the proxy never blocks on IPC).
const CLIENT_QUEUE_DEPTH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)] // wire names (`McpCallStart`, ...) are part of the protocol
pub enum IpcMessage {
    /// A wrapper spawned its MCP server; descendants of `child_pid` belong to it.
    McpServerStart {
        wrapper_pid: u32,
        child_pid: u32,
        server_name: String,
        timestamp: DateTime<Utc>,
    },
    /// A JSON-RPC `tools/call` request was forwarded to the MCP server.
    McpCallStart {
        wrapper_pid: u32,
        child_pid: u32,
        server_name: String,
        rpc_id: Value,
        tool_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arguments_summary: Option<String>,
        timestamp: DateTime<Utc>,
    },
    /// The response for `rpc_id` came back (or the client cancelled the request).
    McpCallEnd {
        child_pid: u32,
        rpc_id: Value,
        timestamp: DateTime<Utc>,
        #[serde(default)]
        is_error: bool,
        #[serde(default)]
        cancelled: bool,
    },
    /// The MCP server process exited.
    McpServerExit {
        wrapper_pid: u32,
        child_pid: u32,
        timestamp: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
}

impl IpcMessage {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            IpcMessage::McpServerStart { timestamp, .. }
            | IpcMessage::McpCallStart { timestamp, .. }
            | IpcMessage::McpCallEnd { timestamp, .. }
            | IpcMessage::McpServerExit { timestamp, .. } => *timestamp,
        }
    }
}

/// Canonical map key for a JSON-RPC id (`1` and `"1"` are different ids).
pub fn rpc_key(id: &Value) -> String {
    id.to_string()
}

/// A message received by the daemon, with the kernel-verified sender PID.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub msg: IpcMessage,
    pub peer_pid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Daemon side
// ---------------------------------------------------------------------------

/// Binds the daemon socket and opens it to every local user (`0666`) so that
/// unprivileged `sogar mcp-wrap` processes can report to a root daemon.
pub fn bind_server(path: &Path) -> Result<UnixListener> {
    clear_stale_socket(path)?;
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind Unix socket {}", path.display()))?;

    // /tmp is sticky, so once bound the path can only be replaced by us. Still,
    // refuse to chmod anything that is not the socket we just created.
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if !meta.file_type().is_socket() {
        bail!("{} is not a socket after bind; refusing to continue", path.display());
    }
    fs::set_permissions(path, Permissions::from_mode(0o666))
        .with_context(|| format!("failed to set 0666 permissions on {}", path.display()))?;
    Ok(listener)
}

fn clear_stale_socket(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("failed to stat {}", path.display())),
    };
    if meta.file_type().is_socket() && std::os::unix::net::UnixStream::connect(path).is_ok() {
        bail!(
            "another `sogar watch` is already listening on {}; stop it first",
            path.display()
        );
    }
    fs::remove_file(path)
        .with_context(|| format!("failed to remove stale socket {}", path.display()))
}

/// Removes the socket file on drop, so wrappers stop trying to reach a dead daemon.
pub struct SocketGuard(PathBuf);

impl SocketGuard {
    pub fn new(path: &Path) -> Self {
        Self(path.to_path_buf())
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = fs::remove_file(&self.0);
        }
    }
}

/// Accepts wrapper connections until the receiving side of `tx` goes away.
pub async fn serve(listener: UnixListener, tx: mpsc::Sender<Envelope>) {
    loop {
        tokio::select! {
            _ = tx.closed() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, tx).await {
                            eprintln!("sogar: IPC connection error: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("sogar: failed to accept IPC connection: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
}

async fn handle_connection(stream: UnixStream, tx: mpsc::Sender<Envelope>) -> Result<()> {
    let peer_pid = peer_pid(&stream);
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::with_capacity(1024);
    loop {
        buf.clear();
        let limit = MAX_MESSAGE_BYTES as u64 + 1;
        let n = (&mut reader).take(limit).read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        if buf.len() > MAX_MESSAGE_BYTES {
            bail!("message from pid {peer_pid:?} exceeds {MAX_MESSAGE_BYTES} bytes");
        }
        let line = buf.trim_ascii();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<IpcMessage>(line) {
            Ok(msg) => {
                if tx.send(Envelope { msg, peer_pid }).await.is_err() {
                    return Ok(());
                }
            }
            Err(e) => eprintln!("sogar: ignoring malformed IPC message from pid {peer_pid:?}: {e}"),
        }
    }
}

/// Kernel-reported PID of the connected peer. tokio's `peer_cred()` does not
/// expose it on macOS, so ask for `LOCAL_PEERPID` directly.
#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for writes of the sizes passed.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    // Fails with ENOTCONN once the peer hung up; such senders are unverifiable.
    if ret == 0 {
        u32::try_from(pid).ok().filter(|p| *p > 0)
    } else {
        None
    }
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    stream
        .peer_cred()
        .ok()
        .and_then(|cred| cred.pid())
        .and_then(|pid| u32::try_from(pid).ok())
}

// ---------------------------------------------------------------------------
// Wrapper side
// ---------------------------------------------------------------------------

/// Background sender owned by `sogar mcp-wrap`. Delivery is best effort: if
/// the daemon is not running, messages are dropped and the MCP traffic is
/// proxied exactly as before.
pub struct IpcClient {
    handle: JoinHandle<()>,
}

impl IpcClient {
    pub fn spawn(path: PathBuf) -> (Self, mpsc::Sender<IpcMessage>) {
        let (tx, rx) = mpsc::channel(CLIENT_QUEUE_DEPTH);
        let handle = tokio::spawn(client_loop(path, rx));
        (Self { handle }, tx)
    }

    /// Waits (bounded) for queued messages to be flushed. All senders must be
    /// dropped first, otherwise this simply times out.
    pub async fn shutdown(self, grace: Duration) {
        let _ = tokio::time::timeout(grace, self.handle).await;
    }
}

async fn client_loop(path: PathBuf, mut rx: mpsc::Receiver<IpcMessage>) {
    let mut conn: Option<UnixStream> = None;
    let mut retry_at: Option<Instant> = None;
    let mut warned = false;

    while let Some(msg) = rx.recv().await {
        let mut line = match serde_json::to_vec(&msg) {
            Ok(line) => line,
            Err(e) => {
                eprintln!("sogar mcp-wrap: failed to encode IPC message: {e}");
                continue;
            }
        };
        line.push(b'\n');

        // One retry covers a daemon restart between two messages.
        for _ in 0..2 {
            if conn.is_none() {
                if retry_at.is_some_and(|at| Instant::now() < at) {
                    break;
                }
                match UnixStream::connect(&path).await {
                    Ok(stream) => {
                        conn = Some(stream);
                        retry_at = None;
                    }
                    Err(e) => {
                        if !warned {
                            eprintln!(
                                "sogar mcp-wrap: flight recorder not reachable at {} ({e}); \
                                 MCP traffic is still proxied unchanged",
                                path.display()
                            );
                            warned = true;
                        }
                        retry_at = Some(Instant::now() + RECONNECT_BACKOFF);
                        break;
                    }
                }
            }
            if let Some(stream) = conn.as_mut() {
                match stream.write_all(&line).await {
                    Ok(()) => break,
                    Err(_) => conn = None,
                }
            }
        }
    }

    if let Some(mut stream) = conn {
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
pub(crate) fn test_socket_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // sun_path is limited to 104 bytes on macOS; TMPDIR can be longer than that.
    let dir = std::env::temp_dir();
    let dir = if dir.as_os_str().len() > 60 { PathBuf::from("/tmp") } else { dir };
    dir.join(format!("sogar-{tag}-{}-{n}.sock", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn messages_round_trip_with_type_tag() {
        let msg = IpcMessage::McpCallStart {
            wrapper_pid: 10,
            child_pid: 11,
            server_name: "fs".into(),
            rpc_id: json!(7),
            tool_name: "read_file".into(),
            arguments_summary: Some(r#"{"path":"/tmp/x"}"#.into()),
            timestamp: Utc::now(),
        };
        let text = serde_json::to_string(&msg).expect("serialize");
        assert!(text.contains(r#""type":"McpCallStart""#));
        let back: IpcMessage = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back, msg);
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let text = r#"{"type":"McpCallEnd","child_pid":11,"rpc_id":"a","timestamp":"2026-10-15T01:15:22.5Z"}"#;
        let msg: IpcMessage = serde_json::from_str(text).expect("deserialize");
        match msg {
            IpcMessage::McpCallEnd { is_error, cancelled, rpc_id, .. } => {
                assert!(!is_error && !cancelled);
                assert_eq!(rpc_key(&rpc_id), r#""a""#);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rpc_keys_distinguish_numbers_from_strings() {
        assert_ne!(rpc_key(&json!(1)), rpc_key(&json!("1")));
    }

    #[tokio::test]
    async fn socket_is_world_writable_and_delivers_messages_with_peer_pid() {
        let path = test_socket_path("ipc");
        let listener = bind_server(&path).expect("bind");
        let _guard = SocketGuard::new(&path);
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);

        // A second daemon must refuse to steal a live socket.
        assert!(bind_server(&path).is_err());

        let (tx, mut rx) = mpsc::channel(8);
        let server = tokio::spawn(serve(listener, tx));

        let (client, sender) = IpcClient::spawn(path.clone());
        let msg = IpcMessage::McpServerStart {
            wrapper_pid: std::process::id(),
            child_pid: 4242,
            server_name: "demo".into(),
            timestamp: Utc::now(),
        };
        sender.send(msg.clone()).await.expect("queue");

        // The wrapper keeps its connection open, so the daemon can read the
        // sender's PID from the kernel.
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timely delivery")
            .expect("message");
        assert_eq!(got.msg, msg);
        assert_eq!(got.peer_pid, Some(std::process::id()));
        drop(sender);
        client.shutdown(Duration::from_secs(2)).await;

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[test]
    fn stale_socket_files_are_replaced() {
        let path = test_socket_path("stale");
        {
            let _dead = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        } // listener dropped: file remains but nobody accepts
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let _listener = bind_server(&path).expect("rebind over stale socket");
        });
        let _ = fs::remove_file(&path);
    }
}
