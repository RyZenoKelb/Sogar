//! `sogar mcp-wrap`: a transparent stdio proxy in front of an MCP server.
//!
//! Bytes are forwarded line by line in both directions, unmodified. In flight,
//! JSON-RPC `tools/call` requests and their responses are recognised and
//! reported to the `sogar watch` daemon (with secrets redacted), tagging the
//! MCP server's PID with the tool call that is currently executing.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::ipc::{rpc_key, IpcClient, IpcMessage};

const REDACTED: &str = "[REDACTED]";
const MAX_SUMMARY_CHARS: usize = 512;
const MAX_PENDING_CALLS: usize = 4096;
const PIPE_BUFFER: usize = 64 * 1024;
/// After the server exits, how long to wait for its remaining stdout
/// (grandchildren may hold the pipe open indefinitely).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const IPC_FLUSH_TIMEOUT: Duration = Duration::from_millis(500);

static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Whole PEM block when present (JSON-escaped or raw newlines), else just the header.
        r"-----BEGIN[A-Z ]+PRIVATE KEY-----(?s:.*?)(?:-----END[A-Z ]+PRIVATE KEY-----|$)",
        r"\bAKIA[0-9A-Z]{16}",
        r"\bghp_[A-Za-z0-9_]+",
        r"\bgithub_pat_[A-Za-z0-9_]+",
        r"\bsk-[A-Za-z0-9_-]+",
        r"\bxox[abprs]-[A-Za-z0-9-]+",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("built-in secret pattern is valid"))
    .collect()
});

/// Replaces AWS access keys, GitHub tokens, `sk-` API keys, Slack tokens and
/// PEM private keys with `[REDACTED]`.
pub fn redact_secrets(text: &str) -> String {
    SECRET_PATTERNS
        .iter()
        .fold(text.to_owned(), |acc, re| re.replace_all(&acc, REDACTED).into_owned())
}

pub fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_owned(),
    }
}

/// Compact, redacted, length-bounded rendering of `params.arguments`.
pub fn summarize_arguments(arguments: &Value) -> String {
    truncate_chars(&redact_secrets(&arguments.to_string()), MAX_SUMMARY_CHARS)
}

// ---------------------------------------------------------------------------
// JSON-RPC inspection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ClientSignal {
    ToolCall {
        id: Value,
        tool_name: String,
        arguments_summary: Option<String>,
    },
    Cancelled {
        id: Value,
    },
}

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<IgnoredAny>,
    #[serde(default)]
    result: Option<IgnoredAny>,
    #[serde(default)]
    error: Option<IgnoredAny>,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Parses a single message or a JSON-RPC batch; anything else yields nothing.
fn parse_messages<T: DeserializeOwned>(line: &[u8]) -> Vec<T> {
    let line = line.trim_ascii();
    if line.first() == Some(&b'[') {
        serde_json::from_slice(line).unwrap_or_default()
    } else {
        serde_json::from_slice(line).map(|m| vec![m]).unwrap_or_default()
    }
}

/// `tools/call` requests and `notifications/cancelled` in a client→server line.
pub fn extract_client_signals(line: &[u8]) -> Vec<ClientSignal> {
    parse_messages::<RpcRequest>(line)
        .into_iter()
        .filter_map(|req| match req.method.as_deref() {
            Some("tools/call") => {
                let id = req.id.filter(|id| !id.is_null())?;
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>")
                    .to_owned();
                let arguments_summary = params.get("arguments").map(summarize_arguments);
                Some(ClientSignal::ToolCall { id, tool_name, arguments_summary })
            }
            Some("notifications/cancelled") => {
                let id = req.params?.get("requestId")?.clone();
                Some(ClientSignal::Cancelled { id })
            }
            _ => None,
        })
        .collect()
}

/// `(id, is_error)` of every JSON-RPC response in a server→client line.
pub fn extract_responses(line: &[u8]) -> Vec<(Value, bool)> {
    let tool_error = contains(line, br#""isError":true"#) || contains(line, br#""isError": true"#);
    parse_messages::<RpcResponse>(line)
        .into_iter()
        .filter(|r| r.method.is_none() && (r.result.is_some() || r.error.is_some()))
        .filter_map(|r| {
            let is_error = r.error.is_some() || tool_error;
            r.id.map(|id| (id, is_error))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// Shared state of one wrapped MCP server.
pub struct ProxyContext {
    wrapper_pid: u32,
    child_pid: u32,
    server_name: String,
    pending: Mutex<HashMap<String, Value>>,
    events: mpsc::Sender<IpcMessage>,
}

impl ProxyContext {
    pub fn new(wrapper_pid: u32, child_pid: u32, server_name: &str, events: mpsc::Sender<IpcMessage>) -> Self {
        Self {
            wrapper_pid,
            child_pid,
            server_name: server_name.to_owned(),
            pending: Mutex::new(HashMap::new()),
            events,
        }
    }

    /// Never blocks the data path: if the IPC queue is full the event is dropped.
    pub fn notify(&self, msg: IpcMessage) {
        let _ = self.events.try_send(msg);
    }

    fn pending(&self) -> MutexGuard<'_, HashMap<String, Value>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has_pending(&self) -> bool {
        !self.pending().is_empty()
    }

    fn on_client_signal(&self, signal: ClientSignal) {
        match signal {
            ClientSignal::ToolCall { id, tool_name, arguments_summary } => {
                {
                    let mut pending = self.pending();
                    if pending.len() < MAX_PENDING_CALLS {
                        pending.insert(rpc_key(&id), id.clone());
                    }
                }
                self.notify(IpcMessage::McpCallStart {
                    wrapper_pid: self.wrapper_pid,
                    child_pid: self.child_pid,
                    server_name: self.server_name.clone(),
                    rpc_id: id,
                    tool_name,
                    arguments_summary,
                    timestamp: Utc::now(),
                });
            }
            ClientSignal::Cancelled { id } => {
                if let Some(id) = self.pending().remove(&rpc_key(&id)) {
                    self.notify(self.call_end(id, false, true));
                }
            }
        }
    }

    fn on_response(&self, id: &Value, is_error: bool) {
        if let Some(id) = self.pending().remove(&rpc_key(id)) {
            self.notify(self.call_end(id, is_error, false));
        }
    }

    fn call_end(&self, rpc_id: Value, is_error: bool, cancelled: bool) -> IpcMessage {
        IpcMessage::McpCallEnd {
            child_pid: self.child_pid,
            rpc_id,
            timestamp: Utc::now(),
            is_error,
            cancelled,
        }
    }
}

/// Client (agent) → MCP server. Tool calls are reported *before* the request
/// is forwarded, so the daemon's call window opens before the server acts.
pub async fn pump_client_to_server<R, W>(reader: R, mut writer: W, ctx: Arc<ProxyContext>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::with_capacity(PIPE_BUFFER, reader);
    let mut line = Vec::with_capacity(8 * 1024);
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        if contains(&line, b"tools/call") || contains(&line, b"notifications/cancelled") {
            for signal in extract_client_signals(&line) {
                ctx.on_client_signal(signal);
            }
        }
        writer.write_all(&line).await?;
        writer.flush().await?;
    }
}

/// MCP server → client (agent). Responses are forwarded first, then matched.
pub async fn pump_server_to_client<R, W>(reader: R, mut writer: W, ctx: Arc<ProxyContext>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::with_capacity(PIPE_BUFFER, reader);
    let mut line = Vec::with_capacity(8 * 1024);
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            return writer.flush().await;
        }
        writer.write_all(&line).await?;
        writer.flush().await?;
        if ctx.has_pending() {
            for (id, is_error) in extract_responses(&line) {
                ctx.on_response(&id, is_error);
            }
        }
    }
}

pub struct WrapOptions {
    pub server_name: String,
    pub command: Vec<String>,
    pub socket: PathBuf,
}

/// Runs the wrapped server to completion and returns the exit code to use.
pub async fn run(opts: WrapOptions) -> Result<i32> {
    let (program, args) = opts
        .command
        .split_first()
        .context("mcp-wrap needs the MCP server command after `--`")?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn MCP server {program:?}"))?;
    let child_pid = child.id().context("MCP server exited before it could be tracked")?;
    let wrapper_pid = std::process::id();

    let (client, events) = IpcClient::spawn(opts.socket);
    let ctx = Arc::new(ProxyContext::new(wrapper_pid, child_pid, &opts.server_name, events));
    ctx.notify(IpcMessage::McpServerStart {
        wrapper_pid,
        child_pid,
        server_name: opts.server_name.clone(),
        timestamp: Utc::now(),
    });

    let child_stdin = child.stdin.take().context("MCP server stdin was not captured")?;
    let child_stdout = child.stdout.take().context("MCP server stdout was not captured")?;
    let upstream = tokio::spawn(pump_client_to_server(tokio::io::stdin(), child_stdin, ctx.clone()));
    let downstream = tokio::spawn(pump_server_to_client(child_stdout, tokio::io::stdout(), ctx.clone()));

    let mut sigterm = signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    let status = loop {
        tokio::select! {
            status = child.wait() => break status.context("failed to wait for MCP server")?,
            _ = sigterm.recv() => forward_signal(child_pid, libc::SIGTERM),
            _ = sigint.recv() => forward_signal(child_pid, libc::SIGINT),
            _ = sighup.recv() => forward_signal(child_pid, libc::SIGHUP),
        }
    };

    match tokio::time::timeout(DRAIN_TIMEOUT, downstream).await {
        Ok(Ok(Err(e))) if e.kind() != io::ErrorKind::BrokenPipe => {
            eprintln!("sogar mcp-wrap: error forwarding server output: {e}");
        }
        _ => {}
    }
    upstream.abort();

    let exit_code = exit_code(&status);
    ctx.notify(IpcMessage::McpServerExit {
        wrapper_pid,
        child_pid,
        timestamp: Utc::now(),
        exit_code: Some(exit_code),
    });
    drop(ctx);
    client.shutdown(IPC_FLUSH_TIMEOUT).await;
    Ok(exit_code)
}

fn forward_signal(pid: u32, sig: libc::c_int) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: plain kill(2) on our own child.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{duplex, AsyncReadExt};

    #[test]
    fn redacts_each_secret_family() {
        let cases = [
            ("key AKIAIOSFODNN7EXAMPLE end", "key [REDACTED] end"),
            ("token ghp_abcDEF123_xyz", "token [REDACTED]"),
            ("Bearer sk-ant-api03-AbC_d-e", "Bearer [REDACTED]"),
            ("OPENAI=sk-proj-123", "OPENAI=[REDACTED]"),
            ("pat github_pat_11ABC_def", "pat [REDACTED]"),
            ("slack xoxb-123-456-abc", "slack [REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_secrets(input), expected, "{input}");
        }
        // Words that merely contain the prefixes survive.
        assert_eq!(redact_secrets("task-list ask-me"), "task-list ask-me");
    }

    #[test]
    fn redacts_private_keys_in_raw_and_json_escaped_form() {
        let raw = "x -----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY----- y";
        assert_eq!(redact_secrets(raw), "x [REDACTED] y");
        let escaped = json!({"content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\n-----END OPENSSH PRIVATE KEY-----"}).to_string();
        let red = redact_secrets(&escaped);
        assert_eq!(red, r#"{"content":"[REDACTED]"}"#);
        assert_eq!(redact_secrets("-----BEGIN EC PRIVATE KEY----- MHcC"), "[REDACTED]");
    }

    #[test]
    fn extracts_tool_calls_with_redacted_arguments() {
        let line = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "/tmp/x", "content": "AKIAIOSFODNN7EXAMPLE"}}})
            .to_string();
        let signals = extract_client_signals(line.as_bytes());
        assert_eq!(
            signals,
            vec![ClientSignal::ToolCall {
                id: json!(7),
                tool_name: "write_file".into(),
                // The client's key order is preserved.
                arguments_summary: Some(r#"{"path":"/tmp/x","content":"[REDACTED]"}"#.into()),
            }]
        );
        assert!(!signals.iter().any(|s| format!("{s:?}").contains("AKIA")));
    }

    #[test]
    fn extracts_batches_and_cancellations_and_ignores_other_traffic() {
        let batch = json!([
            {"jsonrpc": "2.0", "id": "a", "method": "tools/call", "params": {"name": "search"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "z"}}
        ])
        .to_string();
        let signals = extract_client_signals(batch.as_bytes());
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[1], ClientSignal::Cancelled { id: json!("z") });

        // tools/call notifications (no id) and garbage are ignored.
        assert!(extract_client_signals(br#"{"method":"tools/call","params":{}}"#).is_empty());
        assert!(extract_client_signals(b"tools/call but not json").is_empty());
    }

    #[test]
    fn long_arguments_are_truncated() {
        let summary = summarize_arguments(&json!({"blob": "é".repeat(2000)}));
        assert_eq!(summary.chars().count(), MAX_SUMMARY_CHARS + 1);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn extracts_responses_and_error_flags() {
        assert_eq!(extract_responses(br#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#), vec![(json!(7), false)]);
        assert_eq!(extract_responses(br#"{"jsonrpc":"2.0","id":7,"result":{"isError":true}}"#), vec![(json!(7), true)]);
        assert_eq!(extract_responses(br#"{"jsonrpc":"2.0","id":"x","error":{"code":-32601}}"#), vec![(json!("x"), true)]);
        // Server→client requests and notifications are not responses.
        assert!(extract_responses(br#"{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}"#).is_empty());
        assert!(extract_responses(br#"{"jsonrpc":"2.0","method":"notifications/progress"}"#).is_empty());
    }

    async fn read_line<R: AsyncRead + Unpin>(r: &mut R) -> Vec<u8> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while r.read(&mut byte).await.expect("read") == 1 {
            out.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        out
    }

    #[tokio::test]
    async fn proxies_bytes_unchanged_and_reports_call_lifecycle() {
        let (tx, mut rx) = mpsc::channel(16);
        let ctx = Arc::new(ProxyContext::new(10, 11, "fs", tx));

        let (mut client_w, client_r) = duplex(1 << 16);
        let (server_in_w, mut server_in_r) = duplex(1 << 16);
        let (mut server_out_w, server_out_r) = duplex(1 << 16);
        let (client_out_w, mut client_out_r) = duplex(1 << 16);
        let up = tokio::spawn(pump_client_to_server(client_r, server_in_w, ctx.clone()));
        let down = tokio::spawn(pump_server_to_client(server_out_r, client_out_w, ctx.clone()));

        // Odd spacing and key order must survive byte for byte.
        let request = b"{ \"method\":\"tools/call\" ,\"jsonrpc\":\"2.0\",\"id\":7,\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/Users/dev/.ssh/id_rsa\"}}}\n";
        client_w.write_all(request).await.expect("write");
        assert_eq!(read_line(&mut server_in_r).await, request.to_vec());

        match rx.recv().await.expect("start") {
            IpcMessage::McpCallStart { wrapper_pid, child_pid, server_name, rpc_id, tool_name, arguments_summary, .. } => {
                assert_eq!((wrapper_pid, child_pid, server_name.as_str()), (10, 11, "fs"));
                assert_eq!((rpc_id, tool_name.as_str()), (json!(7), "read_file"));
                assert_eq!(arguments_summary.as_deref(), Some(r#"{"path":"/Users/dev/.ssh/id_rsa"}"#));
            }
            other => panic!("unexpected {other:?}"),
        }

        let notification = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n";
        server_out_w.write_all(notification).await.expect("write");
        server_out_w.write_all(response).await.expect("write");
        assert_eq!(read_line(&mut client_out_r).await, notification.to_vec());
        assert_eq!(read_line(&mut client_out_r).await, response.to_vec());

        match rx.recv().await.expect("end") {
            IpcMessage::McpCallEnd { child_pid, rpc_id, is_error, cancelled, .. } => {
                assert_eq!((child_pid, rpc_id, is_error, cancelled), (11, json!(7), false, false));
            }
            other => panic!("unexpected {other:?}"),
        }

        // A duplicate response for an id that is no longer pending is not reported twice.
        server_out_w.write_all(response).await.expect("write");
        read_line(&mut client_out_r).await;

        // EOF on the client side closes the server's stdin.
        drop(client_w);
        up.await.expect("join").expect("upstream ok");
        let mut rest = Vec::new();
        server_in_r.read_to_end(&mut rest).await.expect("eof");
        assert!(rest.is_empty());

        drop(server_out_w);
        down.await.expect("join").expect("downstream ok");
        drop(ctx);
        assert!(rx.recv().await.is_none(), "no further IPC messages");
    }

    #[tokio::test]
    async fn last_line_without_newline_is_forwarded() {
        let (tx, _rx) = mpsc::channel(4);
        let ctx = Arc::new(ProxyContext::new(1, 2, "s", tx));
        let mut out = Vec::new();
        pump_client_to_server(&b"{\"a\":1}\n{\"b\":2}"[..], &mut out, ctx).await.expect("ok");
        assert_eq!(out, b"{\"a\":1}\n{\"b\":2}");
    }
}
