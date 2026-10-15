//! Real-time webhook alerts for critical events.
//!
//! Every critical record is POSTed as JSON to `--webhook-url` from a
//! background task with a hard timeout, so a slow or unreachable endpoint
//! can never stall the recorder. The payload carries `text` (Slack),
//! `content` (Discord) and the full structured record (Torq, Tines, SOAR).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::lineage::basename;
use crate::mcp_proxy::truncate_chars;

pub const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(3);
/// Alerts in flight at once; beyond this, alerts are dropped (and counted)
/// rather than queued without bound during an event storm.
const MAX_IN_FLIGHT: usize = 16;
/// Discord rejects `content` longer than 2000 characters.
const MAX_CONTENT_CHARS: usize = 1900;
const FAILURE_REPORT_LIMIT: u64 = 5;

pub struct Alerter {
    client: reqwest::Client,
    url: reqwest::Url,
    permits: Arc<Semaphore>,
    failures: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl Alerter {
    pub fn new(url: &str) -> Result<Self> {
        Self::with_timeout(url, WEBHOOK_TIMEOUT)
    }

    pub fn with_timeout(url: &str, timeout: Duration) -> Result<Self> {
        let url =
            reqwest::Url::parse(url).with_context(|| format!("invalid --webhook-url {url:?}"))?;
        if !matches!(url.scheme(), "https" | "http") {
            bail!("--webhook-url must be an http(s) URL");
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .user_agent(concat!("sogar/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build the webhook HTTP client")?;
        Ok(Self {
            client,
            url,
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            failures: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Host part of the URL, for status output (the path often embeds a secret).
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("?")
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Fire-and-forget POST of one critical record. Returns immediately.
    pub fn notify(
        &self,
        seq: u64,
        hash: &str,
        entry: &Value,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let body = payload(seq, hash, entry).to_string();
        let request = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let failures = self.failures.clone();
        Some(tokio::spawn(async move {
            let _permit = permit;
            let error = match request.send().await {
                Ok(response) if response.status().is_success() => return,
                Ok(response) => format!("HTTP {}", response.status()),
                Err(e) if e.is_timeout() => "timed out".to_owned(),
                Err(e) => e.without_url().to_string(),
            };
            let n = failures.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= FAILURE_REPORT_LIMIT || n.is_multiple_of(100) {
                eprintln!("sogar warning: webhook alert for record #{seq} failed ({error}); {n} failure(s) so far");
            }
        }))
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, key| v.get(key))?.as_str()
}

/// One-line alert text for chat channels.
pub fn summary(entry: &Value) -> String {
    format!("sogar CRITICAL: {}", describe(entry))
}

/// One-line, human-readable description of a record: who, through which
/// MCP tool, which process, what it touched.
pub fn describe(entry: &Value) -> String {
    let actor = match str_at(entry, &["actor", "type"]) {
        Some("ai_agent") => format!(
            "{} (root {})",
            str_at(entry, &["actor", "agent_name"]).unwrap_or("?"),
            entry
                .pointer("/actor/root_pid")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        ),
        Some("human") => "human".to_owned(),
        _ => "unknown".to_owned(),
    };
    let mut text = actor;
    if let Some(mcp) = entry.get("mcp") {
        text.push_str(&format!(
            " → MCP {}::{}",
            str_at(mcp, &["server_name"]).unwrap_or("?"),
            str_at(mcp, &["tool_name"]).unwrap_or("?")
        ));
    }
    let event = str_at(entry, &["event"]).unwrap_or("?");
    if let (Some(exe), Some(pid)) = (
        str_at(entry, &["executable"]),
        entry.get("pid").and_then(Value::as_u64),
    ) {
        text.push_str(&format!(" → {}[{pid}]", basename(exe)));
    }
    text.push_str(&format!(" {event}"));
    let target = match entry.get("args").and_then(Value::as_array) {
        Some(args) => args
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        None => str_at(entry, &["path"]).unwrap_or("").to_owned(),
    };
    if !target.is_empty() {
        text.push_str(&format!(" {}", truncate_chars(&target, 300)));
    }
    if let Some(conns) = entry.get("network_connections").and_then(Value::as_array) {
        for remote in conns.iter().filter_map(|c| str_at(c, &["remote"])) {
            text.push_str(&format!(" ⇄ {remote}"));
        }
    }
    if let Some(violation) = str_at(entry, &["policy_violation"]) {
        text.push_str(&format!(" | {violation}"));
    }
    text
}

/// Webhook body: chat-friendly text plus the full structured record.
pub fn payload(seq: u64, hash: &str, entry: &Value) -> Value {
    let text = summary(entry);
    json!({
        "text": text,
        "content": truncate_chars(&text, MAX_CONTENT_CHARS),
        "source": "sogar",
        "sogar_version": env!("CARGO_PKG_VERSION"),
        "seq": seq,
        "hash": hash,
        "record": entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn critical_entry() -> Value {
        json!({
            "time": "2026-10-15T08:54:11Z", "event": "open", "severity": "critical",
            "actor": {"type": "ai_agent", "agent_name": "claude", "root_pid": 100},
            "mcp": {"server_name": "compromised-docs-mcp", "tool_name": "search_docs", "rpc_id": 7},
            "pid": 114, "executable": "/bin/cat", "path": "/Users/dev/.ssh/known_hosts",
            "network_connections": [{"protocol": "tcp", "local": "10.0.0.2:5", "remote": "1.1.1.1:443"}],
            "policy_violation": "MCP behavioral drift: server 'compromised-docs-mcp' executed new binary /bin/cat"
        })
    }

    #[test]
    fn payload_is_chat_and_soar_friendly() {
        let body = payload(42, "abc123", &critical_entry());
        let text = body["text"].as_str().expect("text");
        assert_eq!(
            text,
            "sogar CRITICAL: claude (root 100) → MCP compromised-docs-mcp::search_docs → cat[114] open \
             /Users/dev/.ssh/known_hosts ⇄ 1.1.1.1:443 | MCP behavioral drift: server 'compromised-docs-mcp' \
             executed new binary /bin/cat"
        );
        assert_eq!(body["content"], body["text"]);
        assert_eq!(
            (body["seq"].as_u64(), body["hash"].as_str()),
            (Some(42), Some("abc123"))
        );
        assert_eq!(body["record"]["path"], "/Users/dev/.ssh/known_hosts");

        let long = json!({"event": "exec", "args": ["x".repeat(5000)]});
        assert!(
            payload(1, "h", &long)["content"]
                .as_str()
                .expect("content")
                .chars()
                .count()
                <= MAX_CONTENT_CHARS + 1
        );
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(Alerter::new("file:///etc/passwd").is_err());
        assert!(Alerter::new("not a url").is_err());
        assert_eq!(
            Alerter::new("https://hooks.slack.com/services/T0/B0/secret")
                .expect("ok")
                .host(),
            "hooks.slack.com"
        );
    }

    /// Minimal HTTP endpoint: returns the first request's body.
    async fn one_shot_server(respond: bool) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/hook", listener.local_addr().expect("addr"));
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.expect("read");
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if body.len() >= len {
                        if respond {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                                .await;
                        } else {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                        return body.to_owned();
                    }
                }
                if n == 0 {
                    return String::new();
                }
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn posts_critical_records_to_the_webhook() {
        let (url, server) = one_shot_server(true).await;
        let alerter = Alerter::new(&url).expect("alerter");
        let task = alerter
            .notify(9, "deadbeef", &critical_entry())
            .expect("sent");
        task.await.expect("join");
        let body: Value = serde_json::from_str(&server.await.expect("server")).expect("json body");
        assert_eq!(body["seq"], 9);
        assert_eq!(body["record"]["mcp"]["server_name"], "compromised-docs-mcp");
        assert_eq!(alerter.failures(), 0);
    }

    #[tokio::test]
    async fn slow_endpoints_time_out_without_blocking_the_caller() {
        let (url, _server) = one_shot_server(false).await;
        let alerter = Alerter::with_timeout(&url, Duration::from_millis(300)).expect("alerter");
        let started = std::time::Instant::now();
        let task = alerter.notify(1, "h", &critical_entry()).expect("sent");
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "notify must not wait for the endpoint"
        );
        task.await.expect("join");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(alerter.failures(), 1);
    }
}
