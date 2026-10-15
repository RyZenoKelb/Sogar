//! Spawning and resilient parsing of Apple's signed `/usr/bin/eslogger`.
//!
//! `eslogger` prints one JSON object per EndpointSecurity message. Parsing is
//! deliberately forgiving: unknown fields are ignored, missing or `null`
//! fields fall back to defaults, and a malformed line is reported and skipped
//! instead of tearing the daemon down.

use std::collections::HashSet;
use std::process::Stdio;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;

/// Apple's signed EndpointSecurity client (macOS 13+).
pub const ESLOGGER_PATH: &str = "/usr/bin/eslogger";

/// Events sogar always subscribes to.
pub const CORE_EVENTS: &[&str] = &["exec", "open", "write", "rename", "create", "unlink"];

/// Events used when `eslogger --list-events` advertises them: `fork`/`exit`
/// keep the lineage map exact (and safe against PID reuse), `uipc_connect`
/// records Unix-domain socket connections.
pub const OPTIONAL_EVENTS: &[&str] = &["fork", "exit", "uipc_connect"];

const FREAD: i32 = 0x0001;
const FWRITE: i32 = 0x0002;

/// Malformed lines reported verbatim before switching to periodic summaries.
const MALFORMED_REPORT_LIMIT: u64 = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct KernelEvent {
    pub time: DateTime<Utc>,
    pub global_seq_num: Option<u64>,
    pub pid: u32,
    pub ppid: u32,
    pub original_ppid: u32,
    pub responsible_pid: u32,
    pub session_id: u32,
    pub executable: String,
    pub signing_id: Option<String>,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    Exec {
        target_path: String,
        target_pid: u32,
        args: Vec<String>,
        cwd: Option<String>,
    },
    Open {
        path: String,
        fflag: i32,
    },
    Write {
        path: String,
    },
    Create {
        path: String,
    },
    Rename {
        source: String,
        destination: String,
    },
    Unlink {
        path: String,
    },
    Fork {
        child_pid: u32,
    },
    Exit,
    UipcConnect {
        path: String,
    },
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::Exec { .. } => "exec",
            EventKind::Open { .. } => "open",
            EventKind::Write { .. } => "write",
            EventKind::Create { .. } => "create",
            EventKind::Rename { .. } => "rename",
            EventKind::Unlink { .. } => "unlink",
            EventKind::Fork { .. } => "fork",
            EventKind::Exit => "exit",
            EventKind::UipcConnect { .. } => "uipc_connect",
        }
    }

    /// Filesystem paths this event touches.
    pub fn paths(&self) -> Vec<&str> {
        match self {
            EventKind::Exec { target_path, .. } => vec![target_path.as_str()],
            EventKind::Open { path, .. }
            | EventKind::Write { path }
            | EventKind::Create { path }
            | EventKind::Unlink { path }
            | EventKind::UipcConnect { path } => vec![path.as_str()],
            EventKind::Rename { source, destination } => {
                vec![source.as_str(), destination.as_str()]
            }
            EventKind::Fork { .. } | EventKind::Exit => Vec::new(),
        }
    }

    /// Process lifecycle events drive lineage; they are never noise.
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self,
            EventKind::Exec { .. } | EventKind::Fork { .. } | EventKind::Exit
        )
    }
}

/// `open(2)` access mode derived from `fflag`.
pub fn open_access(fflag: i32) -> &'static str {
    match (fflag & FREAD != 0, fflag & FWRITE != 0) {
        (true, true) => "read_write",
        (false, true) => "write",
        _ => "read",
    }
}

// ---------------------------------------------------------------------------
// Raw eslogger schema (only the fields sogar uses)
// ---------------------------------------------------------------------------

/// Treats an explicit JSON `null` like a missing field.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawMessage {
    #[serde(deserialize_with = "null_default")]
    time: String,
    global_seq_num: Option<u64>,
    #[serde(deserialize_with = "null_default")]
    process: RawProcess,
    #[serde(deserialize_with = "null_default")]
    event: RawEvent,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawAuditToken {
    #[serde(deserialize_with = "null_default")]
    pid: u32,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawFile {
    #[serde(deserialize_with = "null_default")]
    path: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawProcess {
    #[serde(deserialize_with = "null_default")]
    audit_token: RawAuditToken,
    #[serde(deserialize_with = "null_default")]
    ppid: u32,
    #[serde(deserialize_with = "null_default")]
    original_ppid: u32,
    #[serde(deserialize_with = "null_default")]
    responsible_audit_token: RawAuditToken,
    #[serde(deserialize_with = "null_default")]
    session_id: u32,
    #[serde(deserialize_with = "null_default")]
    executable: RawFile,
    signing_id: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawEvent {
    exec: Option<RawExec>,
    open: Option<RawOpen>,
    write: Option<RawTarget>,
    create: Option<RawCreate>,
    rename: Option<RawRename>,
    unlink: Option<RawTarget>,
    fork: Option<RawFork>,
    exit: Option<IgnoredAny>,
    uipc_connect: Option<RawUipcConnect>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawExec {
    #[serde(deserialize_with = "null_default")]
    target: RawProcess,
    #[serde(deserialize_with = "null_default")]
    args: Vec<String>,
    cwd: Option<RawFile>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawOpen {
    #[serde(deserialize_with = "null_default")]
    file: RawFile,
    #[serde(deserialize_with = "null_default")]
    fflag: i32,
}

/// `write` and `unlink` both carry `{"target": <file>}`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct RawTarget {
    #[serde(deserialize_with = "null_default")]
    target: RawFile,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawDestination {
    existing_file: Option<RawFile>,
    new_path: Option<RawNewPath>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawNewPath {
    #[serde(deserialize_with = "null_default")]
    dir: RawFile,
    #[serde(deserialize_with = "null_default")]
    filename: String,
}

impl RawDestination {
    fn into_path(self) -> String {
        if let Some(file) = self.existing_file.filter(|f| !f.path.is_empty()) {
            return file.path;
        }
        match self.new_path {
            Some(new) if new.dir.path.is_empty() => new.filename,
            Some(new) if new.filename.is_empty() => new.dir.path,
            Some(new) => format!("{}/{}", new.dir.path.trim_end_matches('/'), new.filename),
            None => String::new(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawCreate {
    #[serde(deserialize_with = "null_default")]
    destination: RawDestination,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawRename {
    #[serde(deserialize_with = "null_default")]
    source: RawFile,
    #[serde(deserialize_with = "null_default")]
    destination: RawDestination,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawFork {
    #[serde(deserialize_with = "null_default")]
    child: RawProcess,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RawUipcConnect {
    #[serde(deserialize_with = "null_default")]
    file: RawFile,
}

/// Parses one eslogger line. `Ok(None)` means valid JSON for an event type
/// sogar does not handle.
pub fn parse_line(line: &[u8]) -> Result<Option<KernelEvent>, serde_json::Error> {
    let raw: RawMessage = serde_json::from_slice(line)?;
    let pid = raw.process.audit_token.pid;
    let ev = raw.event;

    let kind = if let Some(exec) = ev.exec {
        EventKind::Exec {
            target_path: exec.target.executable.path,
            target_pid: match exec.target.audit_token.pid {
                0 => pid,
                target => target,
            },
            args: exec.args,
            cwd: exec.cwd.map(|f| f.path).filter(|p| !p.is_empty()),
        }
    } else if let Some(open) = ev.open {
        EventKind::Open {
            path: open.file.path,
            fflag: open.fflag,
        }
    } else if let Some(write) = ev.write {
        EventKind::Write {
            path: write.target.path,
        }
    } else if let Some(create) = ev.create {
        EventKind::Create {
            path: create.destination.into_path(),
        }
    } else if let Some(rename) = ev.rename {
        EventKind::Rename {
            source: rename.source.path,
            destination: rename.destination.into_path(),
        }
    } else if let Some(unlink) = ev.unlink {
        EventKind::Unlink {
            path: unlink.target.path,
        }
    } else if let Some(fork) = ev.fork {
        EventKind::Fork {
            child_pid: fork.child.audit_token.pid,
        }
    } else if ev.exit.is_some() {
        EventKind::Exit
    } else if let Some(connect) = ev.uipc_connect {
        EventKind::UipcConnect {
            path: connect.file.path,
        }
    } else {
        return Ok(None);
    };

    let time = DateTime::parse_from_rfc3339(&raw.time)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Some(KernelEvent {
        time,
        global_seq_num: raw.global_seq_num,
        pid,
        ppid: raw.process.ppid,
        original_ppid: raw.process.original_ppid,
        responsible_pid: raw.process.responsible_audit_token.pid,
        session_id: raw.process.session_id,
        executable: raw.process.executable.path,
        signing_id: raw.process.signing_id,
        kind,
    }))
}

// ---------------------------------------------------------------------------
// Sensitivity & noise classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Critical,
}

/// What kind of sensitive location a path or argument refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    None,
    /// `.claude` / `.claude.json`: agent configuration, hooks and transcripts.
    AgentConfig,
    /// Credentials, keys, secrets and code-execution hooks.
    Credential,
}

/// Classifies free text (a path, an argv element, a JSON argument summary) by
/// splitting it into path-like components.
pub fn sensitivity(text: &str) -> Sensitivity {
    let mut found = Sensitivity::None;
    let mut prev = "";
    let components = text
        .split(['/', '=', ':', ',', ' ', '\'', '"', '\n'])
        .filter(|c| !c.is_empty());
    for comp in components {
        let credential = matches!(comp, ".ssh" | ".aws" | ".gnupg" | ".kube")
            || (prev == ".config" && comp == "gcloud")
            || (prev == "Library" && comp == "Keychains")
            || (prev == ".git" && comp == "hooks")
            || is_dotenv(comp);
        if credential {
            return Sensitivity::Credential;
        }
        if matches!(comp, ".claude" | ".claude.json") {
            found = Sensitivity::AgentConfig;
        }
        prev = comp;
    }
    found
}

pub fn is_sensitive(text: &str) -> bool {
    sensitivity(text) != Sensitivity::None
}

fn is_dotenv(name: &str) -> bool {
    name == ".env"
        || name
            .strip_prefix(".env.")
            .is_some_and(|suffix| !matches!(suffix, "example" | "sample" | "template" | "dist"))
}

/// Severity of a kernel event. When the acting process *is* the agent's root
/// process, its own `.claude` bookkeeping (settings, transcripts) is routine;
/// anything else touching `.claude` — a tool's child process, an MCP server,
/// a human — stays critical, as do credential paths for everyone.
pub fn event_severity(ev: &KernelEvent, actor_is_agent_root: bool) -> Severity {
    let threshold = if actor_is_agent_root {
        Sensitivity::Credential
    } else {
        Sensitivity::AgentConfig
    };
    let mut texts: Vec<&str> = ev.kind.paths();
    if let EventKind::Exec { args, cwd, .. } = &ev.kind {
        texts.extend(args.iter().map(String::as_str));
        texts.extend(cwd.as_deref());
    }
    if texts.into_iter().any(|t| sensitivity(t) >= threshold) {
        Severity::Critical
    } else {
        Severity::Info
    }
}

const NOISE_PREFIXES: &[&str] = &[
    "/System/",
    "/usr/lib/",
    "/usr/share/",
    "/private/var/db/",
    "/var/db/",
    "/dev/",
    "/Library/Apple/",
    "/AppleInternal/",
];

const USER_PREFIXES: &[&str] = &["/Users/", "/Volumes/", "/tmp/", "/private/tmp/"];

const SYSTEM_EXECUTABLE_PREFIXES: &[&str] = &[
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/sbin/",
    "/Library/Apple/",
];

fn is_noise_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    if USER_PREFIXES.iter().any(|p| path.starts_with(p)) || is_sensitive(path) {
        return false;
    }
    NOISE_PREFIXES.iter().any(|p| path.starts_with(p)) || path.ends_with(".dylib")
}

/// Where executables and app bundles live. Read-only opens of these (and of
/// `/` itself) are the loader mapping a binary at exec time; the `exec`
/// event already records what ran.
const LOADER_READ_PREFIXES: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/opt/homebrew/bin/",
    "/opt/homebrew/Cellar/",
    "/Applications/",
];

/// Apps whose own cache churn under `~/Library/Application Support/<app>/` is routine.
const VENDOR_APPS: &[&str] = &["Claude", "Cursor", "Windsurf"];

/// Cache directory prefixes inside a vendor app's Application Support folder.
const VENDOR_CACHE_DIRS: &[&str] = &["Cache", "GPUCache", "Code Cache"];

/// Chromium web storage and Claude's `git-shadow` checkout: an app's own
/// state, routine when the app writes it, interesting when anything else does.
const VENDOR_STATE_DIRS: &[&str] = &[
    "IndexedDB",
    "Local Storage",
    "Session Storage",
    "blob_storage",
    "git-shadow",
];

fn is_loader_read(path: &str) -> bool {
    path == "/"
        || LOADER_READ_PREFIXES
            .iter()
            .any(|p| path.starts_with(p) || path == p.trim_end_matches('/'))
}

/// `path` relative to the user's home when it is under `/Users/<name>/`.
fn home_relative(path: &str) -> Option<&str> {
    path.strip_prefix("/Users/")?.split_once('/').map(|(_, rel)| rel)
}

/// `~/Library/Caches/`, `~/Library/Logs/`, and the Chromium caches and web
/// storage of Claude, Cursor and Windsurf (also inside `Partitions/<x>/`).
fn is_vendor_churn_path(path: &str) -> bool {
    let Some(rel) = home_relative(path) else {
        return false;
    };
    if rel.starts_with("Library/Caches/") || rel.starts_with("Library/Logs/") {
        return true;
    }
    let Some((app, inner)) = rel
        .strip_prefix("Library/Application Support/")
        .and_then(|r| r.split_once('/'))
    else {
        return false;
    };
    VENDOR_APPS.contains(&app)
        && (VENDOR_CACHE_DIRS.iter().any(|d| inner.starts_with(d))
            || inner.split('/').any(|component| VENDOR_STATE_DIRS.contains(&component)))
}

/// A process shipped inside an application bundle or by Apple, as opposed to
/// the shells and interpreters (`bash`, `node`, `python`, ...) an agent spawns.
fn is_vendor_process(executable: &str) -> bool {
    let in_app_bundle = executable.contains(".app/")
        && (executable.starts_with("/Applications/")
            || home_relative(executable).is_some_and(|r| r.starts_with("Applications/")));
    in_app_bundle || is_system_executable(executable)
}

/// Why an event carries no attribution value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noise {
    /// Background system reads: frameworks, dyld loads, `/dev/null`, ...
    System,
    /// Read-only opens of binaries and app bundles while they are loaded.
    Loader,
    /// An app bundle's own cache, log and web-storage churn. The caller must
    /// still keep it when the process belongs to an MCP server.
    VendorChurn,
}

/// Classifies routine activity. Lifecycle events and anything touching a
/// sensitive path are never noise; cache/storage access by a non-vendor
/// process (a `bash`, `node`, `python` or `curl` child reading app state)
/// is kept.
pub fn noise_class(ev: &KernelEvent) -> Option<Noise> {
    if ev.kind.is_lifecycle() {
        return None;
    }
    let paths = ev.kind.paths();
    if paths.iter().copied().all(is_noise_path) {
        return Some(Noise::System);
    }
    if paths.iter().any(|p| is_sensitive(p)) {
        return None;
    }
    if let EventKind::Open { path, fflag } = &ev.kind {
        if fflag & FWRITE == 0 && is_loader_read(path) {
            return Some(Noise::Loader);
        }
    }
    (paths.iter().copied().all(is_vendor_churn_path) && is_vendor_process(&ev.executable))
        .then_some(Noise::VendorChurn)
}

#[cfg(test)]
pub fn is_noise(ev: &KernelEvent) -> bool {
    noise_class(ev).is_some()
}

/// Apple system daemons (Spotlight, securityd, ...) that legitimately touch
/// keychains and dotfiles all day long.
pub fn is_system_executable(path: &str) -> bool {
    SYSTEM_EXECUTABLE_PREFIXES.iter().any(|p| path.starts_with(p))
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

/// Core events plus whichever optional events this macOS build supports.
pub async fn select_events() -> Vec<&'static str> {
    let mut events = CORE_EVENTS.to_vec();
    let listed = Command::new(ESLOGGER_PATH)
        .arg("--list-events")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await;
    if let Ok(out) = listed {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let supported: HashSet<&str> = text.split_whitespace().collect();
            events.extend(OPTIONAL_EVENTS.iter().filter(|e| supported.contains(*e)));
        }
    }
    events
}

/// Spawns eslogger in its own process group so a terminal Ctrl-C reaches the
/// daemon first and the daemon decides when eslogger stops.
pub fn spawn(events: &[&str]) -> Result<(Child, ChildStdout)> {
    let mut child = Command::new(ESLOGGER_PATH)
        .args(events)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn {ESLOGGER_PATH}"))?;
    let stdout = child
        .stdout
        .take()
        .context("eslogger stdout was not captured")?;
    Ok((child, stdout))
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PumpStats {
    pub lines: u64,
    pub malformed: u64,
    pub unhandled: u64,
}

/// Reads eslogger output line by line and forwards parsed events. Returns
/// when eslogger closes its stdout or the receiver goes away.
pub async fn pump<R>(reader: R, tx: mpsc::Sender<KernelEvent>) -> PumpStats
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::with_capacity(1 << 16, reader);
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut stats = PumpStats::default();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("sogar: failed to read eslogger output: {e}");
                break;
            }
        }
        let line = buf.trim_ascii();
        if line.is_empty() {
            continue;
        }
        stats.lines += 1;
        match parse_line(line) {
            Ok(Some(ev)) => {
                if tx.send(ev).await.is_err() {
                    break;
                }
            }
            Ok(None) => stats.unhandled += 1,
            Err(e) => {
                stats.malformed += 1;
                if stats.malformed <= MALFORMED_REPORT_LIMIT {
                    let preview = String::from_utf8_lossy(&line[..line.len().min(160)]);
                    eprintln!("sogar: skipping malformed eslogger line ({e}): {preview}");
                } else if stats.malformed % 1000 == 0 {
                    eprintln!("sogar: {} malformed eslogger lines skipped so far", stats.malformed);
                }
            }
        }
    }
    stats
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// A realistic eslogger message with extra fields sogar must ignore.
    pub(crate) fn message(pid: u32, ppid: u32, exe: &str, event: Value) -> Value {
        json!({
            "schema_version": 1,
            "version": 7,
            "mach_time": 1_234_567_u64,
            "event_type": 9,
            "seq_num": 3,
            "global_seq_num": 42,
            "time": "2026-10-15T01:15:22.123456789Z",
            "action_type": 1,
            "thread": {"thread_id": 99},
            "process": {
                "audit_token": {"pid": pid, "euid": 501, "pidversion": 7},
                "ppid": ppid,
                "original_ppid": ppid,
                "responsible_audit_token": {"pid": 400},
                "session_id": 400,
                "group_id": pid,
                "executable": {"path": exe, "path_truncated": false, "stat": {"st_size": 1}},
                "signing_id": "com.apple.zsh",
                "team_id": null,
                "tty": null,
                "is_platform_binary": true
            },
            "event": event
        })
    }

    fn parse(v: &Value) -> KernelEvent {
        parse_line(v.to_string().as_bytes())
            .expect("valid JSON")
            .expect("handled event")
    }

    #[test]
    fn parses_exec_with_args_cwd_and_process_metadata() {
        let msg = message(
            501,
            500,
            "/bin/zsh",
            json!({"exec": {
                "target": {"audit_token": {"pid": 501}, "ppid": 500,
                           "executable": {"path": "/usr/bin/curl"}, "signing_id": "com.apple.curl"},
                "args": ["curl", "-s", "https://example.com"],
                "cwd": {"path": "/Users/dev/project"},
                "env": [],
                "script": null
            }}),
        );
        let ev = parse(&msg);
        assert_eq!(ev.pid, 501);
        assert_eq!(ev.ppid, 500);
        assert_eq!(ev.responsible_pid, 400);
        assert_eq!(ev.session_id, 400);
        assert_eq!(ev.global_seq_num, Some(42));
        assert_eq!(ev.executable, "/bin/zsh");
        assert_eq!(ev.signing_id.as_deref(), Some("com.apple.zsh"));
        assert_eq!(ev.time.to_rfc3339(), "2026-10-15T01:15:22.123456789+00:00");
        assert_eq!(
            ev.kind,
            EventKind::Exec {
                target_path: "/usr/bin/curl".into(),
                target_pid: 501,
                args: vec!["curl".into(), "-s".into(), "https://example.com".into()],
                cwd: Some("/Users/dev/project".into()),
            }
        );
    }

    #[test]
    fn parses_file_events() {
        let open = parse(&message(7, 1, "/bin/cat", json!({"open": {"file": {"path": "/Users/dev/.ssh/id_rsa"}, "fflag": 1}})));
        assert_eq!(open.kind, EventKind::Open { path: "/Users/dev/.ssh/id_rsa".into(), fflag: 1 });

        let write = parse(&message(7, 1, "/bin/cat", json!({"write": {"target": {"path": "/tmp/out"}}})));
        assert_eq!(write.kind, EventKind::Write { path: "/tmp/out".into() });

        let unlink = parse(&message(7, 1, "/bin/rm", json!({"unlink": {"target": {"path": "/tmp/x"}, "parent_dir": {"path": "/tmp"}}})));
        assert_eq!(unlink.kind, EventKind::Unlink { path: "/tmp/x".into() });

        let create_existing = parse(&message(7, 1, "/bin/x", json!({"create": {"destination_type": 0,
            "destination": {"existing_file": {"path": "/Users/dev/a.txt"}}}})));
        assert_eq!(create_existing.kind, EventKind::Create { path: "/Users/dev/a.txt".into() });

        let create_new = parse(&message(7, 1, "/bin/x", json!({"create": {"destination_type": 1,
            "destination": {"new_path": {"dir": {"path": "/Users/dev/"}, "filename": "b.txt", "mode": 420}}}})));
        assert_eq!(create_new.kind, EventKind::Create { path: "/Users/dev/b.txt".into() });

        let rename = parse(&message(7, 1, "/bin/mv", json!({"rename": {"source": {"path": "/tmp/a"},
            "destination_type": 1, "destination": {"new_path": {"dir": {"path": "/tmp"}, "filename": "b"}}}})));
        assert_eq!(rename.kind, EventKind::Rename { source: "/tmp/a".into(), destination: "/tmp/b".into() });
    }

    #[test]
    fn parses_lifecycle_events() {
        let fork = parse(&message(10, 1, "/bin/zsh", json!({"fork": {"child": {"audit_token": {"pid": 11}, "ppid": 10}}})));
        assert_eq!(fork.kind, EventKind::Fork { child_pid: 11 });
        let exit = parse(&message(10, 1, "/bin/zsh", json!({"exit": {"stat": 0}})));
        assert_eq!(exit.kind, EventKind::Exit);
    }

    #[test]
    fn tolerates_nulls_missing_fields_and_unknown_events() {
        let mut msg = message(5, 1, "/bin/x", json!({"open": {"file": {"path": "/tmp/a"}, "fflag": null}}));
        msg["process"]["responsible_audit_token"] = Value::Null;
        msg["process"]["signing_id"] = Value::Null;
        msg["time"] = Value::Null;
        let ev = parse(&msg);
        assert_eq!(ev.responsible_pid, 0);
        assert_eq!(ev.signing_id, None);
        assert_eq!(ev.kind, EventKind::Open { path: "/tmp/a".into(), fflag: 0 });

        let unknown = message(5, 1, "/bin/x", json!({"mmap": {"source": {"path": "/x"}}}));
        assert_eq!(parse_line(unknown.to_string().as_bytes()).expect("valid"), None);

        assert!(parse_line(b"{not json").is_err());
        assert!(parse_line(b"42").is_err());
        assert!(matches!(parse_line(b"[]"), Ok(None)));
    }

    #[test]
    fn classifies_sensitive_paths() {
        for path in [
            "/Users/dev/.ssh/id_ed25519",
            "/Users/dev/.aws/credentials",
            "/Users/dev/.gnupg/pubring.kbx",
            "/Users/dev/.config/gcloud/credentials.db",
            "/Users/dev/.kube/config",
            "/Users/dev/Library/Keychains/login.keychain-db",
            "/Users/dev/app/.env",
            "/Users/dev/app/.env.production",
            "/Users/dev/app/.git/hooks/pre-commit",
            "--env-file=/Users/dev/app/.env",
        ] {
            assert_eq!(sensitivity(path), Sensitivity::Credential, "{path}");
        }
        assert_eq!(sensitivity("/Users/dev/.claude/settings.json"), Sensitivity::AgentConfig);
        assert_eq!(sensitivity(r#"{"path":"/Users/dev/.ssh/id_rsa"}"#), Sensitivity::Credential);
        for path in [
            "/Users/dev/app/src/main.rs",
            "/Users/dev/app/.env.example",
            "/Users/dev/.config/fish/config.fish",
            "/Users/dev/app/.git/config",
            "/Users/dev/claude/notes.md",
        ] {
            assert_eq!(sensitivity(path), Sensitivity::None, "{path}");
        }
    }

    #[test]
    fn agent_root_may_touch_its_own_config_but_not_credentials() {
        let claude_cfg = parse(&message(9, 1, "/usr/local/bin/claude",
            json!({"write": {"target": {"path": "/Users/dev/.claude/projects/x.jsonl"}}})));
        assert_eq!(event_severity(&claude_cfg, true), Severity::Info);
        assert_eq!(event_severity(&claude_cfg, false), Severity::Critical);

        let ssh = parse(&message(9, 1, "/usr/local/bin/claude",
            json!({"open": {"file": {"path": "/Users/dev/.ssh/id_rsa"}, "fflag": 1}})));
        assert_eq!(event_severity(&ssh, true), Severity::Critical);

        let exec = parse(&message(9, 1, "/bin/zsh", json!({"exec": {
            "target": {"executable": {"path": "/bin/cat"}}, "args": ["cat", "/Users/dev/.aws/credentials"]}})));
        assert_eq!(event_severity(&exec, false), Severity::Critical);
    }

    #[test]
    fn filters_system_noise_but_keeps_user_and_sensitive_paths() {
        let ev = |path: &str| parse(&message(9, 1, "/bin/x", json!({"open": {"file": {"path": path}, "fflag": 1}})));
        assert!(is_noise(&ev("/System/Library/Frameworks/Foundation.framework/Foundation")));
        assert!(is_noise(&ev("/usr/lib/libSystem.B.dylib")));
        assert!(is_noise(&ev("/dev/null")));
        assert!(is_noise(&ev("/private/var/db/timezone/zoneinfo")));
        assert!(is_noise(&ev("/opt/homebrew/lib/libssl.3.dylib")));
        assert!(!is_noise(&ev("/Users/dev/app/target/libfoo.dylib")));
        assert!(!is_noise(&ev("/Users/dev/app/src/main.rs")));
        assert!(!is_noise(&ev("/etc/hosts")));

        let exec = parse(&message(9, 1, "/bin/zsh", json!({"exec": {"target": {"executable": {"path": "/System/Library/x"}}}})));
        assert!(!is_noise(&exec));
    }

    #[test]
    fn loader_reads_of_binaries_are_noise_but_execs_and_writes_are_not() {
        let open = |path: &str, fflag: i32| {
            parse(&message(9, 1, "/bin/cat", json!({"open": {"file": {"path": path}, "fflag": fflag}})))
        };
        for path in [
            "/bin/cat",
            "/bin",
            "/",
            "/usr/bin/git",
            "/sbin/ping",
            "/usr/sbin/sysctl",
            "/opt/homebrew/bin/node",
            "/opt/homebrew/Cellar/git/2.47.0/libexec/git-core/git",
            "/Applications/Claude.app/Contents/Helpers",
            "/Applications",
        ] {
            assert!(is_noise(&open(path, 0x1)), "{path}");
        }
        // Writing into these locations is not loader activity.
        assert!(!is_noise(&open("/opt/homebrew/bin/node", 0x2)));
        assert!(!is_noise(&open("/Applications/Evil.app/Contents/MacOS/x", 0x3)));
        // Look-alike prefixes and other system paths are not covered.
        assert!(!is_noise(&open("/binaries/x", 0x1)));
        assert!(!is_noise(&open("/opt/homebrew/etc/gitconfig", 0x1)));
        // The exec itself is always recorded.
        let exec = parse(&message(9, 1, "/bin/zsh", json!({"exec": {"target": {"executable": {"path": "/bin/cat"}}}})));
        assert!(!is_noise(&exec));
    }

    #[test]
    fn vendor_cache_churn_is_noise_unless_a_child_process_touches_it() {
        let helper = "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper";
        let write = |exe: &str, path: &str| parse(&message(9, 1, exe, json!({"write": {"target": {"path": path}}})));
        let read = |exe: &str, path: &str| {
            parse(&message(9, 1, exe, json!({"open": {"file": {"path": path}, "fflag": 1}})))
        };

        for path in [
            "/Users/dev/Library/Application Support/Claude/Cache/Cache_Data/6e063714164c1525_0",
            "/Users/dev/Library/Application Support/Claude/GPUCache/data_1",
            "/Users/dev/Library/Application Support/Claude/Code Cache/js/index",
            "/Users/dev/Library/Application Support/Cursor/CacheStorage/x",
            "/Users/dev/Library/Application Support/Windsurf/Cache/y",
            "/Users/dev/Library/Caches/com.anthropic.claudefordesktop/Cache.db",
            "/Users/dev/Library/Logs/Claude/main.log",
        ] {
            assert!(is_noise(&write(helper, path)), "{path}");
            assert!(is_noise(&read("/System/Library/CoreServices/x", path)), "{path}");
        }

        // A shell/interpreter child reading app caches is exactly what we want to see.
        let cache = "/Users/dev/Library/Application Support/Claude/Cache/Cache_Data/1";
        assert!(!is_noise(&read("/bin/bash", cache)));
        assert!(!is_noise(&read("/opt/homebrew/bin/python3.12", cache)));
        assert!(!is_noise(&read("/opt/homebrew/bin/node", "/Users/dev/Library/Caches/x")));

        // Non-cache app state (cookies, local storage) and other apps stay visible.
        // Cookies and other apps stay visible.
        assert!(!is_noise(&write(helper, "/Users/dev/Library/Application Support/Claude/Cookies")));
        assert!(!is_noise(&write(helper, "/Users/dev/Library/Application Support/Slack/Cache/x")));

        // A rename out of the cache into the project is not routine.
        let rename = parse(&message(9, 1, helper, json!({"rename": {
            "source": {"path": "/Users/dev/Library/Caches/x"},
            "destination": {"existing_file": {"path": "/Users/dev/app/x"}}}})));
        assert!(!is_noise(&rename));
    }

    #[test]
    fn vendor_web_storage_and_git_shadow_are_churn_only_for_vendor_processes() {
        let helper = "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper";
        let claude = "/Applications/Claude.app/Contents/MacOS/Claude";
        let ev = |exe: &str, path: &str| parse(&message(9, 1, exe, json!({"write": {"target": {"path": path}}})));
        let support = "/Users/dev/Library/Application Support";
        for path in [
            format!("{support}/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000123.log"),
            format!("{support}/Claude/Local Storage/leveldb/1.log"),
            format!("{support}/Claude/Session Storage/000003.log"),
            format!("{support}/Claude/blob_storage/0f2e/1"),
            format!("{support}/Claude/git-shadow/4f1a/objects/ab/cdef"),
            format!("{support}/Cursor/Partitions/main/IndexedDB/x"),
            format!("{support}/Windsurf/Local Storage/leveldb/2.ldb"),
        ] {
            assert_eq!(noise_class(&ev(helper, &path)), Some(Noise::VendorChurn), "{path}");
            assert_eq!(noise_class(&ev(claude, &path)), Some(Noise::VendorChurn), "{path}");
            for child in ["/bin/bash", "/bin/sh", "/opt/homebrew/bin/node", "/usr/bin/python3", "/usr/bin/curl"] {
                assert_eq!(noise_class(&ev(child, &path)), None, "{child} {path}");
            }
        }
        // Similar names elsewhere are not vendor state.
        assert_eq!(noise_class(&ev(helper, "/Users/dev/app/IndexedDB/x")), None);
        assert_eq!(noise_class(&ev(helper, &format!("{support}/Slack/IndexedDB/x"))), None);
        assert_eq!(noise_class(&ev(helper, &format!("{support}/Claude/IndexedDBx/y"))), None);
    }

    #[test]
    fn noise_classes_distinguish_system_loader_and_vendor_churn() {
        let open = |exe: &str, path: &str| parse(&message(9, 1, exe, json!({"open": {"file": {"path": path}, "fflag": 1}})));
        assert_eq!(noise_class(&open("/bin/cat", "/usr/lib/dyld")), Some(Noise::System));
        assert_eq!(noise_class(&open("/bin/cat", "/bin/cat")), Some(Noise::Loader));
        assert_eq!(
            noise_class(&open("/Applications/Claude.app/Contents/MacOS/Claude", "/Users/dev/Library/Logs/Claude/main.log")),
            Some(Noise::VendorChurn)
        );
    }

    #[test]
    fn open_access_modes() {
        assert_eq!(open_access(0x1), "read");
        assert_eq!(open_access(0x2), "write");
        assert_eq!(open_access(0x3), "read_write");
    }

    #[tokio::test]
    async fn pump_skips_malformed_lines_and_keeps_going() {
        let good = message(3, 1, "/bin/x", json!({"write": {"target": {"path": "/tmp/a"}}})).to_string();
        let input = format!("garbage\n\n{good}\n{{\"event\":{{\"mmap\":{{}}}}}}\n{good}");
        let (tx, mut rx) = mpsc::channel(8);
        let stats = pump(input.as_bytes(), tx).await;
        assert_eq!(stats.lines, 4);
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.unhandled, 1);
        let mut received = 0;
        while rx.recv().await.is_some() {
            received += 1;
        }
        assert_eq!(received, 2);
    }
}
