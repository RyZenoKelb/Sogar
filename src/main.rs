//! sogar — macOS kernel-to-MCP flight recorder.
//!
//! `sogar watch` joins EndpointSecurity telemetry from `/usr/bin/eslogger`
//! with MCP tool-call context reported by `sogar mcp-wrap`, attributes every
//! event to an AI agent (and tool call) or a human, and appends it to a
//! SHA-256 hash-chained flight record that `sogar verify` can check.

mod alert;
mod config_wrap;
mod doctor;
mod eslogger;
mod export;
mod ipc;
mod ledger;
mod lineage;
mod mcp_proxy;
mod net_inspect;
mod policy;
mod report;

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::{Args, Parser, Subcommand};
use colored::{ColoredString, Colorize};
use serde::Serialize;
use serde_json::Value;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::eslogger::{EventKind, KernelEvent, Noise, Severity};
use crate::ipc::Envelope;
use crate::ledger::{Ledger, Verification};
use crate::lineage::{
    basename, Actor, AgentMatcher, Attribution, IpcEffect, LineageTracker, McpToolCall,
};
use crate::net_inspect::SocketConnection;
use crate::policy::{Lockfile, Observation};

const KERNEL_QUEUE_DEPTH: usize = 65_536;
const IPC_QUEUE_DEPTH: usize = 4_096;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_GAP_WARNINGS: u64 = 20;
const MAX_TARGET_CHARS: usize = 240;
/// Second socket snapshot for freshly exec'd network binaries.
const NET_POLL_DELAY: Duration = Duration::from_millis(40);
/// How long shutdown waits for entries still in their socket poll window.
const DEFERRED_DRAIN: Duration = Duration::from_millis(250);

#[derive(Parser)]
#[command(
    name = "sogar",
    version,
    about = "Kernel-to-MCP flight recorder for AI agents on macOS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record kernel activity and attribute it to AI agents or humans (requires root)
    Watch(WatchArgs),
    /// Proxy a stdio MCP server and report its tool calls to `sogar watch`
    McpWrap(WrapArgs),
    /// Verify the SHA-256 hash chain of a flight record (exit 0 valid, 1 tampered)
    Verify(VerifyArgs),
    /// Route every configured MCP server (Claude Code, Cursor, Claude Desktop) through `sogar mcp-wrap`
    Init(ConfigArgs),
    /// Remove the `sogar mcp-wrap` prefix from configured MCP servers
    Unwrap(ConfigArgs),
    /// Verify a flight record and print a forensic summary (exit 1 if tampered)
    Report(ReportArgs),
    /// Learn each MCP server's normal behaviour from a verified record into a lockfile
    Lock(LockArgs),
    /// Export a verified record as OCSF (SIEM), SARIF (CI) or JSONL to stdout
    Export(ExportArgs),
    /// Read-only health check: eslogger, daemon socket, ledger integrity, lockfile, MCP configs
    Doctor(DoctorArgs),
}

#[derive(Args)]
struct WatchArgs {
    /// Regex identifying AI agent executables; replaces the built-in
    /// claude/Cursor/codex/windsurf/aider/goose pattern (group 1 names the agent)
    #[arg(long, value_name = "REGEX")]
    agent_match: Option<String>,
    /// Flight record path [default: ~/.sogar/flight_record.jsonl of the invoking user]
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
    /// Also record non-critical activity of human-driven processes (very verbose)
    #[arg(long)]
    include_human: bool,
    /// Unix socket on which `sogar mcp-wrap` reports MCP tool calls
    #[arg(long, value_name = "PATH", default_value = ipc::SOCKET_PATH)]
    socket: PathBuf,
    /// MCP behavioral lockfile to enforce [default: ~/.sogar/mcp_lock.json, if present]
    #[arg(long, value_name = "PATH")]
    lockfile: Option<PathBuf>,
    /// POST every critical record as JSON to this URL (Slack, Discord, Torq, Tines, ...)
    #[arg(long, value_name = "URL")]
    webhook_url: Option<String>,
}

#[derive(Args)]
struct DoctorArgs {
    /// Flight record to check [default: ~/.sogar/flight_record.jsonl]
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Daemon socket to check
    #[arg(long, value_name = "PATH", default_value = ipc::SOCKET_PATH)]
    socket: PathBuf,
}

#[derive(Args)]
struct LockArgs {
    /// Verified flight record to learn from [default: ~/.sogar/flight_record.jsonl]
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Lockfile to write [default: ~/.sogar/mcp_lock.json]
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct WrapArgs {
    /// Name of the MCP server, as shown in the flight record
    #[arg(long, value_name = "SERVER_NAME")]
    name: String,
    /// Unix socket of the `sogar watch` daemon
    #[arg(long, value_name = "PATH", default_value = ipc::SOCKET_PATH)]
    socket: PathBuf,
    /// MCP server command line, after `--`
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct ConfigArgs {
    /// Show what would change without writing any file
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct ReportArgs {
    /// Flight record to analyse [default: ~/.sogar/flight_record.jsonl]
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Only print the critical events
    #[arg(long)]
    critical_only: bool,
    /// Only consider records written after this sequence number
    #[arg(long, value_name = "SEQ")]
    after_seq: Option<u64>,
}

#[derive(Args)]
struct ExportArgs {
    /// Flight record to export [default: ~/.sogar/flight_record.jsonl]
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// ocsf: OCSF 1.3 events (NDJSON); sarif: SARIF 2.1.0 log of critical findings; jsonl: verified entries
    #[arg(long, value_enum)]
    format: export::Format,
    /// Only export critical records (SARIF always contains only findings)
    #[arg(long)]
    critical_only: bool,
    /// Only export records written after this sequence number
    #[arg(long, value_name = "SEQ")]
    after_seq: Option<u64>,
    /// Exit with status 3 when any critical record or policy violation is exported (for CI)
    #[arg(long)]
    fail_on_findings: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Flight record to verify [default: ~/.sogar/flight_record.jsonl]
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify(args) => run_verify(args),
        Command::Report(args) => run_report(args),
        Command::Lock(args) => run_lock(args),
        Command::Export(args) => run_export(args),
        Command::Doctor(args) => run_doctor(args),
        Command::Init(args) => run_config(config_wrap::Mode::Wrap, args),
        Command::Unwrap(args) => run_config(config_wrap::Mode::Unwrap, args),
        Command::Watch(args) => {
            let result = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to start the async runtime")
                .and_then(|rt| rt.block_on(run_watch(args)));
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} {e:#}", "sogar:".red().bold());
                    ExitCode::FAILURE
                }
            }
        }
        Command::McpWrap(args) => {
            let opts = mcp_proxy::WrapOptions {
                server_name: args.name,
                command: args.command,
                socket: args.socket,
            };
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to start the async runtime")
                .and_then(|rt| rt.block_on(mcp_proxy::run(opts)));
            // Exit directly: the runtime would otherwise wait on the blocking
            // stdin reader, which only returns when the client closes stdin.
            match result {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("sogar mcp-wrap: {e:#}");
                    std::process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn run_verify(args: VerifyArgs) -> ExitCode {
    let path = match args.file.map_or_else(ledger::default_path, Ok) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("sogar verify: {e:#}");
            return ExitCode::from(2);
        }
    };
    match ledger::verify_file(&path) {
        Ok(Verification::Valid { records, head_hash }) => {
            println!(
                "{} {} — {records} records, hash chain intact",
                "VALID".green().bold(),
                path.display()
            );
            println!("head {head_hash}");
            ExitCode::SUCCESS
        }
        Ok(Verification::Tampered { line, reason }) => {
            println!(
                "{} {} — line {line}: {reason}",
                "TAMPERED".red().bold(),
                path.display()
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("sogar verify: {e:#}");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// init / unwrap / report
// ---------------------------------------------------------------------------

fn plain_output_unless_terminal() {
    if !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }
}

fn run_config(mode: config_wrap::Mode, args: ConfigArgs) -> ExitCode {
    plain_output_unless_terminal();
    match config_wrap::run(mode, args.dry_run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e:#}", "sogar:".red().bold());
            ExitCode::FAILURE
        }
    }
}

fn run_report(args: ReportArgs) -> ExitCode {
    plain_output_unless_terminal();
    let path = match args.file.map_or_else(ledger::default_path, Ok) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("sogar report: {e:#}");
            return ExitCode::from(2);
        }
    };
    match report::analyze(&path, args.after_seq) {
        Ok(summary) => {
            print!("{}", report::render(&summary, &path, args.critical_only));
            if summary.is_tampered() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("sogar report: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run_doctor(args: DoctorArgs) -> ExitCode {
    plain_output_unless_terminal();
    let ledger_path = match args.file.map_or_else(ledger::default_path, Ok) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("sogar doctor: {e:#}");
            return ExitCode::from(2);
        }
    };
    let checks = doctor::run(&ledger_path, &args.socket);
    print!("{}", doctor::render(&checks));
    if checks.iter().any(|c| c.status == doctor::Status::Fail) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run_export(args: ExportArgs) -> ExitCode {
    let path = match args.file.map_or_else(ledger::default_path, Ok) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("sogar export: {e:#}");
            return ExitCode::from(2);
        }
    };
    let opts = export::ExportOptions {
        critical_only: args.critical_only,
        after_seq: args.after_seq,
    };
    match export::export(&path, args.format, opts) {
        Ok(out) => {
            let mut stdout = std::io::stdout().lock();
            if let Err(e) = stdout
                .write_all(out.text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                eprintln!("sogar export: failed to write output: {e}");
                return ExitCode::from(2);
            }
            if out.tampered {
                eprintln!("sogar export: the flight record is TAMPERED; only records before the break were exported");
                ExitCode::from(1)
            } else if args.fail_on_findings && out.findings > 0 {
                eprintln!("sogar export: {} critical finding(s)", out.findings);
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("sogar export: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run_lock(args: LockArgs) -> ExitCode {
    plain_output_unless_terminal();
    let paths = args
        .file
        .map_or_else(ledger::default_path, Ok)
        .and_then(|file| Ok((file, args.out.map_or_else(policy::default_path, Ok)?)));
    let result = paths.and_then(|(file, out)| policy::lock(&file, &out).map(|o| (file, out, o)));
    match result {
        Ok((file, out, outcome)) => {
            println!(
                "Learned {} MCP server baseline(s) from {} ({} observations; {} critical or drifting events excluded)",
                outcome.lockfile.servers.len(),
                file.display(),
                outcome.stats.observations,
                outcome.stats.excluded
            );
            let width = outcome
                .lockfile
                .servers
                .keys()
                .map(|k| k.chars().count())
                .max()
                .unwrap_or(6)
                .max(6);
            println!(
                "\n{}",
                format!("{:<width$}  EXECUTABLES  PATH PREFIXES  NETWORK", "SERVER").bold()
            );
            for (name, server) in &outcome.lockfile.servers {
                println!(
                    "{name:<width$}  {:>11}  {:>13}  {}",
                    server.allowed_executables.len(),
                    server.allowed_path_prefixes.len(),
                    if server.allow_network {
                        "allowed".yellow()
                    } else {
                        "denied".green()
                    }
                );
            }
            println!(
                "\nWrote {}. Review it, then `sudo sogar watch` enforces it.",
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{} {e:#}", "sogar lock:".red().bold());
            ExitCode::FAILURE
        }
    }
}

/// The explicit `--lockfile`, or the default one if it exists.
fn load_lockfile(explicit: Option<&Path>) -> Result<Option<Lockfile>> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => {
            let path = policy::default_path()?;
            if !path.exists() {
                return Ok(None);
            }
            path
        }
    };
    let lockfile = Lockfile::load(&path)?;
    status(&format!(
        "enforcing MCP lockfile {} ({} server(s))",
        path.display(),
        lockfile.servers.len()
    ));
    if let Some(warning) = policy::ownership_warning(&path) {
        warn(&warning);
    }
    Ok(Some(lockfile))
}

// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

/// A kernel event as written to the flight record.
#[derive(Debug, Serialize)]
struct AuditEntry {
    time: DateTime<Utc>,
    event: &'static str,
    severity: Severity,
    actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpToolCall>,
    pid: u32,
    ppid: u32,
    original_ppid: u32,
    responsible_pid: u32,
    session_id: u32,
    executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network_connections: Vec<SocketConnection>,
    /// MCP server owning the process when no tool call was active.
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_violation: Option<String>,
}

impl AuditEntry {
    fn new(ev: KernelEvent, attribution: Attribution, severity: Severity) -> Self {
        let event = ev.kind.name();
        let (mut path, mut destination, mut access, mut args, mut cwd) =
            (None, None, None, None, None);
        match ev.kind {
            EventKind::Exec {
                target_path,
                args: argv,
                cwd: dir,
                ..
            } => {
                path = Some(target_path);
                args = Some(argv.iter().map(|a| mcp_proxy::redact_secrets(a)).collect());
                cwd = dir;
            }
            EventKind::Open { path: p, fflag } => {
                path = Some(p);
                access = Some(eslogger::open_access(fflag));
            }
            EventKind::Write { path: p }
            | EventKind::Create { path: p }
            | EventKind::Unlink { path: p }
            | EventKind::UipcConnect { path: p } => path = Some(p),
            EventKind::Rename {
                source,
                destination: d,
            } => {
                path = Some(source);
                destination = Some(d);
            }
            EventKind::Fork { .. } | EventKind::Exit => {}
        }
        Self {
            time: ev.time,
            event,
            severity,
            actor: attribution.actor,
            mcp_server: attribution.mcp_server.filter(|_| attribution.mcp.is_none()),
            mcp: attribution.mcp,
            pid: ev.pid,
            ppid: ev.ppid,
            original_ppid: ev.original_ppid,
            responsible_pid: ev.responsible_pid,
            session_id: ev.session_id,
            executable: ev.executable,
            signing_id: ev.signing_id,
            path,
            destination,
            access,
            args,
            cwd,
            network_connections: Vec::new(),
            policy_violation: None,
        }
    }

    fn server_name(&self) -> Option<&str> {
        self.mcp
            .as_ref()
            .map(|m| m.server_name.as_str())
            .or(self.mcp_server.as_deref())
    }

    /// Checks an MCP-attributed entry against the lockfile; drift makes it critical.
    fn enforce(&mut self, lockfile: &Lockfile) {
        let Some(server) = self.server_name() else {
            return;
        };
        let (exec_target, paths) = if self.event == "exec" {
            (self.path.as_deref(), Vec::new())
        } else {
            (
                None,
                self.path
                    .iter()
                    .chain(&self.destination)
                    .map(String::as_str)
                    .collect(),
            )
        };
        let observation = Observation {
            server,
            exec_target,
            paths,
            external_remotes: self
                .network_connections
                .iter()
                .filter_map(|c| c.remote.as_deref())
                .filter(|r| policy::is_external(r))
                .collect(),
        };
        let violation = lockfile.evaluate(&observation);
        if violation.is_some() {
            self.severity = Severity::Critical;
        }
        self.policy_violation = violation;
    }

    fn is_network_exec(&self) -> bool {
        self.event == "exec"
            && self
                .path
                .as_deref()
                .is_some_and(net_inspect::is_network_binary)
    }
}

/// An MCP tool-call boundary as written to the flight record.
#[derive(Debug, Serialize)]
struct McpEntry {
    time: DateTime<Utc>,
    event: &'static str,
    severity: Severity,
    actor: Actor,
    mcp: McpToolCall,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_error: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cancelled: bool,
}

struct Recorder {
    ledger: Ledger,
    lockfile: Option<Arc<Lockfile>>,
    alerter: Option<alert::Alerter>,
    /// Entries returning from their delayed socket poll.
    deferred_tx: mpsc::Sender<AuditEntry>,
    tracker: LineageTracker,
    include_human: bool,
    socket_path: String,
    own_pid: u32,
    eslogger_pid: Option<u32>,
    last_global_seq: Option<u64>,
    gap_events: u64,
    gap_warnings: u64,
    recorded: u64,
}

impl Recorder {
    fn on_kernel_event(&mut self, ev: KernelEvent) -> Result<()> {
        self.track_sequence(&ev);
        // sogar's own activity (ledger writes, eslogger, ps) is never recorded.
        if ev.pid == self.own_pid || ev.ppid == self.own_pid || Some(ev.pid) == self.eslogger_pid {
            return Ok(());
        }
        if ev.kind.paths().contains(&self.socket_path.as_str()) {
            return Ok(());
        }
        match eslogger::noise_class(&ev) {
            Some(Noise::System | Noise::Loader) => return Ok(()),
            // An app's own cache/storage churn, unless an MCP server is the one touching it.
            Some(Noise::VendorChurn)
                if self.tracker.mcp_server_of(ev.pid).is_none()
                    && self.tracker.mcp_server_of(ev.ppid).is_none() =>
            {
                return Ok(());
            }
            _ => {}
        }

        let attribution = self.tracker.observe(&ev);
        if matches!(ev.kind, EventKind::Fork { .. } | EventKind::Exit) {
            return Ok(());
        }

        let is_agent_root = matches!(
            &attribution.actor,
            Actor::AiAgent { root_pid, .. } if *root_pid == ev.pid
        );
        let severity = eslogger::event_severity(&ev, is_agent_root);
        let record = attribution.actor.is_agent()
            || self.include_human
            || (severity == Severity::Critical && !eslogger::is_system_executable(&ev.executable));
        if !record {
            return Ok(());
        }

        let mut entry = AuditEntry::new(ev, attribution, severity);
        let lockfile = self.lockfile.clone();
        if let Some(lockfile) = &lockfile {
            entry.enforce(lockfile);
        }
        let network_exec = entry.is_network_exec();
        if network_exec || entry.severity == Severity::Critical {
            entry.network_connections = net_inspect::inspect_pid(entry.pid);
        }
        if network_exec {
            // A just-exec'd client has rarely connected yet: look once more
            // shortly after, then write the entry with everything observed.
            let tx = self.deferred_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(NET_POLL_DELAY).await;
                net_inspect::merge(
                    &mut entry.network_connections,
                    net_inspect::inspect_pid(entry.pid),
                );
                if let Some(lockfile) = &lockfile {
                    entry.enforce(lockfile);
                }
                let _ = tx.send(entry).await;
            });
            return Ok(());
        }
        if let Some(lockfile) = &lockfile {
            entry.enforce(lockfile);
        }
        self.write_audit(entry)
    }

    fn write_audit(&mut self, entry: AuditEntry) -> Result<()> {
        self.append(&entry, entry.severity)?;
        render_audit(&entry);
        Ok(())
    }

    /// Appends to the ledger and, for critical records, fires the webhook.
    fn append<T: Serialize>(&mut self, entry: &T, severity: Severity) -> Result<()> {
        let seq = self.ledger.append(entry)?;
        self.recorded += 1;
        if severity == Severity::Critical {
            if let Some(alerter) = &self.alerter {
                let value = serde_json::to_value(entry).context("failed to encode alert")?;
                alerter.notify(seq, self.ledger.head_hash(), &value);
            }
        }
        Ok(())
    }

    fn on_ipc(&mut self, envelope: Envelope) -> Result<()> {
        let time = envelope.msg.timestamp();
        let effect = match self.tracker.apply_ipc(&envelope.msg, envelope.peer_pid) {
            Ok(effect) => effect,
            Err(reason) => {
                warn(&format!(
                    "rejected MCP message from pid {}: {reason}",
                    envelope.peer_pid.map_or("?".into(), |p| p.to_string())
                ));
                return Ok(());
            }
        };
        let (event, call, is_error, cancelled) = match effect {
            IpcEffect::ServerStarted {
                server_name,
                wrapper_pid,
                child_pid,
            } => {
                let actor = self.tracker.actor_of(child_pid);
                status(&format!(
                    "MCP server {} started (pid {child_pid}, wrapper {wrapper_pid}) for {}",
                    server_name.cyan(),
                    actor_tag(&actor)
                ));
                return Ok(());
            }
            IpcEffect::ServerExited {
                server_name,
                child_pid,
            } => {
                status(&format!(
                    "MCP server {} exited (pid {child_pid})",
                    server_name.cyan()
                ));
                return Ok(());
            }
            IpcEffect::Ignored => return Ok(()),
            IpcEffect::CallStarted(call) => ("mcp_call_start", call, None, false),
            IpcEffect::CallEnded {
                call,
                is_error,
                cancelled,
            } => ("mcp_call_end", call, Some(is_error), cancelled),
        };
        let severity = match call.arguments_summary.as_deref().map(eslogger::sensitivity) {
            Some(s) if s != eslogger::Sensitivity::None => Severity::Critical,
            _ => Severity::Info,
        };
        let entry = McpEntry {
            time,
            event,
            severity,
            actor: self.tracker.actor_of(call.child_pid),
            mcp: call,
            is_error,
            cancelled,
        };
        self.append(&entry, entry.severity)?;
        render_mcp(&entry);
        Ok(())
    }

    fn maintain(&mut self) -> Result<()> {
        self.tracker.maintain(Utc::now());
        self.ledger.sync()
    }

    /// eslogger's `global_seq_num` is contiguous per client; gaps mean the
    /// kernel dropped messages because we fell behind.
    fn track_sequence(&mut self, ev: &KernelEvent) {
        let Some(seq) = ev.global_seq_num else { return };
        if let Some(prev) = self.last_global_seq {
            if seq > prev + 1 {
                let gap = seq - prev - 1;
                self.gap_events += gap;
                self.gap_warnings += 1;
                if self.gap_warnings <= MAX_GAP_WARNINGS {
                    warn(&format!(
                        "eslogger sequence gap: {gap} events possibly dropped"
                    ));
                }
            }
        }
        self.last_global_seq = Some(seq);
    }
}

async fn run_watch(args: WatchArgs) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "`sogar watch` must run as root (try `sudo sogar watch`): \
             {} requires root and Full Disk Access",
            eslogger::ESLOGGER_PATH
        );
    }
    if !Path::new(eslogger::ESLOGGER_PATH).exists() {
        bail!(
            "{} not found; sogar requires macOS 13 or later",
            eslogger::ESLOGGER_PATH
        );
    }
    if !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    let matcher = AgentMatcher::new(args.agent_match.as_deref())?;
    let ledger_path = match args.out {
        Some(path) => path,
        None => ledger::default_path()?,
    };
    let ledger = Ledger::open(&ledger_path)?;
    ledger.share_with_invoking_user()?;

    let lockfile = load_lockfile(args.lockfile.as_deref())?;
    let alerter = args
        .webhook_url
        .as_deref()
        .map(alert::Alerter::new)
        .transpose()?;

    let listener = ipc::bind_server(&args.socket)?;
    let _socket_guard = ipc::SocketGuard::new(&args.socket);

    let mut tracker = LineageTracker::new(matcher);
    match lineage::scan_process_table().await {
        Ok(entries) => {
            let report = tracker.seed(&entries);
            let roots: Vec<String> = report
                .roots
                .iter()
                .map(|(pid, name)| format!("{name}:{pid}"))
                .collect();
            status(&format!(
                "seeded {} running agent(s) [{}], {} processes in lineage",
                report.roots.len(),
                roots.join(", "),
                report.tracked
            ));
        }
        Err(e) => warn(&format!(
            "initial process scan failed, continuing without it: {e:#}"
        )),
    }

    let events = eslogger::select_events().await;
    let (mut child, stdout) = eslogger::spawn(&events)?;
    let (kernel_tx, mut kernel_rx) = mpsc::channel(KERNEL_QUEUE_DEPTH);
    let pump = tokio::spawn(eslogger::pump(stdout, kernel_tx));
    let (ipc_tx, mut ipc_rx) = mpsc::channel(IPC_QUEUE_DEPTH);
    tokio::spawn(ipc::serve(listener, ipc_tx));

    status(&format!(
        "recording to {} (next #{}), MCP socket {} (0666)",
        ledger.path().display(),
        ledger.next_seq(),
        args.socket.display()
    ));
    status(&format!("eslogger events: {}", events.join(" ")));

    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    maintenance.tick().await;

    let (deferred_tx, mut deferred_rx) = mpsc::channel(IPC_QUEUE_DEPTH);
    if let Some(alerter) = &alerter {
        status(&format!(
            "critical events are POSTed to {} (timeout {}s)",
            alerter.host(),
            alert::WEBHOOK_TIMEOUT.as_secs()
        ));
    }
    let mut recorder = Recorder {
        ledger,
        lockfile: lockfile.map(Arc::new),
        alerter,
        deferred_tx,
        tracker,
        include_human: args.include_human,
        socket_path: args.socket.to_string_lossy().into_owned(),
        own_pid: std::process::id(),
        eslogger_pid: child.id(),
        last_global_seq: None,
        gap_events: 0,
        gap_warnings: 0,
        recorded: 0,
    };

    let outcome: Result<()> = loop {
        tokio::select! {
            // MCP context first, so a tool call is known before the kernel
            // events it causes are attributed.
            biased;
            _ = sigint.recv() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
            _ = sighup.recv() => break Ok(()),
            Some(envelope) = ipc_rx.recv() => {
                if let Err(e) = recorder.on_ipc(envelope) {
                    break Err(e);
                }
            }
            event = kernel_rx.recv() => match event {
                Some(ev) => {
                    if let Err(e) = recorder.on_kernel_event(ev) {
                        break Err(e);
                    }
                }
                None => {
                    let exit = child.wait().await.map_or_else(|e| e.to_string(), |s| s.to_string());
                    break Err(anyhow::anyhow!(
                        "eslogger stopped ({exit}); make sure the terminal running sogar has \
                         Full Disk Access (System Settings → Privacy & Security)"
                    ));
                }
            },
            Some(entry) = deferred_rx.recv() => {
                if let Err(e) = recorder.write_audit(entry) {
                    break Err(e);
                }
            }
            _ = maintenance.tick() => {
                if let Err(e) = recorder.maintain() {
                    break Err(e);
                }
            }
        }
    };

    let _ = child.kill().await;
    if outcome.is_ok() {
        // Flush entries still waiting on their socket poll.
        while let Ok(Some(entry)) = tokio::time::timeout(DEFERRED_DRAIN, deferred_rx.recv()).await {
            if let Err(e) = recorder.write_audit(entry) {
                warn(&format!("failed to record a pending entry: {e:#}"));
                break;
            }
        }
    }
    let stats = tokio::time::timeout(Duration::from_secs(2), pump)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let synced = recorder.ledger.sync();

    status(&format!(
        "stopped: {} records written, {} eslogger lines ({} malformed), {} events possibly dropped",
        recorder.recorded, stats.lines, stats.malformed, recorder.gap_events
    ));
    status(&format!("ledger head {}", recorder.ledger.head_hash()));
    if let Some(alerter) = &recorder.alerter {
        if alerter.failures() + alerter.dropped() > 0 {
            warn(&format!(
                "{} webhook alert(s) failed; {} dropped because too many were already in flight",
                alerter.failures(),
                alerter.dropped()
            ));
        }
    }
    outcome.and(synced)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn status(msg: &str) {
    eprintln!("{} {msg}", "sogar".bold());
}

fn warn(msg: &str) {
    eprintln!("{} {msg}", "sogar warning:".yellow().bold());
}

/// Writes one trace line; a closed stdout (e.g. `| head`) must not kill the recorder.
fn emit(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn short_time(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%H:%M:%S%.3f").to_string()
}

fn severity_tag(s: Severity) -> ColoredString {
    match s {
        Severity::Critical => "CRIT".red().bold(),
        Severity::Info => "info".dimmed(),
    }
}

fn actor_tag(actor: &Actor) -> ColoredString {
    match actor {
        Actor::AiAgent {
            agent_name,
            root_pid,
        } => format!("AI:{agent_name}({root_pid})").magenta().bold(),
        Actor::Human => "HUMAN".green(),
    }
}

fn rpc_id_text(id: &Value) -> String {
    id.as_str().map_or_else(|| id.to_string(), str::to_owned)
}

fn mcp_tag(call: &McpToolCall) -> ColoredString {
    format!(
        "[mcp {}::{} #{}]",
        call.server_name,
        call.tool_name,
        rpc_id_text(&call.rpc_id)
    )
    .cyan()
}

fn render_audit(e: &AuditEntry) {
    let mut line = format!(
        "{} {} {}",
        short_time(e.time).dimmed(),
        severity_tag(e.severity),
        actor_tag(&e.actor)
    );
    if let Some(call) = &e.mcp {
        line.push(' ');
        line.push_str(&mcp_tag(call).to_string());
    }
    let kind = match e.access {
        Some(access) => format!("{}({access})", e.event),
        None => e.event.to_owned(),
    };
    let target = match (&e.args, &e.path, &e.destination) {
        (Some(args), _, _) => args.join(" "),
        (None, Some(src), Some(dst)) => format!("{src} → {dst}"),
        (None, Some(path), None) => path.clone(),
        _ => String::new(),
    };
    let target = mcp_proxy::truncate_chars(&target, MAX_TARGET_CHARS);
    let target = match e.severity {
        Severity::Critical => target.red().to_string(),
        Severity::Info => target,
    };
    line.push_str(&format!(
        " {} {}[{}] {target}",
        kind.yellow(),
        basename(&e.executable),
        e.pid
    ));
    for conn in &e.network_connections {
        line.push_str(&format!(" {}", socket_tag(conn)));
    }
    if let Some(server) = &e.mcp_server {
        line.push_str(&format!(" {}", format!("[mcp server {server}]").cyan()));
    }
    if let Some(violation) = &e.policy_violation {
        line.push_str(&format!(" {}", format!("⚠ {violation}").red().bold()));
    }
    emit(&line);
}

fn socket_tag(conn: &SocketConnection) -> ColoredString {
    let remote = conn.remote.as_deref().unwrap_or("*");
    let state = conn.state.map(|s| format!(" {s}")).unwrap_or_default();
    format!(
        "⇄ {} {} → {remote}{state}",
        conn.protocol.as_str(),
        conn.local
    )
    .blue()
}

fn render_mcp(e: &McpEntry) {
    let marker = match (e.event, e.is_error, e.cancelled) {
        ("mcp_call_start", _, _) => "▶ call".cyan().bold(),
        (_, _, true) => "■ cancelled".yellow(),
        (_, Some(true), _) => "■ error".red(),
        _ => "■ done".cyan(),
    };
    let mut line = format!(
        "{} {} {} {marker} {}",
        short_time(e.time).dimmed(),
        severity_tag(e.severity),
        actor_tag(&e.actor),
        mcp_tag(&e.mcp)
    );
    if e.event == "mcp_call_start" {
        if let Some(args) = &e.mcp.arguments_summary {
            line.push(' ');
            line.push_str(&mcp_proxy::truncate_chars(args, MAX_TARGET_CHARS));
        }
    }
    emit(&line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_inspect::Transport;
    use crate::policy::{LockSource, ServerPolicy};
    use std::collections::BTreeMap;

    fn lockfile() -> Lockfile {
        let docs = ServerPolicy {
            allowed_executables: vec!["/usr/bin/git".into()],
            allowed_path_prefixes: vec!["/Users/dev/app/docs/".into()],
            allow_network: false,
        };
        Lockfile {
            version: policy::LOCKFILE_VERSION,
            source: LockSource {
                ledger: String::new(),
                records: 0,
                head_hash: String::new(),
            },
            servers: BTreeMap::from([("docs".to_string(), docs)]),
        }
    }

    fn entry(kind: EventKind, mcp_server: Option<&str>, in_call: bool) -> AuditEntry {
        let ev = KernelEvent {
            time: Utc::now(),
            global_seq_num: None,
            pid: 112,
            ppid: 111,
            original_ppid: 111,
            responsible_pid: 100,
            session_id: 400,
            executable: "/bin/sh".into(),
            signing_id: None,
            kind,
        };
        let call = McpToolCall {
            server_name: "docs".into(),
            tool_name: "search".into(),
            rpc_id: Value::from(7),
            wrapper_pid: 110,
            child_pid: 111,
            arguments_summary: None,
        };
        let attribution = Attribution {
            actor: Actor::AiAgent {
                agent_name: "claude".into(),
                root_pid: 100,
            },
            mcp: in_call.then_some(call),
            mcp_server: mcp_server.map(str::to_owned),
        };
        AuditEntry::new(ev, attribution, Severity::Info)
    }

    fn exec(path: &str) -> EventKind {
        EventKind::Exec {
            target_path: path.into(),
            target_pid: 112,
            args: vec![],
            cwd: None,
        }
    }

    #[test]
    fn baseline_behaviour_stays_informational() {
        let mut e = entry(exec("/usr/bin/git"), Some("docs"), true);
        e.enforce(&lockfile());
        assert_eq!(
            (e.severity, e.policy_violation.as_deref()),
            (Severity::Info, None)
        );

        let mut e = entry(
            EventKind::Open {
                path: "/Users/dev/app/docs/a.md".into(),
                fflag: 1,
            },
            Some("docs"),
            false,
        );
        e.enforce(&lockfile());
        assert_eq!(e.policy_violation, None);
        // Between tool calls the owning server is recorded explicitly.
        assert_eq!(e.mcp_server.as_deref(), Some("docs"));
    }

    #[test]
    fn drift_upgrades_to_critical_with_a_reason() {
        let mut e = entry(exec("/bin/bash"), Some("docs"), true);
        e.enforce(&lockfile());
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(
            e.policy_violation.as_deref(),
            Some("MCP behavioral drift: server 'docs' executed new binary /bin/bash")
        );
        // Within a call, `mcp` already names the server; `mcp_server` is not duplicated.
        assert_eq!(e.mcp_server, None);

        // A socket observed later (after the 40 ms poll) is evaluated again.
        let mut e = entry(exec("/usr/bin/git"), Some("docs"), true);
        e.network_connections.push(SocketConnection {
            protocol: Transport::Tcp,
            fd: 4,
            local: "10.0.0.2:50000".into(),
            remote: Some("1.1.1.1:443".into()),
            state: Some("ESTABLISHED"),
        });
        e.enforce(&lockfile());
        assert!(e
            .policy_violation
            .as_deref()
            .is_some_and(|v| v.contains("1.1.1.1:443")));

        let serialized = serde_json::to_value(&e).expect("json");
        assert_eq!(serialized["severity"], "critical");
        assert!(serialized["policy_violation"].is_string());
    }

    #[test]
    fn events_outside_mcp_servers_are_not_policed() {
        let mut e = entry(exec("/bin/bash"), None, false);
        e.enforce(&lockfile());
        assert_eq!(
            (e.severity, e.policy_violation.as_deref()),
            (Severity::Info, None)
        );
        let serialized = serde_json::to_value(&e).expect("json");
        assert!(
            serialized.get("policy_violation").is_none() && serialized.get("mcp_server").is_none()
        );
    }
}
