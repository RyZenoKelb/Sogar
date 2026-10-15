//! Process lineage tracking, AI agent detection and MCP tool-call correlation.
//!
//! The tracker maps every PID known to descend from an AI agent to an
//! [`AgentLineage`] (agent name, root PID, parent PID). Lineage is inherited
//! through `fork`/`exec`/`ppid`, recovered from the live process table when
//! eslogger events arrive out of order, and seeded from `ps` at startup.
//! MCP servers registered by `sogar mcp-wrap` hang off that tree; kernel
//! events from a server or its descendants are matched to the tool call whose
//! time window contains them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::eslogger::{EventKind, KernelEvent};
use crate::ipc::{rpc_key, IpcMessage};

/// Matches the last path component (or an enclosing `.app` bundle) of known
/// AI agents: `claude`, `Cursor`, `codex`, `windsurf`, `aider`, `goose`.
pub const DEFAULT_AGENT_PATTERN: &str =
    r"(?i)(?:^|/)(claude|cursor|codex|windsurf|aider|goose)(?:\.app/|(?:[ ._-][^/]*)?$)";

/// Agent name used when an MCP host could not be identified.
const UNKNOWN_MCP_CLIENT: &str = "mcp-client";

const MAX_ANCESTRY_DEPTH: usize = 64;
const MAX_CALLS_PER_SERVER: usize = 1024;
/// Ended calls stay matchable this long, so kernel events that eslogger
/// delivers after the response still find their tool call.
const ENDED_CALL_RETENTION_SECS: i64 = 10;
/// Calls without a response (lost cancellation, crashed client) expire.
const OPEN_CALL_MAX_AGE_SECS: i64 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    AiAgent { agent_name: String, root_pid: u32 },
    Human,
}

impl Actor {
    pub fn is_agent(&self) -> bool {
        matches!(self, Actor::AiAgent { .. })
    }
}

impl From<&AgentLineage> for Actor {
    fn from(l: &AgentLineage) -> Self {
        Actor::AiAgent {
            agent_name: l.agent_name.clone(),
            root_pid: l.root_pid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct McpToolCall {
    pub server_name: String,
    pub tool_name: String,
    pub rpc_id: Value,
    pub wrapper_pid: u32,
    pub child_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribution {
    pub actor: Actor,
    /// The tool call executing when the event happened.
    pub mcp: Option<McpToolCall>,
    /// The MCP server the process belongs to, even between tool calls.
    pub mcp_server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLineage {
    pub agent_name: String,
    pub root_pid: u32,
    pub ppid: u32,
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_interpreter(name: &str) -> bool {
    matches!(name, "node" | "bun" | "deno" | "ruby" | "perl") || name.starts_with("python")
}

// ---------------------------------------------------------------------------
// Agent detection
// ---------------------------------------------------------------------------

pub struct AgentMatcher {
    re: Regex,
}

impl AgentMatcher {
    /// `pattern` replaces [`DEFAULT_AGENT_PATTERN`]; capture group 1, if
    /// present, names the agent.
    pub fn new(pattern: Option<&str>) -> Result<Self> {
        let pattern = pattern.unwrap_or(DEFAULT_AGENT_PATTERN);
        let re = Regex::new(pattern)
            .with_context(|| format!("invalid --agent-match regex {pattern:?}"))?;
        Ok(Self { re })
    }

    /// Returns the agent name if this executable/argv is an AI agent. Checks
    /// the executable path, `argv[0]`, and — for interpreters such as `node`
    /// or `python` — the script being run, so `node /opt/homebrew/bin/claude`
    /// is recognised while `cat claude.txt` is not.
    pub fn identify(&self, exe: &str, args: &[String]) -> Option<String> {
        let argv0 = args.first().map(String::as_str).unwrap_or("");
        let mut candidates = vec![exe];
        if !argv0.is_empty() && argv0 != exe {
            candidates.push(argv0);
        }
        if is_interpreter(basename(exe)) || is_interpreter(basename(argv0)) {
            if let Some(script) = args.iter().skip(1).find(|a| !a.starts_with('-')) {
                candidates.push(script);
            }
        }
        candidates
            .into_iter()
            .filter(|c| !c.is_empty())
            .find_map(|c| self.name_in(c))
    }

    fn name_in(&self, text: &str) -> Option<String> {
        let caps = self.re.captures(text)?;
        let m = caps.get(1).or_else(|| caps.get(0))?;
        let name = m.as_str().trim_matches('/').to_lowercase();
        (!name.is_empty()).then_some(name)
    }
}

// ---------------------------------------------------------------------------
// Live process table access
// ---------------------------------------------------------------------------

/// Read-only view of the live process table (stubbed in tests).
pub trait ProcessProbe: Send {
    fn parent_of(&self, pid: u32) -> Option<u32>;
    fn executable_of(&self, pid: u32) -> Option<String>;
    fn is_alive(&self, pid: u32) -> bool;
}

pub struct SystemProbe;

impl ProcessProbe for SystemProbe {
    fn parent_of(&self, pid: u32) -> Option<u32> {
        procinfo::parent_pid(pid)
    }
    fn executable_of(&self, pid: u32) -> Option<String> {
        procinfo::executable_path(pid)
    }
    fn is_alive(&self, pid: u32) -> bool {
        procinfo::is_alive(pid)
    }
}

pub mod procinfo {
    #[cfg(target_os = "macos")]
    pub fn parent_pid(pid: u32) -> Option<u32> {
        let pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: proc_bsdinfo is plain old data; proc_pidinfo writes at most `size` bytes.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        (ret == size).then_some(info.pbi_ppid)
    }

    #[cfg(target_os = "macos")]
    pub fn executable_path(pid: u32) -> Option<String> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is valid for `buf.len()` bytes.
        let ret = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if ret <= 0 {
            return None;
        }
        buf.truncate(ret as usize);
        String::from_utf8(buf).ok()
    }

    #[cfg(not(target_os = "macos"))]
    pub fn parent_pid(_pid: u32) -> Option<u32> {
        None
    }

    #[cfg(not(target_os = "macos"))]
    pub fn executable_path(_pid: u32) -> Option<String> {
        None
    }

    pub fn is_alive(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if pid <= 0 {
            return false;
        }
        // SAFETY: signal 0 performs only the existence/permission check.
        let ret = unsafe { libc::kill(pid, 0) };
        ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

// ---------------------------------------------------------------------------
// Startup process table scan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub args: Vec<String>,
}

/// Snapshot of every running process via `ps -axww -o pid=,ppid=,command=`.
pub async fn scan_process_table() -> Result<Vec<ProcEntry>> {
    let out = tokio::process::Command::new("/bin/ps")
        .args(["-axww", "-o", "pid=,ppid=,command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .context("failed to run /bin/ps")?;
    if !out.status.success() {
        bail!("/bin/ps exited with {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_ps_output(&text)
        .into_iter()
        .map(|(pid, ppid, command)| {
            // argv is space-joined by ps; the exact executable comes from the kernel.
            let args: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            let exe = procinfo::executable_path(pid)
                .or_else(|| args.first().cloned())
                .unwrap_or_default();
            ProcEntry {
                pid,
                ppid,
                exe,
                args,
            }
        })
        .collect())
}

/// Parses `pid ppid command...` lines; the command keeps its inner spacing.
pub fn parse_ps_output(text: &str) -> Vec<(u32, u32, String)> {
    fn field(s: &str) -> Option<(&str, &str)> {
        let s = s.trim_start();
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        (end > 0).then(|| (&s[..end], &s[end..]))
    }
    text.lines()
        .filter_map(|line| {
            let (pid, rest) = field(line)?;
            let (ppid, rest) = field(rest)?;
            Some((
                pid.parse().ok()?,
                ppid.parse().ok()?,
                rest.trim().to_owned(),
            ))
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct SeedReport {
    /// `(root_pid, agent_name)` of every agent found running.
    pub roots: Vec<(u32, String)>,
    /// Processes now tracked (roots and their descendants).
    pub tracked: usize,
}

// ---------------------------------------------------------------------------
// MCP server bookkeeping
// ---------------------------------------------------------------------------

struct CallWindow {
    key: String,
    call: McpToolCall,
    started: DateTime<Utc>,
    ended: Option<DateTime<Utc>>,
}

struct McpServer {
    wrapper_pid: u32,
    server_name: String,
    calls: Vec<CallWindow>,
    exited: Option<DateTime<Utc>>,
}

impl McpServer {
    fn new(wrapper_pid: u32, server_name: &str) -> Self {
        Self {
            wrapper_pid,
            server_name: server_name.to_owned(),
            calls: Vec::new(),
            exited: None,
        }
    }

    /// The most recently started call whose window contains `at`.
    fn call_at(&self, at: DateTime<Utc>) -> Option<McpToolCall> {
        self.calls
            .iter()
            .filter(|c| c.started <= at && c.ended.is_none_or(|end| at <= end))
            .max_by_key(|c| c.started)
            .map(|c| c.call.clone())
    }

    fn end_call(&mut self, key: &str, at: DateTime<Utc>) -> Option<McpToolCall> {
        let window = self
            .calls
            .iter_mut()
            .find(|c| c.key == key && c.ended.is_none())?;
        window.ended = Some(at.max(window.started));
        Some(window.call.clone())
    }

    fn mark_exited(&mut self, at: DateTime<Utc>) {
        self.exited.get_or_insert(at);
        for window in self.calls.iter_mut().filter(|c| c.ended.is_none()) {
            window.ended = Some(at.max(window.started));
        }
    }
}

/// What an accepted IPC message changed.
#[derive(Debug, Clone, PartialEq)]
pub enum IpcEffect {
    ServerStarted {
        server_name: String,
        wrapper_pid: u32,
        child_pid: u32,
    },
    CallStarted(McpToolCall),
    CallEnded {
        call: McpToolCall,
        is_error: bool,
        cancelled: bool,
    },
    ServerExited {
        server_name: String,
        child_pid: u32,
    },
    Ignored,
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

pub struct LineageTracker {
    matcher: AgentMatcher,
    probe: Box<dyn ProcessProbe>,
    procs: HashMap<u32, AgentLineage>,
    servers: HashMap<u32, McpServer>,
}

impl LineageTracker {
    pub fn new(matcher: AgentMatcher) -> Self {
        Self::with_probe(matcher, Box::new(SystemProbe))
    }

    pub fn with_probe(matcher: AgentMatcher, probe: Box<dyn ProcessProbe>) -> Self {
        Self {
            matcher,
            probe,
            procs: HashMap::new(),
            servers: HashMap::new(),
        }
    }

    pub fn actor_of(&self, pid: u32) -> Actor {
        self.procs
            .get(&pid)
            .map(Actor::from)
            .unwrap_or(Actor::Human)
    }

    /// Seeds lineage from a process table snapshot: every outermost agent
    /// becomes a root, and all of its live descendants inherit it.
    pub fn seed(&mut self, entries: &[ProcEntry]) -> SeedReport {
        let ppid_of: HashMap<u32, u32> = entries.iter().map(|e| (e.pid, e.ppid)).collect();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for e in entries {
            if e.pid != e.ppid {
                children.entry(e.ppid).or_default().push(e.pid);
            }
        }
        let agents: HashMap<u32, String> = entries
            .iter()
            .filter_map(|e| self.matcher.identify(&e.exe, &e.args).map(|n| (e.pid, n)))
            .collect();

        let has_agent_ancestor = |pid: u32| {
            let mut cur = pid;
            for _ in 0..MAX_ANCESTRY_DEPTH {
                match ppid_of.get(&cur) {
                    Some(&p) if p > 1 && p != cur => {
                        if agents.contains_key(&p) {
                            return true;
                        }
                        cur = p;
                    }
                    _ => return false,
                }
            }
            false
        };

        let mut roots: Vec<(u32, String)> = agents
            .iter()
            .filter(|(pid, _)| !has_agent_ancestor(**pid))
            .map(|(pid, name)| (*pid, name.clone()))
            .collect();
        roots.sort_unstable();

        let mut visited = HashSet::new();
        for (root, name) in &roots {
            let mut queue = VecDeque::from([*root]);
            while let Some(pid) = queue.pop_front() {
                if !visited.insert(pid) {
                    continue;
                }
                let lineage = AgentLineage {
                    agent_name: name.clone(),
                    root_pid: *root,
                    ppid: ppid_of.get(&pid).copied().unwrap_or(0),
                };
                self.procs.insert(pid, lineage);
                queue.extend(children.get(&pid).into_iter().flatten().copied());
            }
        }

        SeedReport {
            tracked: visited.len(),
            roots,
        }
    }

    /// Updates lineage for one kernel event and attributes it.
    pub fn observe(&mut self, ev: &KernelEvent) -> Attribution {
        let lineage = match &ev.kind {
            EventKind::Exit => {
                if let Some(server) = self.servers.get_mut(&ev.pid) {
                    server.mark_exited(ev.time);
                }
                let mcp_server = self.mcp_server_of(ev.pid);
                let actor = self.procs.remove(&ev.pid).as_ref().map(Actor::from);
                return Attribution {
                    actor: actor.unwrap_or(Actor::Human),
                    mcp: None,
                    mcp_server,
                };
            }
            EventKind::Fork { child_pid } => {
                let parent = self.resolve(ev, None);
                match &parent {
                    Some(l) => {
                        self.procs.insert(
                            *child_pid,
                            AgentLineage {
                                ppid: ev.pid,
                                ..l.clone()
                            },
                        );
                    }
                    // A fresh PID from an untracked parent: drop any stale entry
                    // left by PID reuse, unless a wrapper already registered it.
                    None if !self.is_live_server(*child_pid) => {
                        self.procs.remove(child_pid);
                    }
                    None => {}
                }
                parent
            }
            EventKind::Exec {
                target_path, args, ..
            } => self.resolve(ev, Some((target_path.as_str(), args.as_slice()))),
            _ => self.resolve(ev, None),
        };

        let server = lineage.as_ref().and_then(|_| self.owning_server(ev.pid));
        Attribution {
            actor: lineage.as_ref().map(Actor::from).unwrap_or(Actor::Human),
            mcp: server.and_then(|s| s.call_at(ev.time)),
            mcp_server: server.map(|s| s.server_name.clone()),
        }
    }

    fn is_live_server(&self, pid: u32) -> bool {
        self.servers.get(&pid).is_some_and(|s| s.exited.is_none())
    }

    fn insert(&mut self, pid: u32, lineage: AgentLineage) -> AgentLineage {
        self.procs.insert(pid, lineage.clone());
        lineage
    }

    fn resolve(
        &mut self,
        ev: &KernelEvent,
        exec_image: Option<(&str, &[String])>,
    ) -> Option<AgentLineage> {
        // 1. Already tracked (nested agents keep the outermost root).
        if let Some(l) = self.procs.get(&ev.pid) {
            return Some(l.clone());
        }
        // 2. Parent is tracked.
        if ev.ppid != ev.pid {
            if let Some(parent) = self.procs.get(&ev.ppid) {
                let l = AgentLineage {
                    ppid: ev.ppid,
                    ..parent.clone()
                };
                return Some(self.insert(ev.pid, l));
            }
        }
        // 3. The process itself is an agent: new lineage root.
        let agent = exec_image
            .and_then(|(path, args)| self.matcher.identify(path, args))
            .or_else(|| self.matcher.identify(&ev.executable, &[]));
        if let Some(agent_name) = agent {
            let l = AgentLineage {
                agent_name,
                root_pid: ev.pid,
                ppid: ev.ppid,
            };
            return Some(self.insert(ev.pid, l));
        }
        // 4. True ancestry from the live process table (covers events that
        //    eslogger delivered before their ancestors' exec/fork).
        if let Some(l) = self.adopt_via_ancestry(ev.pid, ev.ppid) {
            return Some(l);
        }
        // 5. XNU's responsible process (e.g. the GUI app that launched it).
        if ev.responsible_pid != 0 && ev.responsible_pid != ev.pid {
            if let Some(resp) = self.procs.get(&ev.responsible_pid) {
                let l = AgentLineage {
                    ppid: ev.ppid,
                    ..resp.clone()
                };
                return Some(self.insert(ev.pid, l));
            }
        }
        None
    }

    /// Walks the real parent chain above `ppid` looking for a tracked process
    /// or a running agent; on success the whole chain is tracked.
    fn adopt_via_ancestry(&mut self, pid: u32, ppid: u32) -> Option<AgentLineage> {
        let mut chain = vec![(pid, ppid)];
        let mut cur = ppid;
        let anchor = loop {
            if cur <= 1 || chain.len() > MAX_ANCESTRY_DEPTH {
                return None;
            }
            if let Some(l) = self.procs.get(&cur) {
                break l.clone();
            }
            let name = self
                .probe
                .executable_of(cur)
                .and_then(|exe| self.matcher.identify(&exe, &[]));
            let parent = self.probe.parent_of(cur);
            if let Some(agent_name) = name {
                let root = AgentLineage {
                    agent_name,
                    root_pid: cur,
                    ppid: parent.unwrap_or(0),
                };
                break self.insert(cur, root);
            }
            let parent = parent?;
            if parent == cur {
                return None;
            }
            chain.push((cur, parent));
            cur = parent;
        };
        for (p, pp) in chain.into_iter().rev() {
            self.procs.insert(
                p,
                AgentLineage {
                    ppid: pp,
                    ..anchor.clone()
                },
            );
        }
        self.procs.get(&pid).cloned()
    }

    /// Lineage of a live process that may not have produced any event yet.
    fn lineage_of_live(&mut self, pid: u32) -> Option<AgentLineage> {
        if let Some(l) = self.procs.get(&pid) {
            return Some(l.clone());
        }
        let parent = self.probe.parent_of(pid);
        let name = self
            .probe
            .executable_of(pid)
            .and_then(|exe| self.matcher.identify(&exe, &[]));
        if let Some(agent_name) = name {
            let l = AgentLineage {
                agent_name,
                root_pid: pid,
                ppid: parent.unwrap_or(0),
            };
            return Some(self.insert(pid, l));
        }
        self.adopt_via_ancestry(pid, parent?)
    }

    /// The MCP server that `pid` is, or descends from.
    fn owning_server(&self, pid: u32) -> Option<&McpServer> {
        let mut cur = pid;
        for _ in 0..MAX_ANCESTRY_DEPTH {
            if let Some(server) = self.servers.get(&cur) {
                return Some(server);
            }
            let next = self.procs.get(&cur)?.ppid;
            if next == cur || next == 0 {
                return None;
            }
            cur = next;
        }
        None
    }

    /// Name of the MCP server owning `pid`, if it is a known server's process tree.
    pub fn mcp_server_of(&self, pid: u32) -> Option<String> {
        self.owning_server(pid).map(|s| s.server_name.clone())
    }

    // -- IPC ---------------------------------------------------------------

    /// Applies a wrapper message. `peer_pid` is the kernel-reported sender;
    /// messages that impersonate another wrapper, or whose sender cannot be
    /// verified, are rejected.
    pub fn apply_ipc(
        &mut self,
        msg: &IpcMessage,
        peer_pid: Option<u32>,
    ) -> Result<IpcEffect, String> {
        match msg {
            IpcMessage::McpServerStart {
                wrapper_pid,
                child_pid,
                server_name,
                ..
            } => {
                self.authorize_wrapper(peer_pid, *wrapper_pid, *child_pid)?;
                self.register_server(*wrapper_pid, *child_pid, server_name);
                Ok(IpcEffect::ServerStarted {
                    server_name: server_name.clone(),
                    wrapper_pid: *wrapper_pid,
                    child_pid: *child_pid,
                })
            }
            IpcMessage::McpCallStart {
                wrapper_pid,
                child_pid,
                server_name,
                rpc_id,
                tool_name,
                arguments_summary,
                timestamp,
            } => {
                self.authorize_wrapper(peer_pid, *wrapper_pid, *child_pid)?;
                let registered = self
                    .servers
                    .get(child_pid)
                    .is_some_and(|s| s.wrapper_pid == *wrapper_pid && s.exited.is_none());
                if !registered {
                    // The daemon may have started after this wrapper.
                    self.register_server(*wrapper_pid, *child_pid, server_name);
                }
                let call = McpToolCall {
                    server_name: server_name.clone(),
                    tool_name: tool_name.clone(),
                    rpc_id: rpc_id.clone(),
                    wrapper_pid: *wrapper_pid,
                    child_pid: *child_pid,
                    arguments_summary: arguments_summary.clone(),
                };
                let Some(server) = self.servers.get_mut(child_pid) else {
                    return Err(format!("MCP server {child_pid} is not registered"));
                };
                if server.calls.len() >= MAX_CALLS_PER_SERVER {
                    server.calls.remove(0);
                }
                server.calls.push(CallWindow {
                    key: rpc_key(rpc_id),
                    call: call.clone(),
                    started: *timestamp,
                    ended: None,
                });
                Ok(IpcEffect::CallStarted(call))
            }
            IpcMessage::McpCallEnd {
                child_pid,
                rpc_id,
                timestamp,
                is_error,
                cancelled,
            } => {
                self.authorize_owner(peer_pid, *child_pid)?;
                let ended = self
                    .servers
                    .get_mut(child_pid)
                    .and_then(|s| s.end_call(&rpc_key(rpc_id), *timestamp));
                Ok(match ended {
                    Some(call) => IpcEffect::CallEnded {
                        call,
                        is_error: *is_error,
                        cancelled: *cancelled,
                    },
                    None => IpcEffect::Ignored,
                })
            }
            IpcMessage::McpServerExit {
                child_pid,
                timestamp,
                ..
            } => {
                self.authorize_owner(peer_pid, *child_pid)?;
                Ok(match self.servers.get_mut(child_pid) {
                    Some(server) => {
                        server.mark_exited(*timestamp);
                        IpcEffect::ServerExited {
                            server_name: server.server_name.clone(),
                            child_pid: *child_pid,
                        }
                    }
                    None => IpcEffect::Ignored,
                })
            }
        }
    }

    fn authorize_wrapper(&self, peer: Option<u32>, wrapper: u32, child: u32) -> Result<(), String> {
        if wrapper == 0 || child == 0 || wrapper == child {
            return Err(format!("invalid pids (wrapper {wrapper}, child {child})"));
        }
        match peer {
            None => return Err("sender pid could not be verified".into()),
            Some(peer) if peer != wrapper => {
                return Err(format!("sender pid {peer} claims to be wrapper {wrapper}"));
            }
            Some(_) => {}
        }
        if let Some(actual) = self.probe.parent_of(child) {
            if actual != wrapper {
                return Err(format!(
                    "pid {child} is a child of {actual}, not of wrapper {wrapper}"
                ));
            }
        }
        Ok(())
    }

    fn authorize_owner(&self, peer: Option<u32>, child: u32) -> Result<(), String> {
        match (peer, self.servers.get(&child)) {
            (None, Some(_)) => Err("sender pid could not be verified".into()),
            (Some(peer), Some(server)) if peer != server.wrapper_pid => Err(format!(
                "sender pid {peer} does not own MCP server {child} (wrapper {})",
                server.wrapper_pid
            )),
            _ => Ok(()),
        }
    }

    fn register_server(&mut self, wrapper_pid: u32, child_pid: u32, server_name: &str) {
        let lineage = match self.lineage_of_live(wrapper_pid) {
            Some(w) => AgentLineage {
                ppid: wrapper_pid,
                ..w
            },
            None => AgentLineage {
                agent_name: UNKNOWN_MCP_CLIENT.to_owned(),
                root_pid: wrapper_pid,
                ppid: wrapper_pid,
            },
        };
        self.procs.insert(child_pid, lineage);
        let keep = self
            .servers
            .get(&child_pid)
            .is_some_and(|s| s.wrapper_pid == wrapper_pid && s.exited.is_none());
        if !keep {
            self.servers
                .insert(child_pid, McpServer::new(wrapper_pid, server_name));
        }
    }

    // -- Housekeeping ------------------------------------------------------

    /// Drops dead processes, expired call windows and exited servers.
    pub fn maintain(&mut self, now: DateTime<Utc>) {
        let probe = &self.probe;
        self.procs.retain(|pid, _| probe.is_alive(*pid));

        let retention = TimeDelta::seconds(ENDED_CALL_RETENTION_SECS);
        let max_open = TimeDelta::seconds(OPEN_CALL_MAX_AGE_SECS);
        self.servers.retain(|child, server| {
            if server.exited.is_none() && !probe.is_alive(*child) {
                server.mark_exited(now);
            }
            server.calls.retain(|c| match c.ended {
                Some(end) => now - end < retention,
                None => now - c.started < max_open,
            });
            server.exited.is_none_or(|t| now - t < retention)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eslogger::parse_line;
    use crate::eslogger::tests::message;
    use serde_json::json;

    #[derive(Default)]
    struct FakeProbe {
        parents: HashMap<u32, u32>,
        exes: HashMap<u32, String>,
        dead: HashSet<u32>,
    }

    impl ProcessProbe for FakeProbe {
        fn parent_of(&self, pid: u32) -> Option<u32> {
            self.parents.get(&pid).copied()
        }
        fn executable_of(&self, pid: u32) -> Option<String> {
            self.exes.get(&pid).cloned()
        }
        fn is_alive(&self, pid: u32) -> bool {
            !self.dead.contains(&pid)
        }
    }

    fn tracker() -> LineageTracker {
        tracker_with(FakeProbe::default())
    }

    fn tracker_with(probe: FakeProbe) -> LineageTracker {
        LineageTracker::with_probe(
            AgentMatcher::new(None).expect("default regex"),
            Box::new(probe),
        )
    }

    fn event(pid: u32, ppid: u32, exe: &str, body: Value) -> KernelEvent {
        parse_line(message(pid, ppid, exe, body).to_string().as_bytes())
            .expect("valid")
            .expect("handled")
    }

    fn exec(pid: u32, ppid: u32, old: &str, new: &str, args: &[&str]) -> KernelEvent {
        event(
            pid,
            ppid,
            old,
            json!({"exec": {"target": {"audit_token": {"pid": pid},
            "executable": {"path": new}}, "args": args}}),
        )
    }

    fn open(pid: u32, ppid: u32, exe: &str, path: &str) -> KernelEvent {
        event(
            pid,
            ppid,
            exe,
            json!({"open": {"file": {"path": path}, "fflag": 1}}),
        )
    }

    fn at(mut ev: KernelEvent, secs: i64) -> KernelEvent {
        ev.time = DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("valid time");
        ev
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("valid time")
    }

    fn claude() -> Actor {
        Actor::AiAgent {
            agent_name: "claude".into(),
            root_pid: 100,
        }
    }

    #[test]
    fn matcher_recognises_agents_without_false_positives() {
        let m = AgentMatcher::new(None).expect("regex");
        let id = |exe: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            m.identify(exe, &args)
        };
        assert_eq!(
            id("/Users/dev/.local/bin/claude", &[]),
            Some("claude".into())
        );
        assert_eq!(
            id("/Applications/Cursor.app/Contents/MacOS/Cursor", &[]),
            Some("cursor".into())
        );
        assert_eq!(
            id("/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)", &[]),
            Some("cursor".into())
        );
        assert_eq!(
            id("/opt/homebrew/bin/codex", &["codex", "exec"]),
            Some("codex".into())
        );
        assert_eq!(
            id(
                "/opt/homebrew/bin/node",
                &["node", "/opt/homebrew/bin/claude"]
            ),
            Some("claude".into())
        );
        assert_eq!(
            id("/usr/bin/python3", &["python3", "-m", "aider"]),
            Some("aider".into())
        );
        assert_eq!(
            id("/Applications/Windsurf.app/Contents/MacOS/Electron", &[]),
            Some("windsurf".into())
        );
        assert_eq!(
            id("/bin/cat", &["cat", "/Users/dev/.claude/settings.json"]),
            None
        );
        assert_eq!(id("/bin/cat", &["cat", "claude.txt"]), None);
        assert_eq!(id("/Users/dev/claude-experiments/run.sh", &[]), None);
        assert_eq!(id("/bin/zsh", &["-zsh"]), None);

        let custom = AgentMatcher::new(Some(r"(?i)/(my-agent)$")).expect("regex");
        assert_eq!(
            custom.identify("/usr/local/bin/my-agent", &[]),
            Some("my-agent".into())
        );
        assert!(AgentMatcher::new(Some("(unclosed")).is_err());
    }

    #[test]
    fn agent_exec_creates_root_and_children_inherit_lineage() {
        let mut t = tracker();
        let root = t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        assert_eq!(root.actor, claude());

        // fork + exec of a shell tool
        t.observe(&event(
            100,
            50,
            "/usr/local/bin/claude",
            json!({"fork": {"child": {"audit_token": {"pid": 101}}}}),
        ));
        let bash = t.observe(&exec(
            101,
            100,
            "/usr/local/bin/claude",
            "/bin/bash",
            &["bash", "-c", "curl x"],
        ));
        assert_eq!(bash.actor, claude());

        // grandchild seen only through ppid
        let curl = t.observe(&open(102, 101, "/usr/bin/curl", "/Users/dev/.netrc"));
        assert_eq!(curl.actor, claude());
        assert_eq!(t.procs[&102].ppid, 101);

        // unrelated human process
        let human = t.observe(&open(300, 299, "/usr/bin/vim", "/Users/dev/notes.md"));
        assert_eq!(human.actor, Actor::Human);
    }

    #[test]
    fn nested_agents_keep_the_outermost_root() {
        let mut t = tracker();
        t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        let codex = t.observe(&exec(
            101,
            100,
            "/bin/bash",
            "/opt/homebrew/bin/codex",
            &["codex"],
        ));
        assert_eq!(codex.actor, claude());
    }

    #[test]
    fn exit_forgets_pid_so_reuse_is_not_misattributed() {
        let mut t = tracker();
        t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        t.observe(&open(101, 100, "/bin/cat", "/Users/dev/a"));
        let gone = t.observe(&event(101, 100, "/bin/cat", json!({"exit": {"stat": 0}})));
        assert_eq!(gone.actor, claude());
        // PID 101 reused by a human process.
        let reused = t.observe(&open(101, 299, "/usr/bin/vim", "/Users/dev/a"));
        assert_eq!(reused.actor, Actor::Human);
    }

    #[test]
    fn fork_from_untracked_parent_clears_stale_entry() {
        let mut t = tracker();
        t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        t.observe(&open(101, 100, "/bin/cat", "/Users/dev/a")); // tracked, but exit never seen
        t.observe(&event(
            299,
            1,
            "/bin/zsh",
            json!({"fork": {"child": {"audit_token": {"pid": 101}}}}),
        ));
        let reused = t.observe(&open(101, 299, "/bin/zsh", "/Users/dev/b"));
        assert_eq!(reused.actor, Actor::Human);
    }

    #[test]
    fn ancestry_walk_recovers_out_of_order_events() {
        // claude(100) -> bash(101) -> curl(102); only curl's event has arrived so far.
        let probe = FakeProbe {
            parents: HashMap::from([(101, 100), (100, 50), (50, 1)]),
            exes: HashMap::from([
                (100, "/usr/local/bin/claude".to_string()),
                (101, "/bin/bash".to_string()),
                (50, "/bin/zsh".to_string()),
            ]),
            ..Default::default()
        };
        let mut t = tracker_with(probe);
        let curl = t.observe(&open(102, 101, "/usr/bin/curl", "/Users/dev/x"));
        assert_eq!(curl.actor, claude());
        assert_eq!(t.procs[&101].root_pid, 100);
    }

    #[test]
    fn responsible_pid_attributes_gui_launched_helpers() {
        let mut t = tracker();
        t.observe(&exec(
            100,
            1,
            "/sbin/launchd",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        let mut ev = open(500, 1, "/usr/bin/helper", "/Users/dev/x");
        ev.responsible_pid = 100;
        assert_eq!(t.observe(&ev).actor, claude());
    }

    #[test]
    fn seeds_running_agents_and_descendants_from_ps() {
        let ps = "\
    1     0 /sbin/launchd
   50     1 -zsh
  100    50 /usr/local/bin/claude --resume
  101   100 /bin/bash -c npm test
  102   101 node /Users/dev/app/node_modules/.bin/jest
  103   100 /opt/homebrew/bin/codex exec
  200     1 /Applications/Cursor.app/Contents/MacOS/Cursor
  201   200 /Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Renderer).app/Contents/MacOS/Cursor Helper (Renderer) --type=renderer
  300    50 vim notes.md
";
        let rows = parse_ps_output(ps);
        assert_eq!(rows.len(), 9);
        assert_eq!(rows[6].2, "/Applications/Cursor.app/Contents/MacOS/Cursor");
        let entries: Vec<ProcEntry> = rows
            .into_iter()
            .map(|(pid, ppid, cmd)| {
                let args: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
                ProcEntry {
                    pid,
                    ppid,
                    exe: args[0].clone(),
                    args,
                }
            })
            .collect();

        let mut t = tracker();
        let report = t.seed(&entries);
        assert_eq!(
            report.roots,
            vec![(100, "claude".into()), (200, "cursor".into())]
        );
        assert_eq!(report.tracked, 6);
        assert_eq!(t.actor_of(102), claude());
        assert_eq!(t.actor_of(103), claude()); // nested codex stays under claude
        assert_eq!(
            t.actor_of(201),
            Actor::AiAgent {
                agent_name: "cursor".into(),
                root_pid: 200
            }
        );
        assert_eq!(t.actor_of(300), Actor::Human);
        assert_eq!(t.actor_of(50), Actor::Human);
    }

    fn start_call(t: &mut LineageTracker, id: Value, tool: &str, secs: i64) {
        let msg = IpcMessage::McpCallStart {
            wrapper_pid: 110,
            child_pid: 111,
            server_name: "fs".into(),
            rpc_id: id,
            tool_name: tool.into(),
            arguments_summary: None,
            timestamp: ts(secs),
        };
        assert!(matches!(
            t.apply_ipc(&msg, Some(110)),
            Ok(IpcEffect::CallStarted(_))
        ));
    }

    fn end_call(t: &mut LineageTracker, id: Value, secs: i64) -> IpcEffect {
        let msg = IpcMessage::McpCallEnd {
            child_pid: 111,
            rpc_id: id,
            timestamp: ts(secs),
            is_error: false,
            cancelled: false,
        };
        t.apply_ipc(&msg, Some(110)).expect("authorized")
    }

    /// claude(100) -> sogar mcp-wrap(110) -> MCP server(111)
    fn tracker_with_mcp_server() -> LineageTracker {
        let mut t = tracker();
        t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        t.observe(&exec(
            110,
            100,
            "/usr/local/bin/claude",
            "/usr/local/bin/sogar",
            &["sogar", "mcp-wrap"],
        ));
        let start = IpcMessage::McpServerStart {
            wrapper_pid: 110,
            child_pid: 111,
            server_name: "fs".into(),
            timestamp: ts(0),
        };
        assert!(matches!(
            t.apply_ipc(&start, Some(110)),
            Ok(IpcEffect::ServerStarted { .. })
        ));
        t
    }

    #[test]
    fn mcp_descendants_are_tagged_with_the_active_tool_call() {
        let mut t = tracker_with_mcp_server();
        start_call(&mut t, json!(7), "read_file", 10);

        // The server itself and a grandchild both inherit the call.
        let direct = t.observe(&at(
            open(111, 110, "/opt/homebrew/bin/node", "/Users/dev/.ssh/id_rsa"),
            11,
        ));
        assert_eq!(direct.actor, claude());
        assert_eq!(
            direct.mcp.as_ref().map(|c| c.tool_name.as_str()),
            Some("read_file")
        );

        t.observe(&at(
            exec(
                112,
                111,
                "/opt/homebrew/bin/node",
                "/bin/sh",
                &["sh", "-c", "cat x"],
            ),
            12,
        ));
        let grandchild = t.observe(&at(open(113, 112, "/bin/cat", "/Users/dev/x"), 12));
        let call = grandchild.mcp.expect("call attached");
        assert_eq!(
            (call.server_name.as_str(), call.rpc_id.clone()),
            ("fs", json!(7))
        );

        // Late kernel event still inside the window; event after the end is not.
        assert!(matches!(
            end_call(&mut t, json!(7), 20),
            IpcEffect::CallEnded { .. }
        ));
        assert!(t
            .observe(&at(
                open(111, 110, "/opt/homebrew/bin/node", "/Users/dev/y"),
                19
            ))
            .mcp
            .is_some());
        assert!(t
            .observe(&at(
                open(111, 110, "/opt/homebrew/bin/node", "/Users/dev/y"),
                21
            ))
            .mcp
            .is_none());
        // Before the call started: no tool call, but still the server's own activity.
        let before = t.observe(&at(
            open(111, 110, "/opt/homebrew/bin/node", "/Users/dev/y"),
            5,
        ));
        assert!(before.mcp.is_none());
        assert_eq!(before.mcp_server.as_deref(), Some("fs"));
        assert_eq!(t.mcp_server_of(113).as_deref(), Some("fs"));
        assert_eq!(t.mcp_server_of(100), None);
    }

    #[test]
    fn concurrent_calls_pick_the_most_recent_and_unknown_ends_are_ignored() {
        let mut t = tracker_with_mcp_server();
        start_call(&mut t, json!("a"), "search", 10);
        start_call(&mut t, json!("b"), "fetch", 12);
        let ev = t.observe(&at(
            open(111, 110, "/opt/homebrew/bin/node", "/Users/dev/z"),
            13,
        ));
        assert_eq!(ev.mcp.map(|c| c.tool_name), Some("fetch".into()));
        assert_eq!(end_call(&mut t, json!(99), 14), IpcEffect::Ignored);
    }

    #[test]
    fn human_processes_never_get_mcp_context() {
        let mut t = tracker_with_mcp_server();
        start_call(&mut t, json!(1), "read_file", 10);
        let human = t.observe(&at(open(300, 299, "/usr/bin/vim", "/Users/dev/z"), 11));
        assert_eq!(
            human,
            Attribution {
                actor: Actor::Human,
                mcp: None,
                mcp_server: None
            }
        );
    }

    #[test]
    fn rejects_impersonated_wrappers() {
        let mut t = tracker_with_mcp_server();
        let forged = IpcMessage::McpServerStart {
            wrapper_pid: 110,
            child_pid: 300,
            server_name: "evil".into(),
            timestamp: ts(0),
        };
        assert!(t.apply_ipc(&forged, Some(666)).is_err());
        let forged_end = IpcMessage::McpServerExit {
            wrapper_pid: 110,
            child_pid: 111,
            timestamp: ts(1),
            exit_code: None,
        };
        assert!(t.apply_ipc(&forged_end, Some(666)).is_err());
        // Senders whose PID the kernel could not report are not trusted.
        assert!(t.apply_ipc(&forged, None).is_err());
        assert!(t.apply_ipc(&forged_end, None).is_err());

        // A wrapper cannot claim a process that is not its child.
        let probe = FakeProbe {
            parents: HashMap::from([(300, 299)]),
            ..Default::default()
        };
        let mut t = tracker_with(probe);
        let claim = IpcMessage::McpServerStart {
            wrapper_pid: 110,
            child_pid: 300,
            server_name: "evil".into(),
            timestamp: ts(0),
        };
        assert!(t.apply_ipc(&claim, Some(110)).is_err());
        assert_eq!(t.actor_of(300), Actor::Human);
    }

    #[test]
    fn registration_before_wrapper_events_resolves_host_agent() {
        // IPC beat eslogger: neither claude's nor the wrapper's exec was seen yet.
        let probe = FakeProbe {
            parents: HashMap::from([(111, 110), (110, 100), (100, 50)]),
            exes: HashMap::from([
                (110, "/usr/local/bin/sogar".to_string()),
                (100, "/usr/local/bin/claude".to_string()),
            ]),
            ..Default::default()
        };
        let mut t = tracker_with(probe);
        let start = IpcMessage::McpServerStart {
            wrapper_pid: 110,
            child_pid: 111,
            server_name: "fs".into(),
            timestamp: ts(0),
        };
        t.apply_ipc(&start, Some(110)).expect("authorized");
        assert_eq!(t.actor_of(111), claude());
    }

    #[test]
    fn maintenance_prunes_dead_processes_and_expired_calls() {
        let probe = FakeProbe {
            dead: HashSet::from([101]),
            ..Default::default()
        };
        let mut t = tracker_with(probe);
        t.observe(&exec(
            100,
            50,
            "/bin/zsh",
            "/usr/local/bin/claude",
            &["claude"],
        ));
        t.observe(&open(101, 100, "/bin/cat", "/Users/dev/a"));
        t.observe(&exec(
            110,
            100,
            "/usr/local/bin/claude",
            "/usr/local/bin/sogar",
            &["sogar"],
        ));
        let start = IpcMessage::McpServerStart {
            wrapper_pid: 110,
            child_pid: 111,
            server_name: "fs".into(),
            timestamp: ts(0),
        };
        t.apply_ipc(&start, Some(110)).expect("ok");
        start_call(&mut t, json!(1), "x", 1);
        end_call(&mut t, json!(1), 2);

        t.maintain(ts(5));
        assert!(!t.procs.contains_key(&101));
        assert_eq!(t.servers[&111].calls.len(), 1);
        t.maintain(ts(60));
        assert!(t.servers[&111].calls.is_empty());

        let exit = IpcMessage::McpServerExit {
            wrapper_pid: 110,
            child_pid: 111,
            timestamp: ts(61),
            exit_code: Some(0),
        };
        assert!(matches!(
            t.apply_ipc(&exit, Some(110)),
            Ok(IpcEffect::ServerExited { .. })
        ));
        t.maintain(ts(100));
        assert!(t.servers.is_empty());
    }

    #[test]
    fn system_probe_sees_this_process() {
        let me = std::process::id();
        assert!(procinfo::is_alive(me));
        if cfg!(target_os = "macos") {
            assert!(procinfo::parent_pid(me).is_some());
            assert!(procinfo::executable_path(me).is_some());
        }
    }
}
