//! Behavioral MCP lockfile and rug-pull detection.
//!
//! `sogar lock` learns, from a verified flight record, what each MCP server
//! normally does: which binaries it executes, which directories it touches,
//! and whether it talks to the network. `sogar watch` then flags any
//! MCP-attributed event outside that baseline as critical "behavioral
//! drift" — the signature of a silently updated (`npx`/`uvx`) server that
//! starts reading credentials, spawning shells or phoning home.
//!
//! The lockfile is deterministic (sorted, no timestamps) so it can be
//! reviewed and diffed like any other lockfile.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::eslogger::is_sensitive;
use crate::ledger::{self, VerifiedRecord};

pub const LOCKFILE_VERSION: u32 = 1;
pub const DRIFT_PREFIX: &str = "MCP behavioral drift";

/// Paths shallower than this (e.g. `~/.gitconfig`, `/etc/hosts`) are allowed
/// individually instead of allowing their whole parent directory.
const MIN_PREFIX_DEPTH: usize = 3;

/// Temporary directories whose file names are random by nature.
const TEMP_ROOTS: &[&str] = &["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPolicy {
    pub allowed_executables: Vec<String>,
    /// Directory prefixes ending in `/`, or exact file paths.
    pub allowed_path_prefixes: Vec<String>,
    pub allow_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSource {
    pub ledger: String,
    pub records: u64,
    pub head_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockfile {
    pub version: u32,
    pub source: LockSource,
    pub servers: BTreeMap<String, ServerPolicy>,
}

/// The policy-relevant facts of one MCP-attributed event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation<'a> {
    pub server: &'a str,
    /// Binary executed, for `exec` events.
    pub exec_target: Option<&'a str>,
    /// Files touched, for file events.
    pub paths: Vec<&'a str>,
    /// Non-loopback peers of sockets held by the process.
    pub external_remotes: Vec<&'a str>,
}

/// Whether a socket peer (`ip:port`) is outside this machine.
pub fn is_external(remote: &str) -> bool {
    remote
        .parse::<SocketAddr>()
        .is_ok_and(|addr| !addr.ip().is_loopback() && !addr.ip().is_unspecified())
}

impl<'a> Observation<'a> {
    /// Extracts an observation from a flight-record entry. `None` for
    /// entries not attributed to an MCP server and for tool-call markers.
    pub fn from_entry(entry: &'a Value) -> Option<Self> {
        let server = entry
            .get("mcp")
            .and_then(|m| m.get("server_name"))
            .or_else(|| entry.get("mcp_server"))
            .and_then(Value::as_str)?;
        let event = entry.get("event").and_then(Value::as_str)?;
        if event.starts_with("mcp_call") {
            return None;
        }
        let path = entry.get("path").and_then(Value::as_str);
        let (exec_target, paths) = if event == "exec" {
            (path, Vec::new())
        } else {
            let destination = entry.get("destination").and_then(Value::as_str);
            (None, path.into_iter().chain(destination).collect())
        };
        let external_remotes = entry
            .get("network_connections")
            .and_then(Value::as_array)
            .map(|conns| {
                conns
                    .iter()
                    .filter_map(|c| c.get("remote").and_then(Value::as_str))
                    .filter(|r| is_external(r))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self { server, exec_target, paths, external_remotes })
    }
}

/// The allowlist entry learned from one accessed path. `None` for `/`
/// itself, which must never become an allow-everything prefix.
fn prefix_for(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    let parent = match path.rfind('/') {
        _ if path.is_empty() => return None,
        Some(0) => "/",
        Some(i) => &path[..i],
        None => return Some(path.to_owned()),
    };
    let parent_dir = if parent == "/" { "/".to_owned() } else { format!("{parent}/") };
    let depth = parent.split('/').filter(|c| !c.is_empty()).count();
    Some(if depth >= MIN_PREFIX_DEPTH || TEMP_ROOTS.iter().any(|t| parent_dir.starts_with(t)) {
        parent_dir
    } else {
        path.to_owned()
    })
}

/// Drops entries already covered by a broader directory prefix.
fn minimize(prefixes: BTreeSet<String>) -> Vec<String> {
    let dirs: Vec<&String> = prefixes.iter().filter(|p| p.ends_with('/')).collect();
    prefixes
        .iter()
        .filter(|p| !dirs.iter().any(|d| *d != *p && p.starts_with(d.as_str())))
        .cloned()
        .collect()
}

fn path_allowed(policy: &ServerPolicy, path: &str) -> bool {
    policy.allowed_path_prefixes.iter().any(|allowed| {
        if allowed.ends_with('/') {
            path.starts_with(allowed.as_str()) || allowed.strip_suffix('/') == Some(path)
        } else {
            path == allowed
        }
    })
}

#[derive(Default)]
struct Baseline {
    executables: BTreeSet<String>,
    prefixes: BTreeSet<String>,
    network: bool,
}

/// Summary of what `build` learned and deliberately ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LearnStats {
    pub observations: usize,
    /// Critical or already-flagged events, never used as a baseline.
    pub excluded: usize,
}

impl Lockfile {
    /// Learns a baseline from verified records. Critical events and prior
    /// policy violations are excluded: an attack captured in the ledger must
    /// not become allowed behaviour.
    pub fn build(records: &[VerifiedRecord], source: LockSource) -> (Self, LearnStats) {
        let mut baselines: BTreeMap<String, Baseline> = BTreeMap::new();
        let mut stats = LearnStats::default();
        for record in records {
            let entry = &record.entry;
            // Servers that only ever received calls are still known (with an empty baseline).
            if let Some(server) = entry.get("mcp").and_then(|m| m.get("server_name")).and_then(Value::as_str) {
                baselines.entry(server.to_owned()).or_default();
            }
            let Some(obs) = Observation::from_entry(entry) else {
                continue;
            };
            let critical = entry.get("severity").and_then(Value::as_str) == Some("critical");
            if critical || entry.get("policy_violation").is_some_and(|v| !v.is_null()) {
                stats.excluded += 1;
                continue;
            }
            stats.observations += 1;
            let baseline = baselines.entry(obs.server.to_owned()).or_default();
            if let Some(binary) = obs.exec_target {
                baseline.executables.insert(binary.to_owned());
            }
            let learned = obs.paths.into_iter().filter(|p| !is_sensitive(p)).filter_map(prefix_for);
            baseline.prefixes.extend(learned);
            baseline.network |= !obs.external_remotes.is_empty();
        }
        let servers = baselines
            .into_iter()
            .map(|(name, b)| {
                let policy = ServerPolicy {
                    allowed_executables: b.executables.into_iter().collect(),
                    allowed_path_prefixes: minimize(b.prefixes),
                    allow_network: b.network,
                };
                (name, policy)
            })
            .collect();
        (Self { version: LOCKFILE_VERSION, source, servers }, stats)
    }

    /// `Some("MCP behavioral drift: ...")` when the observation leaves the
    /// server's baseline.
    pub fn evaluate(&self, obs: &Observation) -> Option<String> {
        let Some(policy) = self.servers.get(obs.server) else {
            return Some(format!(
                "{DRIFT_PREFIX}: server '{}' is not in the lockfile",
                obs.server
            ));
        };
        let mut findings = Vec::new();
        if let Some(binary) = obs.exec_target {
            if !policy.allowed_executables.iter().any(|b| b == binary) {
                findings.push(format!("executed new binary {binary}"));
            }
        }
        for path in &obs.paths {
            if !path_allowed(policy, path) {
                findings.push(format!("accessed {path} outside its allowed path prefixes"));
            }
        }
        if !policy.allow_network {
            for remote in &obs.external_remotes {
                findings.push(format!("opened external socket to {remote} (allow_network = false)"));
            }
        }
        (!findings.is_empty()).then(|| {
            format!("{DRIFT_PREFIX}: server '{}' {}", obs.server, findings.join("; "))
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read lockfile {}", path.display()))?;
        let lock: Lockfile = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid sogar lockfile", path.display()))?;
        if lock.version != LOCKFILE_VERSION {
            bail!(
                "{} has lockfile version {}, this sogar understands version {LOCKFILE_VERSION}",
                path.display(),
                lock.version
            );
        }
        Ok(lock)
    }

    /// Writes the lockfile atomically (`0644`).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let mut text = serde_json::to_string_pretty(self).context("failed to serialize lockfile")?;
        text.push('\n');
        let tmp = path.with_extension("json.tmp");
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.with_context(|| {
            format!(
                "failed to write {} (the ~/.sogar directory is root-owned: run `sudo sogar lock`)",
                path.display()
            )
        })
    }
}

/// `~/.sogar/mcp_lock.json` of the invoking user (also under `sudo`).
pub fn default_path() -> Result<PathBuf> {
    Ok(ledger::invoking_user_home()?.join(".sogar").join("mcp_lock.json"))
}

/// A warning when someone other than root could rewrite the lockfile — an
/// agent running as that user could then loosen its own policy.
pub fn ownership_warning(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    let writable_by_others = meta.mode() & 0o022 != 0;
    (meta.uid() != 0 || writable_by_others).then(|| {
        format!(
            "{} is writable by a non-root user; an agent running as that user could loosen it \
             (regenerate it with `sudo sogar lock`)",
            path.display()
        )
    })
}

pub struct LockOutcome {
    pub lockfile: Lockfile,
    pub stats: LearnStats,
}

/// `sogar lock`: learn a baseline from a verified ledger and write it.
pub fn lock(ledger_path: &Path, out: &Path) -> Result<LockOutcome> {
    let (verification, records) = ledger::read_verified(ledger_path)?;
    let head_hash = match verification {
        ledger::Verification::Valid { head_hash, .. } => head_hash,
        ledger::Verification::Tampered { line, reason } => bail!(
            "refusing to learn a baseline from a tampered ledger ({} line {line}: {reason})",
            ledger_path.display()
        ),
    };
    let source = LockSource {
        ledger: ledger_path.display().to_string(),
        records: records.len() as u64,
        head_hash,
    };
    let (lockfile, stats) = Lockfile::build(&records, source);
    lockfile.save(out)?;
    Ok(LockOutcome { lockfile, stats })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mcp(server: &str) -> Value {
        json!({"server_name": server, "tool_name": "t", "rpc_id": 1, "wrapper_pid": 10, "child_pid": 11})
    }

    fn record(seq: u64, entry: Value) -> VerifiedRecord {
        VerifiedRecord { seq, hash: format!("h{seq}"), entry }
    }

    fn source() -> LockSource {
        LockSource { ledger: "/tmp/l.jsonl".into(), records: 0, head_hash: "abc".into() }
    }

    fn baseline_records() -> Vec<VerifiedRecord> {
        vec![
            record(1, json!({"event": "mcp_call_start", "severity": "info", "mcp": mcp("docs")})),
            record(2, json!({"event": "exec", "severity": "info", "mcp": mcp("docs"), "path": "/usr/bin/git"})),
            record(3, json!({"event": "open", "severity": "info", "mcp": mcp("docs"),
                             "path": "/Users/dev/app/docs/intro.md"})),
            record(4, json!({"event": "open", "severity": "info", "mcp_server": "docs",
                             "path": "/Users/dev/app/docs/api/ref.md"})),
            record(5, json!({"event": "write", "severity": "info", "mcp": mcp("docs"), "path": "/tmp/docs-cache-81723"})),
            record(6, json!({"event": "open", "severity": "info", "mcp": mcp("docs"), "path": "/Users/dev/.gitconfig"})),
            record(7, json!({"event": "rename", "severity": "info", "mcp": mcp("docs"),
                             "path": "/Users/dev/app/build/a.tmp", "destination": "/Users/dev/app/build/a.json"})),
            // Critical and already-flagged behaviour is never learned.
            record(8, json!({"event": "exec", "severity": "critical", "mcp": mcp("docs"), "path": "/usr/bin/curl",
                             "network_connections": [{"protocol": "tcp", "fd": 3, "local": "10.0.0.2:1", "remote": "1.1.1.1:443"}]})),
            record(9, json!({"event": "open", "severity": "critical", "mcp": mcp("docs"), "path": "/Users/dev/.ssh/id_rsa"})),
            record(10, json!({"event": "exec", "severity": "info", "mcp": mcp("docs"), "path": "/bin/sh",
                              "policy_violation": "MCP behavioral drift: ..."})),
            // Another server talks to its API.
            record(11, json!({"event": "exec", "severity": "info", "mcp": mcp("web"), "path": "/opt/homebrew/bin/node",
                              "network_connections": [{"protocol": "tcp", "fd": 3, "local": "10.0.0.2:2", "remote": "140.82.112.3:443"},
                                                      {"protocol": "tcp", "fd": 4, "local": "127.0.0.1:3", "remote": "127.0.0.1:8080"}]})),
            // A directory read of `/` (loader noise in older ledgers) must not allow everything.
            record(14, json!({"event": "open", "severity": "info", "mcp": mcp("docs"), "path": "/"})),
            // Human and non-MCP agent events are ignored.
            record(12, json!({"event": "exec", "severity": "info", "actor": {"type": "human"}, "path": "/usr/bin/vim"})),
            record(13, json!({"event": "mcp_call_start", "severity": "info", "mcp": mcp("idle")})),
        ]
    }

    #[test]
    fn learns_a_deterministic_baseline_excluding_critical_behaviour() {
        let (lock, stats) = Lockfile::build(&baseline_records(), source());
        assert_eq!(stats, LearnStats { observations: 8, excluded: 3 });
        assert_eq!(lock.servers.keys().collect::<Vec<_>>(), ["docs", "idle", "web"]);

        let docs = &lock.servers["docs"];
        assert_eq!(docs.allowed_executables, ["/usr/bin/git"]);
        assert_eq!(
            docs.allowed_path_prefixes,
            ["/Users/dev/.gitconfig", "/Users/dev/app/build/", "/Users/dev/app/docs/", "/tmp/"]
        );
        assert!(!docs.allow_network);
        assert!(lock.servers["web"].allow_network);
        assert_eq!(lock.servers["idle"], ServerPolicy::default());

        // Same input, same bytes.
        let (again, _) = Lockfile::build(&baseline_records(), source());
        assert_eq!(
            serde_json::to_string_pretty(&lock).expect("json"),
            serde_json::to_string_pretty(&again).expect("json")
        );
    }

    #[test]
    fn known_behaviour_passes_and_drift_is_described() {
        let (lock, _) = Lockfile::build(&baseline_records(), source());
        let obs = |exec: Option<&'static str>, paths: Vec<&'static str>, remotes: Vec<&'static str>| Observation {
            server: "docs",
            exec_target: exec,
            paths,
            external_remotes: remotes,
        };

        assert_eq!(lock.evaluate(&obs(Some("/usr/bin/git"), vec![], vec![])), None);
        assert_eq!(lock.evaluate(&obs(None, vec!["/Users/dev/app/docs/new/page.md"], vec![])), None);
        assert_eq!(lock.evaluate(&obs(None, vec!["/Users/dev/app/docs"], vec![])), None);
        assert_eq!(lock.evaluate(&obs(None, vec!["/tmp/other-random-name"], vec![])), None);
        assert_eq!(lock.evaluate(&obs(None, vec!["/Users/dev/.gitconfig"], vec![])), None);

        let shell = lock.evaluate(&obs(Some("/bin/sh"), vec![], vec![])).expect("drift");
        assert_eq!(shell, "MCP behavioral drift: server 'docs' executed new binary /bin/sh");

        let creds = lock.evaluate(&obs(None, vec!["/Users/dev/.ssh/known_hosts"], vec![])).expect("drift");
        assert!(creds.contains("accessed /Users/dev/.ssh/known_hosts outside its allowed path prefixes"), "{creds}");
        assert!(lock.evaluate(&obs(None, vec!["/Users/dev/.gitconfig.bak"], vec![])).is_some());
        assert!(lock.evaluate(&obs(None, vec!["/Users/dev/app/docsx/a"], vec![])).is_some());

        let net = lock.evaluate(&obs(Some("/usr/bin/git"), vec![], vec!["1.1.1.1:443"])).expect("drift");
        assert!(net.ends_with("opened external socket to 1.1.1.1:443 (allow_network = false)"), "{net}");

        let unknown = Observation { server: "new-server", ..Default::default() };
        assert_eq!(
            lock.evaluate(&unknown).as_deref(),
            Some("MCP behavioral drift: server 'new-server' is not in the lockfile")
        );
    }

    #[test]
    fn observations_come_from_ledger_entries() {
        let entry = json!({"event": "exec", "mcp": mcp("docs"), "path": "/usr/bin/curl",
            "network_connections": [{"remote": "1.1.1.1:443"}, {"remote": "[::1]:80"}, {"local": "x"}]});
        let obs = Observation::from_entry(&entry).expect("mcp event");
        assert_eq!(obs.exec_target, Some("/usr/bin/curl"));
        assert_eq!(obs.external_remotes, ["1.1.1.1:443"]);
        assert!(Observation::from_entry(&json!({"event": "open", "path": "/x"})).is_none());
        assert!(Observation::from_entry(&json!({"event": "mcp_call_end", "mcp": mcp("docs")})).is_none());
        assert!(!is_external("127.0.0.1:5"));
        assert!(!is_external("garbage"));
        assert!(is_external("[2606:4700::1111]:443"));
    }

    #[test]
    fn prefixes_generalize_to_directories_but_not_near_the_root() {
        let p = |path: &str| prefix_for(path);
        assert_eq!(p("/Users/dev/app/src/main.rs").as_deref(), Some("/Users/dev/app/src/"));
        assert_eq!(p("/Users/dev/notes.md").as_deref(), Some("/Users/dev/notes.md"));
        assert_eq!(p("/etc/hosts").as_deref(), Some("/etc/hosts"));
        assert_eq!(p("/tmp/x").as_deref(), Some("/tmp/"));
        assert_eq!(p("/private/tmp/y").as_deref(), Some("/private/tmp/"));
        assert_eq!(p("/Users").as_deref(), Some("/Users"));
        // Reading the root directory must not allow everything.
        assert_eq!(p("/"), None);
        assert_eq!(p(""), None);
        let set: BTreeSet<String> = ["/a/b/c/", "/a/b/c/d/", "/a/b/c/file", "/x/y/z/"].iter().map(|s| s.to_string()).collect();
        assert_eq!(minimize(set), ["/a/b/c/", "/x/y/z/"]);
    }

    #[test]
    fn lock_round_trips_through_disk_and_refuses_tampered_ledgers() {
        let dir = std::env::temp_dir().join(format!("sogar-policy-{}", std::process::id()));
        let ledger_path = dir.join("flight_record.jsonl");
        let out = dir.join("mcp_lock.json");
        {
            let mut ledger = ledger::Ledger::open(&ledger_path).expect("open");
            for r in baseline_records() {
                ledger.append(&r.entry).expect("append");
            }
        }
        let outcome = lock(&ledger_path, &out).expect("lock");
        assert_eq!(outcome.lockfile.source.records, 14);
        assert_eq!(Lockfile::load(&out).expect("load"), outcome.lockfile);

        let text = fs::read_to_string(&ledger_path).expect("read");
        fs::write(&ledger_path, text.replacen("git", "gat", 1)).expect("write");
        let err = lock(&ledger_path, &out).err().expect("refused").to_string();
        assert!(err.contains("tampered"), "{err}");

        fs::write(&out, r#"{"version": 99, "source": {"ledger": "", "records": 0, "head_hash": ""}, "servers": {}}"#)
            .expect("write");
        assert!(Lockfile::load(&out).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
