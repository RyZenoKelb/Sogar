//! `sogar doctor`: read-only health check of a sogar installation.
//!
//! Every check only inspects state: it never writes to the ledger, the
//! lockfile or MCP configs, and it never sends a message to the daemon (the
//! socket check connects and disconnects, which the daemon treats as an
//! empty session).

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use colored::{ColoredString, Colorize};
use serde_json::Value;

use crate::config_wrap::{self, Mode, Outcome};
use crate::eslogger::ESLOGGER_PATH;
use crate::ledger::{self, Verification};
use crate::policy::{self, Lockfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Info,
    Warn,
    Fail,
}

impl Status {
    fn tag(self) -> ColoredString {
        match self {
            Status::Pass => "[ ok ]".green().bold(),
            Status::Info => "[info]".blue(),
            Status::Warn => "[warn]".yellow().bold(),
            Status::Fail => "[FAIL]".red().bold(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub hint: Option<String>,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

fn owner(uid: u32) -> String {
    if uid == 0 {
        "root".into()
    } else {
        format!("uid {uid}")
    }
}

pub fn check_eslogger(path: &Path) -> Check {
    match fs::metadata(path) {
        Ok(meta) if meta.is_file() && meta.permissions().mode() & 0o111 != 0 => Check::new(
            "eslogger",
            Status::Pass,
            format!("{} present", path.display()),
        ),
        Ok(_) => Check::new(
            "eslogger",
            Status::Fail,
            format!("{} is not an executable file", path.display()),
        ),
        Err(_) => Check::new(
            "eslogger",
            Status::Fail,
            format!("{} not found", path.display()),
        )
        .hint("sogar watch requires macOS 13 or later"),
    }
}

pub fn check_daemon(socket: &Path) -> Check {
    const START: &str = "start the recorder in another terminal: sudo sogar watch";
    let meta = match fs::symlink_metadata(socket) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Check::new(
                "daemon",
                Status::Warn,
                format!("not running (no socket at {})", socket.display()),
            )
            .hint(START);
        }
        Err(e) => {
            return Check::new(
                "daemon",
                Status::Fail,
                format!("cannot stat {}: {e}", socket.display()),
            )
        }
    };
    if !meta.file_type().is_socket() {
        return Check::new(
            "daemon",
            Status::Fail,
            format!("{} exists but is not a socket", socket.display()),
        )
        .hint("remove it, then start `sudo sogar watch`");
    }
    let mode = meta.permissions().mode() & 0o777;
    if let Err(e) = UnixStream::connect(socket) {
        return Check::new(
            "daemon",
            Status::Warn,
            format!(
                "stale socket {}: nothing is accepting ({e})",
                socket.display()
            ),
        )
        .hint(START);
    }
    let detail = format!(
        "{} accepting connections (mode {mode:04o}, owner {})",
        socket.display(),
        owner(meta.uid())
    );
    if mode & 0o666 == 0o666 {
        Check::new("daemon", Status::Pass, detail)
    } else {
        Check::new("daemon", Status::Warn, detail)
            .hint("unprivileged `sogar mcp-wrap` processes cannot report tool calls unless the socket is 0666")
    }
}

pub fn check_ledger(path: &Path) -> Check {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Check::new(
                "ledger",
                Status::Info,
                format!("no flight record yet at {}", path.display()),
            )
            .hint("`sudo sogar watch` creates it");
        }
        Err(e) => {
            return Check::new(
                "ledger",
                Status::Fail,
                format!("cannot stat {}: {e}", path.display()),
            )
        }
    };
    let mode = meta.permissions().mode() & 0o777;
    let ownership = format!("owner {}, mode {mode:04o}", owner(meta.uid()));
    match ledger::verify_file(path) {
        Ok(Verification::Valid { records, head_hash }) => {
            let detail = format!(
                "{}: {records} records, chain intact, head {} ({ownership})",
                path.display(),
                &head_hash[..head_hash.len().min(16)]
            );
            if meta.uid() != 0 || mode & 0o022 != 0 {
                Check::new("ledger", Status::Warn, detail)
                    .hint("the record is writable by a non-root user; an agent running as that user could rewrite it")
            } else {
                Check::new("ledger", Status::Pass, detail)
            }
        }
        Ok(Verification::Tampered { line, reason }) => Check::new(
            "ledger",
            Status::Fail,
            format!("{}: TAMPERED at line {line}: {reason}", path.display()),
        )
        .hint("run `sogar report` to see the trusted prefix, then move the file aside"),
        Err(e) => Check::new(
            "ledger",
            Status::Fail,
            format!("{} ({ownership}): {e:#}", path.display()),
        )
        .hint("it is root-owned and group-readable; check you are in its group, or use sudo"),
    }
}

pub fn check_lockfile(path: &Path) -> Check {
    if !path.exists() {
        return Check::new(
            "lockfile",
            Status::Info,
            format!("no MCP lockfile at {}", path.display()),
        )
        .hint(
            "after a representative session, run `sudo sogar lock` to enable rug-pull detection",
        );
    }
    match Lockfile::load(path) {
        Ok(lock) => {
            let networked = lock.servers.values().filter(|s| s.allow_network).count();
            let detail = format!(
                "{}: {} MCP server profile(s) locked, {networked} allowed network access",
                path.display(),
                lock.servers.len()
            );
            match policy::ownership_warning(path) {
                Some(warning) => Check::new("lockfile", Status::Warn, detail).hint(warning),
                None => Check::new("lockfile", Status::Pass, detail),
            }
        }
        Err(e) => Check::new("lockfile", Status::Fail, format!("{e:#}"))
            .hint("regenerate it with `sudo sogar lock`"),
    }
}

/// How many configured stdio MCP servers already go through `sogar mcp-wrap`.
pub fn check_mcp_configs(files: &[std::path::PathBuf]) -> Check {
    let (mut wrapped, mut unwrapped) = (0usize, 0usize);
    for file in files {
        let Some(mut doc) = fs::read_to_string(file)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        else {
            continue;
        };
        // Unwrapping an in-memory copy classifies each entry; nothing is written.
        for change in config_wrap::rewrite_document(&mut doc, Mode::Unwrap, "") {
            match change.outcome {
                Outcome::Unwrapped => wrapped += 1,
                Outcome::NotWrapped => unwrapped += 1,
                _ => {}
            }
        }
    }
    let total = wrapped + unwrapped;
    let detail = format!(
        "{wrapped} of {total} stdio MCP server(s) wrapped across {} config file(s)",
        files.len()
    );
    if unwrapped > 0 {
        Check::new("mcp configs", Status::Warn, detail)
            .hint("unwrapped servers run without tool-call attribution: run `sogar init`")
    } else if total == 0 {
        Check::new("mcp configs", Status::Info, detail)
    } else {
        Check::new("mcp configs", Status::Pass, detail)
    }
}

pub fn render(checks: &[Check]) -> String {
    let width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    let mut out = format!("{}\n", "sogar doctor".bold());
    for check in checks {
        out.push_str(&format!(
            "  {} {:<width$}  {}\n",
            check.status.tag(),
            check.name,
            check.detail
        ));
        if let Some(hint) = &check.hint {
            out.push_str(&format!(
                "  {:6} {:<width$}  {}\n",
                "",
                "",
                format!("→ {hint}").dimmed()
            ));
        }
    }
    let worst = checks
        .iter()
        .map(|c| c.status)
        .max()
        .unwrap_or(Status::Pass);
    out.push_str(&match worst {
        Status::Fail => format!("\n{}\n", "Problems found.".red().bold()),
        Status::Warn => format!("\n{}\n", "Working, with warnings.".yellow().bold()),
        _ => format!("\n{}\n", "All checks passed.".green().bold()),
    });
    out
}

/// Runs every check; the caller decides the exit code from the statuses.
pub fn run(ledger_path: &Path, socket: &Path) -> Vec<Check> {
    let mut checks = vec![
        check_eslogger(Path::new(ESLOGGER_PATH)),
        check_daemon(socket),
        check_ledger(ledger_path),
    ];
    match policy::default_path() {
        Ok(path) => checks.push(check_lockfile(&path)),
        Err(e) => checks.push(Check::new("lockfile", Status::Warn, format!("{e:#}"))),
    }
    if let (Ok(home), Ok(cwd)) = (ledger::invoking_user_home(), std::env::current_dir()) {
        checks.push(check_mcp_configs(&config_wrap::discover(&home, &cwd)));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            // Short path: sockets are limited to 104 bytes on macOS.
            let dir = PathBuf::from("/tmp").join(format!("sogar-doc-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn eslogger_presence() {
        let dir = TempDir::new();
        assert_eq!(check_eslogger(&dir.0.join("missing")).status, Status::Fail);
        let file = dir.0.join("eslogger");
        fs::write(&file, "").expect("write");
        assert_eq!(check_eslogger(&file).status, Status::Fail, "not executable");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(check_eslogger(&file).status, Status::Pass);
    }

    #[test]
    fn daemon_states() {
        let dir = TempDir::new();
        let sock = dir.0.join("s.sock");
        let missing = check_daemon(&sock);
        assert_eq!(missing.status, Status::Warn);
        assert!(missing
            .hint
            .as_deref()
            .is_some_and(|h| h.contains("sudo sogar watch")));

        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).expect("chmod");
        let restricted = check_daemon(&sock);
        assert_eq!(restricted.status, Status::Warn);
        assert!(
            restricted.detail.contains("mode 0600"),
            "{}",
            restricted.detail
        );

        fs::set_permissions(&sock, fs::Permissions::from_mode(0o666)).expect("chmod");
        assert_eq!(check_daemon(&sock).status, Status::Pass);

        drop(listener); // socket file remains, nobody accepts
        let stale = check_daemon(&sock);
        assert_eq!(stale.status, Status::Warn);
        assert!(stale.detail.contains("stale"), "{}", stale.detail);

        let not_socket = dir.0.join("plain");
        fs::write(&not_socket, "").expect("write");
        assert_eq!(check_daemon(&not_socket).status, Status::Fail);
    }

    #[test]
    fn ledger_states() {
        let dir = TempDir::new();
        let path = dir.0.join("flight_record.jsonl");
        assert_eq!(check_ledger(&path).status, Status::Info);

        {
            let mut ledger = ledger::Ledger::open(&path).expect("open");
            ledger
                .append(&serde_json::json!({"event": "open", "path": "/x"}))
                .expect("append");
        }
        // Owned by the test user, not root: valid but flagged.
        let user_owned = check_ledger(&path);
        assert_eq!(user_owned.status, Status::Warn);
        assert!(
            user_owned.detail.contains("1 records, chain intact"),
            "{}",
            user_owned.detail
        );

        let text = fs::read_to_string(&path).expect("read");
        fs::write(&path, text.replace("/x", "/y")).expect("write");
        let tampered = check_ledger(&path);
        assert_eq!(tampered.status, Status::Fail);
        assert!(
            tampered.detail.contains("TAMPERED at line 1"),
            "{}",
            tampered.detail
        );
    }

    #[test]
    fn lockfile_states() {
        let dir = TempDir::new();
        let path = dir.0.join("mcp_lock.json");
        assert_eq!(check_lockfile(&path).status, Status::Info);
        fs::write(&path, "not json").expect("write");
        assert_eq!(check_lockfile(&path).status, Status::Fail);
        fs::write(
            &path,
            r#"{"version":1,"source":{"ledger":"x","records":1,"head_hash":"h"},
               "servers":{"a":{"allowed_executables":[],"allowed_path_prefixes":[],"allow_network":true},
                          "b":{"allowed_executables":[],"allowed_path_prefixes":[],"allow_network":false}}}"#,
        )
        .expect("write");
        let ok = check_lockfile(&path);
        assert!(
            ok.detail
                .contains("2 MCP server profile(s) locked, 1 allowed network access"),
            "{}",
            ok.detail
        );
        // Written by the test user rather than root.
        assert_eq!(ok.status, Status::Warn);
    }

    #[test]
    fn mcp_config_coverage() {
        let dir = TempDir::new();
        let file = dir.0.join("mcp.json");
        fs::write(
            &file,
            r#"{"mcpServers":{
                "a":{"command":"/usr/local/bin/sogar","args":["mcp-wrap","--name","a","--","npx","x"]},
                "b":{"command":"npx","args":["y"]},
                "c":{"type":"http","url":"https://example.com/mcp"}}}"#,
        )
        .expect("write");
        let before = fs::read_to_string(&file).expect("read");
        let check = check_mcp_configs(std::slice::from_ref(&file));
        assert_eq!(check.status, Status::Warn);
        assert!(
            check
                .detail
                .starts_with("1 of 2 stdio MCP server(s) wrapped"),
            "{}",
            check.detail
        );
        assert_eq!(
            fs::read_to_string(&file).expect("read"),
            before,
            "doctor must not write"
        );
        assert_eq!(check_mcp_configs(&[]).status, Status::Info);
    }

    #[test]
    fn render_summarizes_the_worst_status() {
        colored::control::set_override(false);
        let checks = vec![
            Check::new("eslogger", Status::Pass, "present"),
            Check::new("daemon", Status::Warn, "not running").hint("sudo sogar watch"),
        ];
        let text = render(&checks);
        assert!(text.contains("[ ok ] eslogger  present"), "{text}");
        assert!(text.contains("→ sudo sogar watch"), "{text}");
        assert!(text.contains("Working, with warnings."), "{text}");
        assert!(render(&[Check::new("x", Status::Fail, "bad")]).contains("Problems found."));
    }
}
