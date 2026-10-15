//! `sogar init` / `sogar unwrap`: route every configured stdio MCP server
//! through `sogar mcp-wrap`, and back.
//!
//! Wrapping rewrites only `command` and `args` of each `mcpServers` entry:
//! `{"command": "<sogar>", "args": ["mcp-wrap", "--name", "<key>", "--", <orig command>, <orig args>...]}`.
//! Unwrapping strips that prefix from the *current* entry, so edits made
//! after wrapping (extra args, env, ...) survive. Key order and all other
//! fields are preserved.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use colored::{ColoredString, Colorize};
use serde_json::{Map, Value};

use crate::ledger;
use crate::lineage::basename;

const BACKUP_SUFFIX: &str = ".sogar.bak";
const WRAP_SUBCOMMAND: &str = "mcp-wrap";
const MAX_COMMAND_CHARS: usize = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wrap,
    Unwrap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Wrapped,
    AlreadyWrapped,
    Unwrapped,
    NotWrapped,
    Skipped(String),
}

impl Outcome {
    fn changed(&self) -> bool {
        matches!(self, Outcome::Wrapped | Outcome::Unwrapped)
    }

    fn label(&self) -> String {
        match self {
            Outcome::Wrapped => "wrapped".into(),
            Outcome::AlreadyWrapped => "already wrapped".into(),
            Outcome::Unwrapped => "unwrapped".into(),
            Outcome::NotWrapped => "not wrapped".into(),
            Outcome::Skipped(why) => format!("skipped: {why}"),
        }
    }

    fn paint(&self, padded: String) -> ColoredString {
        match self {
            Outcome::Wrapped | Outcome::Unwrapped => padded.green().bold(),
            Outcome::AlreadyWrapped | Outcome::NotWrapped => padded.dimmed(),
            Outcome::Skipped(_) => padded.yellow(),
        }
    }
}

/// One `mcpServers` entry and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChange {
    /// Server key, suffixed with `@ <project>` for project-scoped entries.
    pub server: String,
    pub outcome: Outcome,
    /// The entry's command line after the change.
    pub command: String,
}

// ---------------------------------------------------------------------------
// Document rewriting (pure)
// ---------------------------------------------------------------------------

fn string_args(server: &Map<String, Value>) -> Option<Vec<String>> {
    match server.get("args") {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|a| a.as_str().map(str::to_owned)).collect(),
        Some(_) => None,
    }
}

fn is_wrapped(server: &Map<String, Value>) -> bool {
    let command = server.get("command").and_then(Value::as_str).unwrap_or("");
    let first_arg = server
        .get("args")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str);
    basename(command) == "sogar" && first_arg == Some(WRAP_SUBCOMMAND)
}

fn command_line(server: &Map<String, Value>) -> String {
    let command = server.get("command").and_then(Value::as_str).unwrap_or("");
    let mut parts = vec![basename(command).to_owned()];
    parts.extend(string_args(server).unwrap_or_default());
    parts.join(" ")
}

fn wrap_server(server: &mut Map<String, Value>, name: &str, sogar: &str) -> Outcome {
    let Some(command) = server.get("command").and_then(Value::as_str).map(str::to_owned) else {
        return Outcome::Skipped(if server.contains_key("url") {
            "remote server (url)".into()
        } else {
            "no command".into()
        });
    };
    if is_wrapped(server) {
        return Outcome::AlreadyWrapped;
    }
    let Some(original_args) = string_args(server) else {
        return Outcome::Skipped("args is not a list of strings".into());
    };
    let mut args: Vec<Value> = [WRAP_SUBCOMMAND, "--name", name, "--", command.as_str()]
        .into_iter()
        .map(Value::from)
        .collect();
    args.extend(original_args.into_iter().map(Value::from));
    server.insert("command".into(), Value::from(sogar));
    server.insert("args".into(), Value::Array(args));
    Outcome::Wrapped
}

fn unwrap_server(server: &mut Map<String, Value>) -> Outcome {
    if server.get("command").and_then(Value::as_str).is_none() {
        return Outcome::Skipped("no command".into());
    }
    if !is_wrapped(server) {
        return Outcome::NotWrapped;
    }
    let Some(args) = string_args(server) else {
        return Outcome::Skipped("args is not a list of strings".into());
    };
    let Some(separator) = args.iter().position(|a| a == "--") else {
        return Outcome::Skipped("wrapped args have no `--`".into());
    };
    let Some((command, rest)) = args[separator + 1..].split_first() else {
        return Outcome::Skipped("no original command after `--`".into());
    };
    server.insert("command".into(), Value::from(command.as_str()));
    server.insert(
        "args".into(),
        Value::Array(rest.iter().map(|a| Value::from(a.as_str())).collect()),
    );
    Outcome::Unwrapped
}

fn rewrite_servers(
    servers: &mut Map<String, Value>,
    scope: Option<&str>,
    mode: Mode,
    sogar: &str,
    changes: &mut Vec<ServerChange>,
) {
    for (name, entry) in servers.iter_mut() {
        let label = match scope {
            Some(project) => format!("{name} @ {project}"),
            None => name.clone(),
        };
        let Some(server) = entry.as_object_mut() else {
            changes.push(ServerChange {
                server: label,
                outcome: Outcome::Skipped("entry is not an object".into()),
                command: String::new(),
            });
            continue;
        };
        let outcome = match mode {
            Mode::Wrap => wrap_server(server, name, sogar),
            Mode::Unwrap => unwrap_server(server),
        };
        changes.push(ServerChange {
            server: label,
            outcome,
            command: command_line(server),
        });
    }
}

/// Rewrites every `mcpServers` map in a config document: the top-level one
/// and, for `~/.claude.json`, each `projects.<path>.mcpServers`.
pub fn rewrite_document(doc: &mut Value, mode: Mode, sogar: &str) -> Vec<ServerChange> {
    let mut changes = Vec::new();
    if let Some(servers) = doc.get_mut("mcpServers").and_then(Value::as_object_mut) {
        rewrite_servers(servers, None, mode, sogar, &mut changes);
    }
    if let Some(projects) = doc.get_mut("projects").and_then(Value::as_object_mut) {
        for (project, config) in projects.iter_mut() {
            if let Some(servers) = config.get_mut("mcpServers").and_then(Value::as_object_mut) {
                rewrite_servers(servers, Some(project), mode, sogar, &mut changes);
            }
        }
    }
    changes
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// MCP configuration files that exist, without duplicates (e.g. when the
/// current directory is the home directory).
pub fn discover(home: &Path, cwd: &Path) -> Vec<PathBuf> {
    let candidates = [
        home.join(".claude.json"),
        home.join(".cursor").join("mcp.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        cwd.join(".mcp.json"),
        cwd.join(".cursor").join("mcp.json"),
    ];
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|p| p.is_file())
        .filter(|p| seen.insert(fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .collect()
}

pub struct FileReport {
    pub path: PathBuf,
    pub changes: Vec<ServerChange>,
    pub error: Option<String>,
    /// Backup created by this run.
    pub backup: Option<PathBuf>,
    pub written: bool,
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Replaces the file's contents atomically, keeping its permissions. A
/// symlinked config (e.g. from a dotfiles repo) is updated at its target.
fn write_atomically(path: &Path, contents: &str) -> Result<()> {
    let target = fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))?;
    let permissions = fs::metadata(&target)
        .with_context(|| format!("failed to stat {}", target.display()))?
        .permissions();
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = target.with_file_name(format!(".{file_name}.sogar.tmp"));
    let result = (|| -> Result<()> {
        let mut file = File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&tmp, permissions)?;
        fs::rename(&tmp, &target)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("failed to write {}", target.display()))
}

/// Rewrites one config file. Wrapping keeps the pre-sogar original in
/// `<file>.sogar.bak` (an existing backup is never overwritten).
pub fn process_file(path: &Path, mode: Mode, sogar: &str, dry_run: bool) -> FileReport {
    let mut report = FileReport {
        path: path.to_path_buf(),
        changes: Vec::new(),
        error: None,
        backup: None,
        written: false,
    };
    let result = (|| -> Result<()> {
        let text = fs::read_to_string(path).context("unreadable")?;
        let mut doc: Value = serde_json::from_str(&text).context("invalid JSON")?;
        report.changes = rewrite_document(&mut doc, mode, sogar);
        if dry_run || !report.changes.iter().any(|c| c.outcome.changed()) {
            return Ok(());
        }
        if mode == Mode::Wrap {
            let backup = backup_path(path);
            if !backup.exists() {
                fs::copy(path, &backup)
                    .with_context(|| format!("failed to back up to {}", backup.display()))?;
                report.backup = Some(backup);
            }
        }
        let mut contents = serde_json::to_string_pretty(&doc).context("failed to serialize")?;
        if text.ends_with('\n') {
            contents.push('\n');
        }
        write_atomically(path, &contents)?;
        report.written = true;
        Ok(())
    })();
    if let Err(e) = result {
        report.error = Some(format!("{e:#}"));
    }
    report
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

fn display_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
}

fn truncate(text: &str, max: usize) -> String {
    crate::mcp_proxy::truncate_chars(text, max)
}

struct Row {
    file: String,
    server: String,
    outcome: Outcome,
    command: String,
}

/// Renders the summary table for `sogar init` / `sogar unwrap`.
pub fn render_summary(reports: &[FileReport], home: &Path, mode: Mode, dry_run: bool) -> String {
    let mut rows: Vec<Row> = Vec::new();
    for report in reports {
        let file = display_path(&report.path, home);
        let row = |server: &str, outcome: Outcome, command: String| Row {
            file: file.clone(),
            server: server.to_owned(),
            outcome,
            command,
        };
        if let Some(error) = &report.error {
            rows.push(row("-", Outcome::Skipped(error.clone()), String::new()));
        }
        for change in &report.changes {
            rows.push(row(
                &change.server,
                change.outcome.clone(),
                truncate(&change.command, MAX_COMMAND_CHARS),
            ));
        }
        if report.error.is_none() && report.changes.is_empty() {
            rows.push(row("-", Outcome::Skipped("no stdio MCP servers".into()), String::new()));
        }
    }

    let width = |cell: fn(&Row) -> usize, header: &str| {
        rows.iter().map(cell).chain([header.chars().count()]).max().unwrap_or(0)
    };
    let w_file = width(|r| r.file.chars().count(), "FILE");
    let w_server = width(|r| r.server.chars().count(), "SERVER");
    let w_result = width(|r| r.outcome.label().chars().count(), "RESULT");

    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        format!("{:<w_file$}  {:<w_server$}  {:<w_result$}  COMMAND", "FILE", "SERVER", "RESULT").bold()
    ));
    for Row { file, server, outcome, command } in &rows {
        let result = outcome.paint(format!("{:<w_result$}", outcome.label()));
        out.push_str(&format!("{file:<w_file$}  {server:<w_server$}  {result}  {command}\n"));
    }

    let changed = rows.iter().filter(|r| r.outcome.changed()).count();
    let verb = match mode {
        Mode::Wrap => "wrapped",
        Mode::Unwrap => "unwrapped",
    };
    out.push('\n');
    if dry_run {
        out.push_str(&format!("Dry run: {changed} server(s) would be {verb}; no files were changed.\n"));
        return out;
    }
    for report in reports {
        if let Some(backup) = &report.backup {
            out.push_str(&format!("Backed up original to {}\n", display_path(backup, home)));
        }
    }
    let files = reports.iter().filter(|r| r.written).count();
    out.push_str(&format!("{changed} server(s) {verb} in {files} file(s)."));
    if changed > 0 {
        out.push_str(" Restart Claude Code, Cursor and Claude Desktop to apply.");
    }
    out.push('\n');
    out
}

pub fn run(mode: Mode, dry_run: bool) -> Result<()> {
    if ledger::is_root() {
        bail!("run `sogar init`/`sogar unwrap` as your normal user, not with sudo: they edit your own MCP configs");
    }
    let home = ledger::invoking_user_home()?;
    let cwd = std::env::current_dir().context("cannot determine the current directory")?;
    let exe = std::env::current_exe().context("cannot locate the sogar binary")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    let sogar = exe
        .to_str()
        .context("the sogar binary path is not valid UTF-8")?
        .to_owned();

    let files = discover(&home, &cwd);
    if files.is_empty() {
        println!(
            "No MCP configuration files found (looked for ~/.claude.json, ~/.cursor/mcp.json, \
             Claude Desktop's claude_desktop_config.json, and .mcp.json / .cursor/mcp.json in {}).",
            cwd.display()
        );
        return Ok(());
    }

    if mode == Mode::Wrap {
        println!("Wrapping MCP servers with {}", sogar.bold());
        if sogar.contains("/target/debug/") || sogar.contains("/target/release/") {
            println!(
                "{} sogar is running from a cargo build directory; wrapped servers stop working if it \
                 is rebuilt elsewhere or deleted. Consider `cargo install --path .` first.",
                "note:".yellow().bold()
            );
        }
        println!();
    }

    let reports: Vec<FileReport> = files
        .iter()
        .map(|path| process_file(path, mode, &sogar, dry_run))
        .collect();
    print!("{}", render_summary(&reports, &home, mode, dry_run));
    if reports.iter().any(|r| r.error.is_some()) {
        bail!("some configuration files could not be processed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SOGAR: &str = "/usr/local/bin/sogar";

    fn sample() -> Value {
        json!({
            "numStartups": 12,
            "mcpServers": {
                "github": {"type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                           "env": {"GITHUB_TOKEN": "x"}},
                "remote": {"type": "http", "url": "https://mcp.example.com"},
                "bare": {"command": "/opt/mcp/server"}
            },
            "projects": {
                "/Users/dev/app": {
                    "allowedTools": [],
                    "mcpServers": {"db": {"command": "uvx", "args": ["mcp-sqlite", "app.db"]}}
                }
            }
        })
    }

    #[test]
    fn wraps_stdio_servers_and_preserves_everything_else() {
        let mut doc = sample();
        let changes = rewrite_document(&mut doc, Mode::Wrap, SOGAR);
        let outcomes: Vec<(&str, &Outcome)> = changes.iter().map(|c| (c.server.as_str(), &c.outcome)).collect();
        assert_eq!(
            outcomes,
            vec![
                ("github", &Outcome::Wrapped),
                ("remote", &Outcome::Skipped("remote server (url)".into())),
                ("bare", &Outcome::Wrapped),
                ("db @ /Users/dev/app", &Outcome::Wrapped),
            ]
        );
        assert_eq!(
            doc["mcpServers"]["github"],
            json!({"type": "stdio", "command": SOGAR,
                   "args": ["mcp-wrap", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
                   "env": {"GITHUB_TOKEN": "x"}})
        );
        assert_eq!(doc["mcpServers"]["bare"]["args"], json!(["mcp-wrap", "--name", "bare", "--", "/opt/mcp/server"]));
        assert_eq!(doc["projects"]["/Users/dev/app"]["mcpServers"]["db"]["command"], SOGAR);
        assert_eq!(doc["mcpServers"]["remote"], sample()["mcpServers"]["remote"]);
        assert_eq!(doc["numStartups"], 12);
        assert_eq!(changes[0].command, "sogar mcp-wrap --name github -- npx -y @modelcontextprotocol/server-github");

        // Field order inside entries is untouched.
        let keys: Vec<&String> = doc["mcpServers"]["github"].as_object().expect("object").keys().collect();
        assert_eq!(keys, ["type", "command", "args", "env"]);

        // Idempotent.
        let again = rewrite_document(&mut doc, Mode::Wrap, SOGAR);
        assert!(again.iter().all(|c| !c.outcome.changed()));
        assert_eq!(again[0].outcome, Outcome::AlreadyWrapped);
    }

    #[test]
    fn unwrap_restores_the_original_entries() {
        let mut doc = sample();
        rewrite_document(&mut doc, Mode::Wrap, SOGAR);
        let changes = rewrite_document(&mut doc, Mode::Unwrap, SOGAR);
        assert_eq!(changes[0].outcome, Outcome::Unwrapped);
        assert_eq!(doc["mcpServers"]["github"], sample()["mcpServers"]["github"]);
        assert_eq!(doc["projects"], sample()["projects"]);
        // An entry that had no `args` comes back with an empty list.
        assert_eq!(doc["mcpServers"]["bare"], json!({"command": "/opt/mcp/server", "args": []}));
        assert_eq!(
            rewrite_document(&mut doc, Mode::Unwrap, SOGAR)[0].outcome,
            Outcome::NotWrapped
        );
    }

    #[test]
    fn unwrap_preserves_edits_made_after_wrapping() {
        let mut doc = sample();
        rewrite_document(&mut doc, Mode::Wrap, SOGAR);
        let github = doc["mcpServers"]["github"].as_object_mut().expect("object");
        // The user appended an argument, changed env, and pointed the wrapper at another socket.
        let args = github.get_mut("args").and_then(Value::as_array_mut).expect("args");
        args.push(json!("--read-only"));
        args.insert(3, json!("--socket"));
        args.insert(4, json!("/tmp/other.sock"));
        github.insert("env".into(), json!({"GITHUB_TOKEN": "y"}));

        rewrite_document(&mut doc, Mode::Unwrap, SOGAR);
        assert_eq!(
            doc["mcpServers"]["github"],
            json!({"type": "stdio", "command": "npx",
                   "args": ["-y", "@modelcontextprotocol/server-github", "--read-only"],
                   "env": {"GITHUB_TOKEN": "y"}})
        );
    }

    #[test]
    fn recognises_wrappers_from_other_install_paths_and_skips_malformed_entries() {
        let mut doc = json!({"mcpServers": {
            "moved": {"command": "/opt/old/sogar", "args": ["mcp-wrap", "--name", "moved", "--", "node", "s.js"]},
            "broken": {"command": "sogar", "args": ["mcp-wrap", "--name", "broken"]},
            "weird": {"command": "x", "args": "not-a-list"},
            "scalar": 5
        }});
        let wrap: Vec<Outcome> = rewrite_document(&mut doc.clone(), Mode::Wrap, SOGAR).into_iter().map(|c| c.outcome).collect();
        assert_eq!(wrap[0], Outcome::AlreadyWrapped);
        assert!(matches!(&wrap[2], Outcome::Skipped(why) if why.contains("args")));
        assert!(matches!(&wrap[3], Outcome::Skipped(_)));

        let unwrap: Vec<Outcome> = rewrite_document(&mut doc, Mode::Unwrap, SOGAR).into_iter().map(|c| c.outcome).collect();
        assert_eq!(unwrap[0], Outcome::Unwrapped);
        assert!(matches!(&unwrap[1], Outcome::Skipped(why) if why.contains("--")));
        assert_eq!(doc["mcpServers"]["moved"], json!({"command": "node", "args": ["s.js"]}));
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("sogar-cfg-{}-{n}", std::process::id()));
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
    fn files_are_backed_up_rewritten_atomically_and_dry_runs_change_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new();
        let path = dir.0.join(".mcp.json");
        let original = format!("{}\n", serde_json::to_string_pretty(&sample()).expect("json"));
        fs::write(&path, &original).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        let dry = process_file(&path, Mode::Wrap, SOGAR, true);
        assert!(!dry.written && dry.backup.is_none());
        assert_eq!(fs::read_to_string(&path).expect("read"), original);

        let report = process_file(&path, Mode::Wrap, SOGAR, false);
        assert!(report.error.is_none(), "{:?}", report.error);
        assert!(report.written);
        assert_eq!(report.backup.as_deref(), Some(backup_path(&path).as_path()));
        assert_eq!(fs::read_to_string(backup_path(&path)).expect("backup"), original);
        let wrapped = fs::read_to_string(&path).expect("read");
        assert!(wrapped.ends_with("}\n"));
        assert!(wrapped.find("numStartups") < wrapped.find("mcpServers"), "top-level key order kept");
        assert_eq!(fs::metadata(&path).expect("stat").permissions().mode() & 0o777, 0o600);

        // A second init keeps the pristine backup.
        let again = process_file(&path, Mode::Wrap, SOGAR, false);
        assert!(!again.written && again.backup.is_none());

        let unwrapped = process_file(&path, Mode::Unwrap, SOGAR, false);
        assert!(unwrapped.written);
        let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(doc["mcpServers"]["github"], sample()["mcpServers"]["github"]);

        // Leftover temp files would show up next to the config.
        let names: Vec<String> = fs::read_dir(&dir.0)
            .expect("ls")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.iter().any(|n| n.ends_with(".sogar.tmp")), "{names:?}");
    }

    #[test]
    fn symlinked_configs_are_updated_in_place() {
        let dir = TempDir::new();
        let real = dir.0.join("dotfiles-mcp.json");
        let link = dir.0.join("mcp.json");
        fs::write(&real, serde_json::to_string(&sample()).expect("json")).expect("write");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let report = process_file(&link, Mode::Wrap, SOGAR, false);
        assert!(report.written, "{:?}", report.error);
        assert!(fs::symlink_metadata(&link).expect("lstat").file_type().is_symlink());
        assert!(fs::read_to_string(&real).expect("read").contains("mcp-wrap"));
    }

    #[test]
    fn invalid_json_is_reported_not_overwritten() {
        let dir = TempDir::new();
        let path = dir.0.join("mcp.json");
        fs::write(&path, "{ not json").expect("write");
        let report = process_file(&path, Mode::Wrap, SOGAR, false);
        assert!(report.error.as_deref().is_some_and(|e| e.contains("invalid JSON")));
        assert_eq!(fs::read_to_string(&path).expect("read"), "{ not json");
    }

    #[test]
    fn discovers_existing_configs_once() {
        let home = TempDir::new();
        fs::create_dir_all(home.0.join(".cursor")).expect("mkdir");
        fs::write(home.0.join(".claude.json"), "{}").expect("write");
        fs::write(home.0.join(".cursor/mcp.json"), "{}").expect("write");
        // cwd == home: ~/.cursor/mcp.json must not be listed twice.
        let found = discover(&home.0, &home.0);
        assert_eq!(found, vec![home.0.join(".claude.json"), home.0.join(".cursor/mcp.json")]);
    }

    #[test]
    fn summary_lists_every_server_and_the_backup() {
        colored::control::set_override(false);
        let home = PathBuf::from("/Users/dev");
        let reports = vec![FileReport {
            path: home.join(".claude.json"),
            changes: rewrite_document(&mut sample(), Mode::Wrap, SOGAR),
            error: None,
            backup: Some(home.join(".claude.json.sogar.bak")),
            written: true,
        }];
        let text = render_summary(&reports, &home, Mode::Wrap, false);
        assert!(text.contains("~/.claude.json  github"), "{text}");
        assert!(text.contains("skipped: remote server (url)"), "{text}");
        assert!(text.contains("Backed up original to ~/.claude.json.sogar.bak"), "{text}");
        assert!(text.contains("3 server(s) wrapped in 1 file(s)."), "{text}");

        let dry = render_summary(&reports, &home, Mode::Wrap, true);
        assert!(dry.contains("Dry run: 3 server(s) would be wrapped"), "{dry}");
    }
}
