//! `sogar export`: hand a verified flight record to SecOps tooling.
//!
//! * `ocsf`  — newline-delimited OCSF 1.3 events (Process Activity, File
//!   System Activity, Network Activity, API Activity) for CrowdStrike Falcon
//!   Next-Gen SIEM, Splunk, Datadog and other OCSF-aware pipelines.
//! * `sarif` — a SARIF 2.1.0 log with one `error` result per critical record
//!   or policy violation, so a CI run (e.g. GitHub code scanning) fails when
//!   an agent or MCP server did something it must not.
//! * `jsonl` — the verified entries themselves, with their `seq` and `hash`.
//!
//! Only records that pass hash-chain verification are exported; a broken
//! chain is reported (and, in SARIF, becomes a finding of its own).

use std::path::Path;

use anyhow::Result;
use chrono::DateTime;
use clap::ValueEnum;
use serde_json::{json, Map, Value};

use crate::alert::describe;
use crate::ledger::{self, Verification, VerifiedRecord};
use crate::lineage::basename;

pub const OCSF_VERSION: &str = "1.3.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Ocsf,
    Sarif,
    Jsonl,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExportOptions {
    pub critical_only: bool,
    /// Only records with a sequence number greater than this.
    pub after_seq: Option<u64>,
}

pub struct ExportOutput {
    pub text: String,
    /// Critical records exported (policy violations are critical).
    pub findings: usize,
    pub tampered: bool,
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn u64_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn is_critical(entry: &Value) -> bool {
    str_field(entry, "severity") == Some("critical")
}

fn selected<'a>(records: &'a [VerifiedRecord], opts: &ExportOptions) -> Vec<&'a VerifiedRecord> {
    records
        .iter()
        .filter(|r| opts.after_seq.is_none_or(|after| r.seq > after))
        .filter(|r| !opts.critical_only || is_critical(&r.entry))
        .collect()
}

pub fn export(path: &Path, format: Format, opts: ExportOptions) -> Result<ExportOutput> {
    let (verification, records) = ledger::read_verified(path)?;
    let chosen = selected(&records, &opts);
    let findings = chosen.iter().filter(|r| is_critical(&r.entry)).count();
    let text = match format {
        Format::Jsonl => to_jsonl(&chosen),
        Format::Ocsf => to_ocsf(&chosen, &hostname()),
        Format::Sarif => to_sarif(&chosen, &verification, path),
    };
    Ok(ExportOutput {
        text,
        findings,
        tampered: matches!(verification, Verification::Tampered { .. }),
    })
}

// ---------------------------------------------------------------------------
// JSONL
// ---------------------------------------------------------------------------

fn to_jsonl(records: &[&VerifiedRecord]) -> String {
    let mut out = String::new();
    for record in records {
        let mut line = Map::new();
        line.insert("seq".into(), json!(record.seq));
        line.insert("hash".into(), json!(record.hash));
        if let Some(entry) = record.entry.as_object() {
            line.extend(entry.clone());
        }
        out.push_str(&Value::Object(line).to_string());
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// OCSF
// ---------------------------------------------------------------------------

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its full length.
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if ret != 0 {
        return "localhost".into();
    }
    let len = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

fn epoch_millis(entry: &Value) -> i64 {
    str_field(entry, "time")
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map_or(0, |t| t.timestamp_millis())
}

fn ocsf_file(path: &str, type_id: u8) -> Value {
    let parent = path
        .rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p });
    json!({"path": path, "name": basename(path), "parent_folder": parent, "type_id": type_id})
}

/// Fields shared by every OCSF event sogar emits.
fn ocsf_base(
    record: &VerifiedRecord,
    device: &Value,
    class: (u32, &str, u32, &str),
    activity: (u32, &str),
) -> Map<String, Value> {
    let (class_uid, class_name, category_uid, category_name) = class;
    let (activity_id, activity_name) = activity;
    let entry = &record.entry;
    let critical = is_critical(entry);
    let mut event = Map::new();
    for (key, value) in [
        ("class_uid", json!(class_uid)),
        ("class_name", json!(class_name)),
        ("category_uid", json!(category_uid)),
        ("category_name", json!(category_name)),
        ("activity_id", json!(activity_id)),
        ("activity_name", json!(activity_name)),
        (
            "type_uid",
            json!(u64::from(class_uid) * 100 + u64::from(activity_id)),
        ),
        ("type_name", json!(format!("{class_name}: {activity_name}"))),
        ("time", json!(epoch_millis(entry))),
        ("severity_id", json!(if critical { 5 } else { 1 })),
        (
            "severity",
            json!(if critical {
                "Critical"
            } else {
                "Informational"
            }),
        ),
        ("message", json!(describe(entry))),
        (
            "metadata",
            json!({
                "version": OCSF_VERSION,
                "product": {"name": "sogar", "vendor_name": "sogar", "version": env!("CARGO_PKG_VERSION")},
                "uid": record.hash,
                "sequence": record.seq,
                "original_time": str_field(entry, "time"),
                "log_name": "sogar flight record",
            }),
        ),
        ("device", device.clone()),
    ] {
        event.insert(key.into(), value);
    }

    let mut actor = Map::new();
    if let Some(name) = entry.pointer("/actor/agent_name").and_then(Value::as_str) {
        actor.insert("app_name".into(), json!(name));
    }
    if let (Some(pid), Some(exe)) = (u64_field(entry, "pid"), str_field(entry, "executable")) {
        let mut process = json!({"pid": pid, "file": ocsf_file(exe, 1)});
        if let Some(ppid) = u64_field(entry, "ppid") {
            process["parent_process"] = json!({"pid": ppid});
        }
        if let Some(session) = u64_field(entry, "session_id") {
            process["session"] = json!({"uid": session.to_string()});
        }
        actor.insert("process".into(), process);
    } else if let Some(child) = entry.pointer("/mcp/child_pid").and_then(Value::as_u64) {
        actor.insert(
            "process".into(),
            json!({"pid": child, "name": "MCP server"}),
        );
    }
    event.insert("actor".into(), Value::Object(actor));

    let mut sogar = Map::new();
    for key in [
        "actor",
        "mcp",
        "mcp_server",
        "policy_violation",
        "severity",
        "responsible_pid",
        "signing_id",
    ] {
        if let Some(value) = entry.get(key) {
            sogar.insert(key.into(), value.clone());
        }
    }
    event.insert("unmapped".into(), json!({"sogar": sogar}));
    event
}

fn ocsf_events(record: &VerifiedRecord, device: &Value) -> Vec<Value> {
    const SYSTEM: (u32, &str) = (1, "System Activity");
    let entry = &record.entry;
    let event = str_field(entry, "event").unwrap_or("");
    let path = str_field(entry, "path").unwrap_or("");
    let mut events = Vec::new();

    let primary = match event {
        "exec" => {
            let mut e = ocsf_base(
                record,
                device,
                (1007, "Process Activity", SYSTEM.0, SYSTEM.1),
                (1, "Launch"),
            );
            let mut process = json!({"file": ocsf_file(path, 1)});
            if let Some(pid) = u64_field(entry, "pid") {
                process["pid"] = json!(pid);
            }
            if let Some(args) = entry.get("args").and_then(Value::as_array) {
                let argv: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
                process["cmd_line"] = json!(argv.join(" "));
            }
            if let Some(cwd) = str_field(entry, "cwd") {
                process["working_directory"] = json!(cwd);
            }
            if let Some(ppid) = u64_field(entry, "ppid") {
                process["parent_process"] = json!({"pid": ppid});
            }
            e.insert("process".into(), process);
            Some(e)
        }
        "open" | "write" | "create" | "unlink" | "rename" | "uipc_connect" => {
            let activity = match event {
                "create" => (1, "Create"),
                "write" => (3, "Update"),
                "unlink" => (4, "Delete"),
                "rename" => (5, "Rename"),
                _ => (14, "Open"),
            };
            let mut e = ocsf_base(
                record,
                device,
                (1001, "File System Activity", SYSTEM.0, SYSTEM.1),
                activity,
            );
            let type_id = if event == "uipc_connect" { 5 } else { 1 }; // 5 = Local Socket
            e.insert("file".into(), ocsf_file(path, type_id));
            if let Some(destination) = str_field(entry, "destination") {
                e.insert("file_result".into(), ocsf_file(destination, 1));
            }
            Some(e)
        }
        "mcp_call_start" | "mcp_call_end" => {
            let activity = if event == "mcp_call_start" {
                "Tool Call Start"
            } else {
                "Tool Call End"
            };
            let mut e = ocsf_base(
                record,
                device,
                (6003, "API Activity", 6, "Application Activity"),
                (99, activity),
            );
            let mcp = entry.get("mcp").unwrap_or(&Value::Null);
            let rpc_id = mcp.get("rpc_id").map_or_else(String::new, |id| {
                id.as_str().map_or_else(|| id.to_string(), str::to_owned)
            });
            let mut api = json!({
                "operation": str_field(mcp, "tool_name"),
                "service": {"name": str_field(mcp, "server_name")},
                "request": {"uid": rpc_id},
            });
            if entry.get("is_error").and_then(Value::as_bool) == Some(true) {
                api["response"] = json!({"error": "tool call failed"});
            }
            e.insert("api".into(), api);
            e.insert(
                "src_endpoint".into(),
                json!({"hostname": device["hostname"]}),
            );
            Some(e)
        }
        _ => None,
    };
    events.extend(primary.map(Value::Object));

    // Each socket captured by libproc becomes its own Network Activity event.
    for conn in entry
        .get("network_connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let listening = str_field(conn, "state") == Some("LISTEN");
        let activity = if listening {
            (7, "Listen")
        } else {
            (1, "Open")
        };
        let mut e = ocsf_base(
            record,
            device,
            (4001, "Network Activity", 4, "Network Activity"),
            activity,
        );
        let endpoint = |addr: Option<&str>| {
            let parsed = addr.and_then(|a| a.parse::<std::net::SocketAddr>().ok());
            parsed.map(|a| json!({"ip": a.ip().to_string(), "port": a.port()}))
        };
        if let Some(src) = endpoint(str_field(conn, "local")) {
            e.insert("src_endpoint".into(), src);
        }
        if let Some(dst) = endpoint(str_field(conn, "remote")) {
            e.insert("dst_endpoint".into(), dst);
        }
        let mut info = json!({"protocol_name": str_field(conn, "protocol")});
        if !listening && conn.get("remote").is_some() {
            info["direction_id"] = json!(2);
            info["direction"] = json!("Outbound");
        }
        e.insert("connection_info".into(), info);
        if let Some(state) = str_field(conn, "state") {
            e.insert("status_detail".into(), json!(state));
        }
        events.push(Value::Object(e));
    }
    events
}

fn to_ocsf(records: &[&VerifiedRecord], hostname: &str) -> String {
    let device = json!({
        "hostname": hostname,
        "type_id": 2,
        "type": "Desktop",
        "os": {"name": "macOS", "type_id": 300, "type": "macOS"},
    });
    let mut out = String::new();
    for record in records {
        for event in ocsf_events(record, &device) {
            out.push_str(&event.to_string());
            out.push('\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

const RULE_CRITICAL: (&str, &str, &str) = (
    "SOGAR001",
    "critical-event",
    "An AI agent, MCP server or process touched a credential, secret or agent-configuration path.",
);
const RULE_DRIFT: (&str, &str, &str) = (
    "SOGAR002",
    "mcp-behavioral-drift",
    "An MCP server left its locked behavioral baseline (new binary, new path or unexpected network).",
);
const RULE_TAMPER: (&str, &str, &str) = (
    "SOGAR003",
    "flight-record-tampered",
    "The flight record's SHA-256 hash chain is broken; records after the break cannot be trusted.",
);
const RULES: [(&str, &str, &str); 3] = [RULE_CRITICAL, RULE_DRIFT, RULE_TAMPER];

/// `file://` URI with RFC 3986 percent-encoding.
fn file_uri(path: &str) -> String {
    let mut uri = String::from("file://");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

fn sarif_result(
    rule: (&str, &str, &str),
    message: String,
    location: &str,
    fingerprint: &str,
    properties: Value,
) -> Value {
    let rule_index = RULES.iter().position(|r| r.0 == rule.0).unwrap_or(0);
    json!({
        "ruleId": rule.0,
        "ruleIndex": rule_index,
        "level": "error",
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": file_uri(location)}}}],
        "partialFingerprints": {"sogarRecordHash/v1": fingerprint},
        "properties": properties,
    })
}

fn to_sarif(
    records: &[&VerifiedRecord],
    verification: &Verification,
    ledger_path: &Path,
) -> String {
    let ledger_str = ledger_path.display().to_string();
    let mut results: Vec<Value> = records
        .iter()
        .filter(|r| is_critical(&r.entry))
        .map(|record| {
            let entry = &record.entry;
            let violation = str_field(entry, "policy_violation");
            let rule = if violation.is_some() {
                RULE_DRIFT
            } else {
                RULE_CRITICAL
            };
            let location = str_field(entry, "path")
                .filter(|p| p.starts_with('/'))
                .unwrap_or(&ledger_str);
            let mut properties = Map::new();
            properties.insert("seq".into(), json!(record.seq));
            for key in [
                "time",
                "event",
                "actor",
                "mcp",
                "mcp_server",
                "pid",
                "executable",
                "args",
                "network_connections",
                "policy_violation",
            ] {
                if let Some(value) = entry.get(key) {
                    properties.insert(key.into(), value.clone());
                }
            }
            sarif_result(
                rule,
                describe(entry),
                location,
                &record.hash,
                Value::Object(properties),
            )
        })
        .collect();

    let integrity = match verification {
        Verification::Valid { head_hash, .. } => json!({"status": "valid", "head_hash": head_hash}),
        Verification::Tampered { line, reason } => {
            results.push(sarif_result(
                RULE_TAMPER,
                format!("Flight record hash chain broken at line {line}: {reason}"),
                &ledger_str,
                &format!("tamper:{line}"),
                json!({"line": line}),
            ));
            json!({"status": "tampered", "line": line, "reason": reason})
        }
    };

    let rules: Vec<Value> = RULES
        .iter()
        .map(|(id, name, description)| {
            json!({
                "id": id,
                "name": name,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "ai-agent", "mcp"]},
            })
        })
        .collect();

    let log = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "sogar",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
            "properties": {"flight_record": ledger_str, "integrity": integrity},
        }],
    });
    let mut text = serde_json::to_string_pretty(&log).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempLedger(PathBuf);

    impl TempLedger {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            Self(
                std::env::temp_dir()
                    .join(format!("sogar-export-{}-{n}", std::process::id()))
                    .join("f.jsonl"),
            )
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    fn agent() -> Value {
        json!({"type": "ai_agent", "agent_name": "claude", "root_pid": 100})
    }

    fn mcp() -> Value {
        json!({"server_name": "compromised-docs-mcp", "tool_name": "search_docs", "rpc_id": 7,
               "wrapper_pid": 110, "child_pid": 111, "arguments_summary": "{\"q\":\"setup\"}"})
    }

    fn sample(path: &Path) {
        let mut ledger = Ledger::open(path).expect("open");
        for entry in [
            json!({"time": "2026-10-15T08:54:10.250Z", "event": "mcp_call_start", "severity": "info", "actor": agent(), "mcp": mcp()}),
            json!({"time": "2026-10-15T08:54:11Z", "event": "exec", "severity": "critical", "actor": agent(), "mcp": mcp(),
                   "pid": 112, "ppid": 111, "session_id": 400, "executable": "/bin/sh", "path": "/usr/bin/curl",
                   "args": ["curl", "-s", "https://1.1.1.1"], "cwd": "/Users/dev/app",
                   "network_connections": [{"protocol": "tcp", "fd": 5, "local": "10.0.0.2:50000",
                                            "remote": "1.1.1.1:443", "state": "ESTABLISHED"}],
                   "policy_violation": "MCP behavioral drift: server 'compromised-docs-mcp' executed new binary /usr/bin/curl"}),
            json!({"time": "2026-10-15T08:54:11.5Z", "event": "open", "severity": "critical", "actor": agent(), "mcp": mcp(),
                   "pid": 113, "ppid": 112, "executable": "/bin/cat", "path": "/Users/dev/.ssh/known hosts", "access": "read"}),
            json!({"time": "2026-10-15T08:54:12Z", "event": "rename", "severity": "info", "actor": {"type": "human"},
                   "pid": 300, "executable": "/usr/bin/mv", "path": "/Users/dev/a", "destination": "/Users/dev/b"}),
            json!({"time": "2026-10-15T08:54:13Z", "event": "mcp_call_end", "severity": "info", "actor": agent(), "mcp": mcp(), "is_error": false}),
        ] {
            ledger.append(&entry).expect("append");
        }
    }

    fn lines(text: &str) -> Vec<Value> {
        text.lines()
            .map(|l| serde_json::from_str(l).expect("json line"))
            .collect()
    }

    #[test]
    fn jsonl_carries_chain_metadata_and_honours_filters() {
        let t = TempLedger::new();
        sample(&t.0);
        let all = export(&t.0, Format::Jsonl, ExportOptions::default()).expect("export");
        let rows = lines(&all.text);
        assert_eq!(rows.len(), 5);
        assert_eq!(
            (rows[0]["seq"].as_u64(), rows[0]["event"].as_str()),
            (Some(1), Some("mcp_call_start"))
        );
        assert_eq!(rows[0]["hash"].as_str().map(str::len), Some(64));
        assert_eq!(all.findings, 2);

        let critical = export(
            &t.0,
            Format::Jsonl,
            ExportOptions {
                critical_only: true,
                after_seq: None,
            },
        )
        .expect("export");
        assert_eq!(lines(&critical.text).len(), 2);
        let after = export(
            &t.0,
            Format::Jsonl,
            ExportOptions {
                critical_only: false,
                after_seq: Some(3),
            },
        )
        .expect("export");
        assert_eq!(
            lines(&after.text)
                .iter()
                .map(|r| r["seq"].as_u64().unwrap_or(0))
                .collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(after.findings, 0);
    }

    #[test]
    fn ocsf_maps_process_file_network_and_api_activity() {
        let t = TempLedger::new();
        sample(&t.0);
        let out = export(&t.0, Format::Ocsf, ExportOptions::default()).expect("export");
        let events = lines(&out.text);
        let classes: Vec<(u64, u64)> = events
            .iter()
            .map(|e| {
                (
                    e["class_uid"].as_u64().unwrap_or(0),
                    e["activity_id"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(
            classes,
            [
                (6003, 99),
                (1007, 1),
                (4001, 1),
                (1001, 14),
                (1001, 5),
                (6003, 99)
            ]
        );

        for e in &events {
            for field in [
                "class_uid",
                "category_uid",
                "activity_id",
                "type_uid",
                "time",
                "severity_id",
                "metadata",
            ] {
                assert!(e.get(field).is_some(), "missing {field} in {e}");
            }
            assert_eq!(e["metadata"]["version"], OCSF_VERSION);
            assert_eq!(e["metadata"]["product"]["name"], "sogar");
            assert_eq!(e["device"]["os"]["type_id"], 300);
            assert_eq!(
                e["type_uid"].as_u64(),
                Some(
                    e["class_uid"].as_u64().unwrap_or(0) * 100
                        + e["activity_id"].as_u64().unwrap_or(0)
                )
            );
        }

        let launch = &events[1];
        assert_eq!(launch["time"], 1_792_054_451_000_i64);
        assert_eq!(launch["severity_id"], 5);
        assert_eq!(launch["process"]["file"]["path"], "/usr/bin/curl");
        assert_eq!(launch["process"]["cmd_line"], "curl -s https://1.1.1.1");
        assert_eq!(launch["process"]["working_directory"], "/Users/dev/app");
        assert_eq!(launch["actor"]["app_name"], "claude");
        assert_eq!(launch["actor"]["process"]["file"]["path"], "/bin/sh");
        assert_eq!(
            launch["unmapped"]["sogar"]["mcp"]["tool_name"],
            "search_docs"
        );
        assert!(launch["unmapped"]["sogar"]["policy_violation"]
            .as_str()
            .is_some_and(|v| v.contains("drift")));

        let net = &events[2];
        assert_eq!(net["dst_endpoint"], json!({"ip": "1.1.1.1", "port": 443}));
        assert_eq!(net["src_endpoint"]["port"], 50000);
        assert_eq!(net["connection_info"]["protocol_name"], "tcp");
        assert_eq!(
            net["metadata"]["uid"], launch["metadata"]["uid"],
            "socket events point at their record"
        );

        assert_eq!(events[3]["file"]["parent_folder"], "/Users/dev/.ssh");
        assert_eq!(events[4]["file_result"]["path"], "/Users/dev/b");
        assert_eq!(events[4]["severity_id"], 1);
        assert_eq!(events[0]["api"]["operation"], "search_docs");
        assert_eq!(events[0]["api"]["service"]["name"], "compromised-docs-mcp");
        assert_eq!(events[0]["api"]["request"]["uid"], "7");
    }

    #[test]
    fn sarif_reports_critical_events_drift_and_tampering() {
        let t = TempLedger::new();
        sample(&t.0);
        let out = export(&t.0, Format::Sarif, ExportOptions::default()).expect("export");
        let log: Value = serde_json::from_str(&out.text).expect("sarif json");
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "sogar");
        assert_eq!(
            run["tool"]["driver"]["rules"].as_array().map(Vec::len),
            Some(3)
        );
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 2);
        assert_eq!(
            (
                results[0]["ruleId"].as_str(),
                results[0]["ruleIndex"].as_u64()
            ),
            (Some("SOGAR002"), Some(1))
        );
        assert_eq!(results[1]["ruleId"], "SOGAR001");
        assert_eq!(results[1]["level"], "error");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "file:///Users/dev/.ssh/known%20hosts"
        );
        assert_eq!(
            results[1]["partialFingerprints"]["sogarRecordHash/v1"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        assert!(results[1]["message"]["text"]
            .as_str()
            .is_some_and(|m| m.contains("compromised-docs-mcp::search_docs")));
        assert_eq!(run["properties"]["integrity"]["status"], "valid");

        // Break the chain: a SOGAR003 finding is added and the export says so.
        let text = std::fs::read_to_string(&t.0).expect("read");
        std::fs::write(&t.0, text.replacen("known hosts", "notes", 1)).expect("write");
        let out = export(&t.0, Format::Sarif, ExportOptions::default()).expect("export");
        assert!(out.tampered);
        let log: Value = serde_json::from_str(&out.text).expect("sarif json");
        let results = log["runs"][0]["results"].as_array().expect("results");
        assert_eq!(
            results.last().and_then(|r| r["ruleId"].as_str()),
            Some("SOGAR003")
        );
        assert_eq!(log["runs"][0]["properties"]["integrity"]["line"], 3);
    }

    #[test]
    fn file_uris_are_percent_encoded() {
        assert_eq!(
            file_uri("/Users/dev/My Docs/ä.txt"),
            "file:///Users/dev/My%20Docs/%C3%A4.txt"
        );
    }
}
