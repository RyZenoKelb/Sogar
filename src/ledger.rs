//! Tamper-evident, SHA-256 hash-chained JSONL flight record.
//!
//! Each line is `{"seq":N,"prev_hash":H(N-1),"hash":H(N),"entry":{...}}` with
//! `H(N) = sha256(canonical_json({"entry":…,"prev_hash":H(N-1),"seq":N}))`,
//! where canonical JSON is compact with object keys sorted. The chain starts
//! at the all-zero genesis hash, so editing, inserting, deleting or reordering
//! any record breaks verification from that point on. Anchor the head hash
//! printed by `sogar verify` somewhere else to also detect tail truncation.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const TAIL_CHUNK: u64 = 8 * 1024;

pub struct Ledger {
    path: PathBuf,
    file: File,
    next_seq: u64,
    head: String,
    created_dir: Option<PathBuf>,
}

impl Ledger {
    /// Opens (or creates) a flight record and resumes its chain. Refuses to
    /// extend a file whose last record is incomplete or fails verification.
    pub fn open(path: &Path) -> Result<Self> {
        let mut created_dir = None;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if !dir.exists() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o750)
                    .create(dir)
                    .with_context(|| format!("failed to create {}", dir.display()))?;
                created_dir = Some(dir.to_path_buf());
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o640)
            .open(path)
            .with_context(|| format!("failed to open flight record {}", path.display()))?;

        let (next_seq, head) = match read_last_line(&mut file, path)? {
            None => (1, GENESIS_HASH.to_owned()),
            Some(last) => resume_from(&last).map_err(|reason| {
                anyhow::anyhow!(
                    "refusing to extend {}: its last record fails verification ({reason}); \
                     run `sogar verify --file {}` and move the file aside",
                    path.display(),
                    path.display()
                )
            })?,
        };

        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_seq,
            head,
            created_dir,
        })
    }

    /// Appends one entry (which must serialize to a JSON object) as a single
    /// `write(2)` and returns its sequence number.
    pub fn append<T: Serialize>(&mut self, entry: &T) -> Result<u64> {
        let value = serde_json::to_value(entry).context("failed to serialize flight record entry")?;
        if !value.is_object() {
            bail!("flight record entries must be JSON objects");
        }
        let entry_json = canonical_json(&value);
        let seq = self.next_seq;
        let hash = sha256_hex(hash_material(seq, &self.head, &entry_json).as_bytes());
        let line = format!(
            "{{\"seq\":{seq},\"prev_hash\":\"{}\",\"hash\":\"{hash}\",\"entry\":{entry_json}}}\n",
            self.head
        );
        self.file
            .write_all(line.as_bytes())
            .with_context(|| format!("failed to append to {}", self.path.display()))?;
        self.head = hash;
        self.next_seq += 1;
        Ok(seq)
    }

    pub fn sync(&self) -> Result<()> {
        self.file
            .sync_data()
            .with_context(|| format!("failed to sync {}", self.path.display()))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_hash(&self) -> &str {
        &self.head
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// When running as root via `sudo`, keeps the record owned by root (so
    /// the user's agents cannot rewrite it) but readable by the invoking
    /// user's group, so `sogar verify` works without sudo.
    pub fn share_with_invoking_user(&self) -> Result<()> {
        if !is_root() {
            return Ok(());
        }
        let Some(gid) = std::env::var("SUDO_GID").ok().and_then(|g| g.parse::<u32>().ok()) else {
            return Ok(());
        };
        let targets = [(Some(self.path.as_path()), 0o640), (self.created_dir.as_deref(), 0o750)];
        for (path, mode) in targets {
            let Some(path) = path else { continue };
            std::os::unix::fs::chown(path, Some(0), Some(gid))
                .with_context(|| format!("failed to chown {}", path.display()))?;
            fs::set_permissions(path, Permissions::from_mode(mode))
                .with_context(|| format!("failed to chmod {}", path.display()))?;
        }
        Ok(())
    }
}

fn hash_material(seq: u64, prev_hash: &str, entry_json: &str) -> String {
    // Identical to canonical_json({"entry":…,"prev_hash":…,"seq":…}).
    format!("{{\"entry\":{entry_json},\"prev_hash\":\"{prev_hash}\",\"seq\":{seq}}}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn resume_from(last: &[u8]) -> std::result::Result<(u64, String), String> {
    let value: Value = serde_json::from_slice(last).map_err(|e| format!("not valid JSON: {e}"))?;
    let seq = value.get("seq").and_then(Value::as_u64).ok_or("missing \"seq\"")?;
    let prev = value
        .get("prev_hash")
        .and_then(Value::as_str)
        .ok_or("missing \"prev_hash\"")?
        .to_owned();
    let hash = check_record(last, seq, &prev)?;
    Ok((seq + 1, hash))
}

/// Returns the last line (without its newline), or `None` for an empty file.
fn read_last_line(file: &mut File, path: &Path) -> Result<Option<Vec<u8>>> {
    let len = file
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    if len == 0 {
        return Ok(None);
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::Start(len - 1))?;
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        bail!(
            "{} ends with an incomplete record (crash or truncation?); \
             run `sogar verify --file {}` and move the file aside",
            path.display(),
            path.display()
        );
    }

    let mut tail: Vec<u8> = Vec::new();
    let mut pos = len - 1;
    while pos > 0 {
        let start = pos.saturating_sub(TAIL_CHUNK);
        let mut chunk = vec![0u8; (pos - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        if let Some(i) = chunk.iter().rposition(|b| *b == b'\n') {
            let mut line = chunk.split_off(i + 1);
            line.extend_from_slice(&tail);
            return Ok(Some(line));
        }
        chunk.extend_from_slice(&tail);
        tail = chunk;
        pos = start;
    }
    Ok(Some(tail))
}

/// Compact JSON with object keys sorted, independent of serde_json features.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::from(key.as_str()).to_string());
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Valid { records: u64, head_hash: String },
    Tampered { line: usize, reason: String },
}

/// Checks one record against the expected position in the chain and returns
/// its hash.
fn check_record(line: &[u8], expected_seq: u64, expected_prev: &str) -> std::result::Result<String, String> {
    let value: Value = serde_json::from_slice(line).map_err(|e| format!("not valid JSON: {e}"))?;
    let Value::Object(mut record) = value else {
        return Err("record is not a JSON object".into());
    };
    let hash = match record.remove("hash") {
        Some(Value::String(hash)) => hash,
        _ => return Err("missing \"hash\"".into()),
    };
    let seq = record.get("seq").and_then(Value::as_u64).ok_or("missing \"seq\"")?;
    if seq != expected_seq {
        return Err(format!(
            "sequence {seq} where {expected_seq} was expected (record inserted, deleted or reordered)"
        ));
    }
    let prev = record
        .get("prev_hash")
        .and_then(Value::as_str)
        .ok_or("missing \"prev_hash\"")?;
    if prev != expected_prev {
        return Err("prev_hash does not link to the previous record".into());
    }
    if !record.get("entry").is_some_and(Value::is_object) {
        return Err("missing \"entry\" object".into());
    }
    if record.len() != 3 {
        return Err("unexpected fields in record".into());
    }
    let computed = sha256_hex(canonical_json(&Value::Object(record)).as_bytes());
    if computed != hash {
        return Err("hash mismatch: record content was modified".into());
    }
    Ok(hash)
}

pub fn verify_file(path: &Path) -> Result<Verification> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    verify_reader(BufReader::new(file))
}

pub fn verify_reader<R: BufRead>(mut reader: R) -> Result<Verification> {
    let mut prev = GENESIS_HASH.to_owned();
    let mut records = 0u64;
    let mut line_no = 0usize;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf).context("failed to read flight record")? == 0 {
            break;
        }
        line_no += 1;
        if buf.pop() != Some(b'\n') {
            return Ok(Verification::Tampered {
                line: line_no,
                reason: "truncated record (missing trailing newline)".into(),
            });
        }
        match check_record(&buf, records + 1, &prev) {
            Ok(hash) => {
                prev = hash;
                records += 1;
            }
            Err(reason) => return Ok(Verification::Tampered { line: line_no, reason }),
        }
    }
    Ok(Verification::Valid { records, head_hash: prev })
}

/// One record that passed chain verification.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRecord {
    pub seq: u64,
    pub hash: String,
    pub entry: Value,
}

/// Verifies the chain, then returns every record before the first broken
/// one: the only records that can be trusted.
pub fn read_verified(path: &Path) -> Result<(Verification, Vec<VerifiedRecord>)> {
    let verification = verify_file(path)?;
    let trusted = match &verification {
        Verification::Valid { records, .. } => usize::try_from(*records).unwrap_or(usize::MAX),
        Verification::Tampered { line, .. } => line.saturating_sub(1),
    };
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut records = Vec::with_capacity(trusted.min(1 << 20));
    for line in BufReader::new(file).lines().take(trusted) {
        let line = line.with_context(|| format!("failed to read {}", path.display()))?;
        let mut record: Value = serde_json::from_str(&line).context("verified record is not JSON")?;
        records.push(VerifiedRecord {
            seq: record.get("seq").and_then(Value::as_u64).unwrap_or(0),
            hash: record.get("hash").and_then(Value::as_str).unwrap_or("").to_owned(),
            entry: record.get_mut("entry").map(Value::take).unwrap_or(Value::Null),
        });
    }
    Ok((verification, records))
}

// ---------------------------------------------------------------------------
// Default location
// ---------------------------------------------------------------------------

/// `~/.sogar/flight_record.jsonl` of the invoking user (also under `sudo`).
pub fn default_path() -> Result<PathBuf> {
    Ok(invoking_user_home()?.join(".sogar").join("flight_record.jsonl"))
}

pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub(crate) fn invoking_user_home() -> Result<PathBuf> {
    if is_root() {
        let sudo_user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root");
        if let Some(home) = sudo_user.as_deref().and_then(home_of_user) {
            return Ok(home);
        }
    }
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    // SAFETY: getuid has no preconditions; getpwuid returns NULL or a valid entry.
    passwd_home(unsafe { libc::getpwuid(libc::getuid()) })
        .context("cannot determine the home directory; pass an explicit path")
}

fn home_of_user(user: &str) -> Option<PathBuf> {
    let name = CString::new(user).ok()?;
    // SAFETY: `name` is a valid C string; called once at startup.
    passwd_home(unsafe { libc::getpwnam(name.as_ptr()) })
}

fn passwd_home(pw: *mut libc::passwd) -> Option<PathBuf> {
    if pw.is_null() {
        return None;
    }
    // SAFETY: non-null passwd entries have a valid (possibly null) pw_dir.
    let dir = unsafe { (*pw).pw_dir };
    if dir.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(dir) }.to_bytes();
    (!bytes.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempLedger(PathBuf);

    impl TempLedger {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("sogar-ledger-{}-{n}", std::process::id()));
            Self(dir.join("nested").join("flight_record.jsonl"))
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn lines(&self) -> Vec<String> {
            fs::read_to_string(&self.0).expect("read").lines().map(str::to_owned).collect()
        }
        fn write_lines(&self, lines: &[String]) {
            let mut text = lines.join("\n");
            text.push('\n');
            fs::write(&self.0, text).expect("write");
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent().and_then(Path::parent) {
                let _ = fs::remove_dir_all(dir);
            }
        }
    }

    fn sample(i: u64) -> Value {
        json!({"event": "open", "pid": 100 + i, "path": format!("/Users/dev/file-{i}"),
               "actor": {"type": "ai_agent", "agent_name": "claude", "root_pid": 100},
               "args": ["cat", "naïve \"quoted\" \\ text"]})
    }

    fn write_records(t: &TempLedger, n: u64) -> String {
        let mut ledger = Ledger::open(t.path()).expect("open");
        for i in 0..n {
            assert_eq!(ledger.append(&sample(i)).expect("append"), i + 1);
        }
        ledger.head_hash().to_owned()
    }

    fn verify(t: &TempLedger) -> Verification {
        verify_file(t.path()).expect("readable")
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let v = json!({"b": 1, "a": {"z": [1, {"y": null, "x": true}], "c": "é\n"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":"é\n","z":[1,{"x":true,"y":null}]},"b":1}"#);
    }

    #[test]
    fn empty_ledger_is_valid() {
        let t = TempLedger::new();
        Ledger::open(t.path()).expect("open");
        assert_eq!(verify(&t), Verification::Valid { records: 0, head_hash: GENESIS_HASH.into() });
    }

    #[test]
    fn chain_starts_at_genesis_and_verifies() {
        let t = TempLedger::new();
        let head = write_records(&t, 5);
        let lines = t.lines();
        assert_eq!(lines.len(), 5);
        let first: Value = serde_json::from_str(&lines[0]).expect("json");
        assert_eq!(first["prev_hash"], GENESIS_HASH);
        assert_eq!(first["seq"], 1);
        assert_eq!(verify(&t), Verification::Valid { records: 5, head_hash: head });
    }

    #[test]
    fn reopening_resumes_the_chain() {
        let t = TempLedger::new();
        write_records(&t, 3);
        let mut ledger = Ledger::open(t.path()).expect("reopen");
        assert_eq!(ledger.next_seq(), 4);
        ledger.append(&sample(9)).expect("append");
        assert!(matches!(verify(&t), Verification::Valid { records: 4, .. }));
    }

    #[test]
    fn detects_modified_entry() {
        let t = TempLedger::new();
        write_records(&t, 4);
        let mut lines = t.lines();
        lines[1] = lines[1].replace("/Users/dev/file-1", "/Users/dev/innocent");
        t.write_lines(&lines);
        match verify(&t) {
            Verification::Tampered { line, reason } => {
                assert_eq!(line, 2);
                assert!(reason.contains("hash mismatch"), "{reason}");
            }
            other => panic!("expected tampering, got {other:?}"),
        }
    }

    #[test]
    fn detects_recomputed_hash_breaking_the_link() {
        // An attacker who fixes up one record's hash still breaks the next link.
        let t = TempLedger::new();
        write_records(&t, 3);
        let mut lines = t.lines();
        let mut rec: serde_json::Map<String, Value> = serde_json::from_str(&lines[0]).expect("json");
        rec.insert("entry".into(), json!({"event": "open", "path": "/forged"}));
        rec.remove("hash");
        let hash = sha256_hex(canonical_json(&Value::Object(rec.clone())).as_bytes());
        rec.insert("hash".into(), Value::String(hash));
        lines[0] = Value::Object(rec).to_string();
        t.write_lines(&lines);
        match verify(&t) {
            Verification::Tampered { line, reason } => {
                assert_eq!(line, 2);
                assert!(reason.contains("prev_hash"), "{reason}");
            }
            other => panic!("expected tampering, got {other:?}"),
        }
    }

    #[test]
    fn detects_deleted_reordered_and_truncated_records() {
        let t = TempLedger::new();
        write_records(&t, 4);
        let original = t.lines();

        let mut deleted = original.clone();
        deleted.remove(1);
        t.write_lines(&deleted);
        assert!(matches!(verify(&t), Verification::Tampered { line: 2, .. }));

        let mut swapped = original.clone();
        swapped.swap(1, 2);
        t.write_lines(&swapped);
        assert!(matches!(verify(&t), Verification::Tampered { line: 2, .. }));

        let mut text = original.join("\n");
        text.truncate(text.len() - 5);
        fs::write(t.path(), text).expect("write");
        assert!(matches!(verify(&t), Verification::Tampered { line: 4, .. }));
        assert!(Ledger::open(t.path()).is_err(), "must not extend a torn record");
    }

    #[test]
    fn refuses_to_extend_a_tampered_tail() {
        let t = TempLedger::new();
        write_records(&t, 2);
        let mut lines = t.lines();
        lines[1] = lines[1].replace("file-1", "file-X");
        t.write_lines(&lines);
        let err = Ledger::open(t.path()).err().expect("refused").to_string();
        assert!(err.contains("fails verification"), "{err}");
    }

    #[test]
    fn resumes_records_longer_than_one_tail_chunk() {
        let t = TempLedger::new();
        let mut ledger = Ledger::open(t.path()).expect("open");
        ledger.append(&json!({"blob": "x".repeat(20_000)})).expect("append");
        ledger.append(&json!({"blob": "y".repeat(30_000)})).expect("append");
        let head = ledger.head_hash().to_owned();
        drop(ledger);
        let ledger = Ledger::open(t.path()).expect("reopen");
        assert_eq!((ledger.next_seq(), ledger.head_hash()), (3, head.as_str()));
    }

    #[test]
    fn rejects_non_object_entries() {
        let t = TempLedger::new();
        let mut ledger = Ledger::open(t.path()).expect("open");
        assert!(ledger.append(&json!([1, 2])).is_err());
    }
}
