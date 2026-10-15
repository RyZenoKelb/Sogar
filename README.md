# sogar

[![crates.io](https://img.shields.io/crates/v/sogar.svg)](https://crates.io/crates/sogar)
[![CI](https://github.com/RyZenoKelb/Sogar/actions/workflows/ci.yml/badge.svg)](https://github.com/RyZenoKelb/Sogar/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Platform: macOS 13+](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey.svg)

**A kernel-to-MCP flight recorder for AI agents on macOS.**

sogar records what AI coding agents (Claude Code, Claude Desktop, Cursor, Codex, Windsurf, aider, goose) and the MCP servers they launch actually do to your machine. Every process launch, file access and socket is attributed to the agent and the exact MCP tool call that caused it, and written to a tamper-evident, SHA-256 hash-chained log.

## The attribution gap

Two layers see part of the picture, and neither sees all of it:

| Layer | Sees | Misses |
|---|---|---|
| Agent hooks (e.g. Claude Code hooks) | Tool calls the agent knows it makes | Child processes (`fork`/`exec`), shell scripts, anything an MCP server does in its own process tree |
| macOS kernel telemetry (EndpointSecurity) | Every `exec`, `open`, `write`, `rename` | *Why* it happened: which agent, which MCP server, which tool call; whether a human or an agent typed the command |

So when `~/.aws/credentials` is read by `/bin/cat`, the kernel knows a `cat` ran, but not that it was spawned by the `search_docs` tool of an MCP server Claude Code started three minutes earlier.

## How sogar bridges it, without private entitlements

The EndpointSecurity framework normally requires an Apple-granted entitlement. sogar avoids that by combining three ordinary, public mechanisms:

1. **`/usr/bin/eslogger`**: Apple's own signed EndpointSecurity client (macOS 13+). `sogar watch` runs it as root and parses its JSON stream (`exec`, `fork`, `exit`, `open`, `write`, `create`, `rename`, `unlink`, `uipc_connect`).
2. **`libproc`**: eslogger has no TCP/IP `connect` event, so sogar asks the kernel directly (`proc_pidinfo(PROC_PIDLISTFDS)` → `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`) which IPv4/IPv6 sockets a process holds. This runs whenever a network-capable binary (`curl`, `ssh`, `git`, `node`, `python`, …) is executed, or a critical file is touched.
3. **MCP `stdio` interception**: `sogar mcp-wrap` sits between the agent and each MCP server and forwards JSON-RPC byte for byte. It reports each `tools/call` and its response, with secrets redacted, to the daemon over `/tmp/sogar.sock`. The daemon checks the sender's PID with the kernel (`LOCAL_PEERPID`), so a process cannot impersonate another wrapper.

The daemon keeps a process-lineage tree (seeded from `ps` at startup, then kept current from `fork`/`exec`/`exit`). It joins the two streams by PID ancestry and by the tool call's time window:

```
AI agent (claude, root 4211)
 └─ sogar mcp-wrap --name docs            ← tools/call search_docs #7 window opens
     └─ MCP server (node, pid 4302)
         └─ sh -c …                        ← attributed to docs::search_docs #7
             ├─ open ~/.aws/credentials    CRITICAL
             └─ exec curl                  ⇄ tcp 10.0.0.2:51544 → 203.0.113.9:443 ESTABLISHED
```

## Quickstart

```bash
cargo install sogar

# 1. Route your MCP servers through sogar (edits ~/.claude.json, ~/.cursor/mcp.json,
#    Claude Desktop's config, ./.mcp.json; originals saved as *.sogar.bak)
sogar init --dry-run
sogar init

# 2. Start the recorder (the terminal needs Full Disk Access for eslogger)
sudo sogar watch

# 3. Check the installation (read-only)
sogar doctor

# 4. Inspect what happened
sogar verify
sogar report --critical-only
```

`sogar doctor` checks the installation without changing anything:
- **eslogger:** is `/usr/bin/eslogger` present?
- **daemon:** is `/tmp/sogar.sock` accepting connections with mode `0666`?
- **ledger:** what are the flight record's owner and permissions? Does its hash chain verify? It also prints the record count and head hash.
- **lockfile:** how many MCP server profiles does `~/.sogar/mcp_lock.json` lock?
- **MCP configs:** how many configured stdio servers already go through `sogar mcp-wrap`?

Each check prints a hint when something needs attention. The exit status is non-zero only when a check fails (for example a tampered ledger or a missing `eslogger`).

`sogar unwrap` restores your MCP configs. It strips only the `sogar mcp-wrap … --` prefix, so edits you made since wrapping are kept.

## Commands

| Command | Purpose |
|---|---|
| `sogar watch [--agent-match RE] [--out PATH] [--lockfile PATH] [--webhook-url URL] [--include-human]` | Root daemon: records, attributes, enforces the MCP lockfile, alerts |
| `sogar mcp-wrap --name NAME -- CMD [ARGS…]` | Transparent stdio proxy for one MCP server (configured by `init`) |
| `sogar init` / `sogar unwrap` `[--dry-run]` | Wrap / unwrap every stdio MCP server in known config files |
| `sogar verify [--file PATH]` | Recompute the hash chain from genesis; exit 0 valid, 1 tampered |
| `sogar report [--file PATH] [--critical-only] [--after-seq N]` | Forensic summary by actor, MCP server and tool, plus every critical event |
| `sogar lock [--file PATH] [--out PATH]` | Learn each MCP server's behavioral baseline into `~/.sogar/mcp_lock.json` |
| `sogar export --format ocsf\|sarif\|jsonl [--critical-only] [--after-seq N] [--fail-on-findings]` | Hand verified records to a SIEM or CI |
| `sogar doctor [--file PATH] [--socket PATH]` | Read-only health check of eslogger, the daemon, the ledger, the lockfile and MCP configs |

## What counts as critical

Any file access, exec or argument that touches `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.kube`, `Library/Keychains`, `.env*`, `.git/hooks` or `.claude` is **critical**. The one exception is the agent's own root process touching its own `.claude` bookkeeping. MCP-server activity outside its lockfile baseline is also critical.

Routine noise is dropped before it reaches the ledger:
- system framework and dyld reads;
- loader reads of `/bin`, `/usr/bin`, Homebrew and `/Applications`;
- an app bundle's own caches, logs, `IndexedDB`, `Local Storage`, `Session Storage`, `blob_storage` and `git-shadow`.

These paths are still recorded when a shell, an interpreter or an MCP server touches them.

## MCP rug-pull detection

An `npx`/`uvx` MCP server can update silently and start behaving differently. `sogar lock` learns each server's baseline from a verified flight record:

```json
{
  "version": 1,
  "source": { "ledger": "/Users/dev/.sogar/flight_record.jsonl", "records": 1840, "head_hash": "1ecaa319…" },
  "servers": {
    "docs": {
      "allowed_executables": ["/usr/bin/git"],
      "allowed_path_prefixes": ["/Users/dev/.gitconfig", "/Users/dev/app/docs/", "/tmp/"],
      "allow_network": false
    }
  }
}
```

Critical events and earlier violations are never learned, so a ledger that already contains an attack cannot whitelist it. The output is sorted and contains no timestamps, so it can be reviewed and diffed like any lockfile. Generate it with `sudo sogar lock`: the file is then root-owned, and an agent running as you cannot loosen it. `watch` warns if it can.

While a lockfile is present, `watch` upgrades any MCP-attributed event that runs a new binary, leaves the allowed paths, or opens an external socket while `allow_network` is false. The event becomes critical with an explanation:

```
"policy_violation": "MCP behavioral drift: server 'docs' executed new binary /bin/sh"
```

## Alerts, SIEM and CI

- **Webhooks.** `--webhook-url` POSTs every critical record in the background. Each request has a 3 s timeout and at most 16 requests are in flight, so a slow endpoint never stalls the recorder. The body has `text` (Slack), `content` (Discord), and the full `record` plus its `seq` and `hash` for Torq, Tines and other SOAR tools. TLS uses the macOS system trust store.
- **OCSF.** `sogar export --format ocsf` emits newline-delimited OCSF 1.3 events:

  | sogar record | OCSF class |
  |---|---|
  | `exec` | Process Activity (1007) |
  | File events | File System Activity (1001) |
  | Each captured socket | Network Activity (4001) |
  | MCP tool calls | API Activity (6003) |

  Agent and MCP context travels in `actor.app_name` and `unmapped.sogar`. This feeds CrowdStrike Falcon Next-Gen SIEM, Splunk, Datadog and other OCSF pipelines.
- **SARIF.** `sogar export --format sarif` writes a SARIF 2.1.0 log for code scanning. Each critical record becomes an `error` result: `SOGAR001` critical event, `SOGAR002` MCP behavioral drift, `SOGAR003` broken hash chain. The record hash is the stable fingerprint. In CI, note the ledger position before the job (`--after-seq`), and add `--fail-on-findings` to fail the step (exit 3).

## The flight record

`~/.sogar/flight_record.jsonl` holds one record per line:

```json
{"seq":2,"prev_hash":"9c0d…","hash":"5e41…","entry":{"actor":{"agent_name":"claude","root_pid":4211,"type":"ai_agent"},"event":"open","access":"read","executable":"/bin/cat","path":"/Users/dev/.aws/credentials","pid":4410,"ppid":4409,"mcp":{"server_name":"docs","tool_name":"search_docs","rpc_id":7,"child_pid":4302,"wrapper_pid":4301,"arguments_summary":"{\"query\":\"setup\",\"token\":\"[REDACTED]\"}"},"severity":"critical","time":"2026-10-15T08:54:11.502Z"}}
```

`hash = sha256(canonical_json({entry, prev_hash, seq}))`, where canonical JSON is compact with sorted keys, starting from an all-zero genesis hash. Editing, inserting, deleting or reordering any record breaks verification from that point on. Store the `head` printed by `sogar verify` elsewhere to also detect truncation. Under `sudo`, the file is owned by root and readable only by the invoking user's group.

Secrets are redacted before anything is written or sent: AWS keys, GitHub tokens, `sk-…` API keys, Slack tokens and PEM private keys. This covers tool arguments and recorded command lines.

A report looks like this:

```
sogar forensic report — /Users/dev/.sogar/flight_record.jsonl
VALID hash chain intact (1840 records, head 1ecaa319c7ee55a6)
1840 events, 3 critical

Critical events
  #1207 2026-10-15 10:54:11.502 claude (root 4211) open
      mcp     docs::search_docs #7
      args    {"query":"setup","token":"[REDACTED]"}
      process cat[4410]
      target  /Users/dev/.aws/credentials
      policy  MCP behavioral drift: server 'docs' accessed /Users/dev/.aws/credentials outside its allowed path prefixes
```

## Requirements and limits

- macOS 13+ (for `eslogger`) and, to build from source, Rust 1.88+. `watch` needs root, and the terminal that runs it needs Full Disk Access.
- Socket snapshots are taken when a process starts and once more 40 ms later, not by tracing every connection. A short connection that opens and closes between snapshots can be missed.
- An agent is recognised by its executable or script name (`--agent-match` overrides the pattern). Processes that a GUI agent such as Cursor launches for you (its integrated terminal, for example) are attributed to that agent.
- The hash chain has no key: it proves the log is internally consistent, not who wrote it. Anchor the head hash externally for stronger guarantees.

## Contributing

Bug reports, detection ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup and guidelines, and [CHANGELOG.md](CHANGELOG.md) for release notes. This project follows a [code of conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open public issues for them.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
