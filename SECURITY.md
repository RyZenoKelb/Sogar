# Security policy

sogar runs a root daemon, accepts messages from unprivileged processes, and keeps a forensic record that people rely on after an incident. We take reports about it seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:

**[Report a vulnerability](https://github.com/RyZenoKelb/Sogar/security/advisories/new)**

Please include:
- the affected version (`sogar --version`) and macOS version;
- the impact, and the steps or a proof of concept that reproduce it;
- any suggested fix or mitigation.

You will get an acknowledgement as soon as possible. A fix and an advisory are coordinated with you before anything is published, and you are credited unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| < 0.3 | No |

## In scope

For example:
- privilege escalation through `sogar watch`, its socket or the files it writes as root;
- a process impersonating an MCP wrapper, or forging, suppressing or misattributing records;
- ledger tampering that `sogar verify` does not detect, other than the documented limits below;
- secrets that reach the ledger, a webhook or an export despite redaction;
- bypasses of the MCP lockfile (behavioral drift that is not flagged);
- `sogar init`/`unwrap` corrupting or leaking MCP configuration files.

## Known limits (not vulnerabilities)

These are documented in the README:
- The hash chain has no key. It proves internal consistency, not authorship, and detects truncation only if the head hash is stored elsewhere.
- Socket snapshots are periodic, not a full connection trace.
- Agents are identified by executable or script name, and processes launched from inside a GUI agent are attributed to it.
- Anyone with root can stop or alter sogar.
