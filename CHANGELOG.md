# Changelog

All notable changes to sogar are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-10-15

No functional changes since 0.3.0.

### Changed

- The crates.io page now links to the current source tree on GitHub.
- The package now ships `CHANGELOG.md` and declares its minimum supported Rust version (1.88).
- The `homepage` link to a domain that is not live yet is removed.
- The code is formatted with rustfmt.

## [0.3.0] - 2026-10-15

First public release.

### Added

- `sogar watch`:
  - a root daemon that parses `/usr/bin/eslogger` (`exec`, `fork`, `exit`, `open`, `write`, `create`, `rename`, `unlink`, `uipc_connect`);
  - process lineage seeded from the live process table at startup;
  - attribution of each event to an AI agent (and the MCP tool call active at the time) or to a human.
- `sogar mcp-wrap`:
  - a transparent stdio proxy that reports `tools/call` requests and responses to the daemon over `/tmp/sogar.sock`;
  - tool arguments redacted before they are sent;
  - the sender's PID is verified with the kernel (`LOCAL_PEERPID`).
- Critical-path classification: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.kube`, `Library/Keychains`, `.env*`, `.git/hooks`, `.claude`.
- Noise filtering: system frameworks, loader reads of binaries, and vendor app cache, log and web-storage churn. This activity is still recorded when a shell, an interpreter or an MCP server touches those paths.
- Native socket inspection through `libproc`, attached to network-capable executions and critical events.
- The SHA-256 hash-chained JSONL flight record, plus `sogar verify` and `sogar report`.
- `sogar init` / `sogar unwrap`: wrap and restore MCP servers in Claude Code, Cursor and Claude Desktop configurations.
- `sogar lock`, and live enforcement in `watch`: behavioral MCP lockfiles with rug-pull ("behavioral drift") detection.
- `--webhook-url`: critical-event alerts for Slack, Discord, Torq and Tines.
- `sogar export`: OCSF 1.3, SARIF 2.1.0 and JSONL.
- `sogar doctor`: a read-only installation health check.

[Unreleased]: https://github.com/RyZenoKelb/Sogar/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/RyZenoKelb/Sogar/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/RyZenoKelb/Sogar/releases/tag/v0.3.0
