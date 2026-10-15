# Contributing to sogar

Thanks for helping make AI agents observable. Bug reports, detection ideas, documentation fixes and code are all welcome.

## Before you start

- **Security issues:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).
- **Larger changes** (new event sources, protocol or ledger-format changes, new commands): open an issue first so the design can be discussed before you invest time.
- **Redact your data.** Flight records, `eslogger` output and `sogar doctor` output contain usernames, paths and hostnames. Remove anything you would not publish before pasting it into an issue or PR.

## Development setup

You need macOS 13 or later and Rust 1.88 or later. sogar uses macOS-only interfaces (`eslogger`, `libproc`, `LOCAL_PEERPID`), so it does not build on other platforms.

```bash
git clone https://github.com/RyZenoKelb/Sogar.git
cd Sogar
cargo build
cargo test
```

The unit tests need neither root nor Full Disk Access. To exercise the daemon end to end:

```bash
cargo build --release
sudo ./target/release/sogar watch     # terminal needs Full Disk Access
./target/release/sogar doctor         # in another terminal
```

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same checks on macOS, plus a build with the minimum supported Rust version (1.88) and `cargo package`.

## Code guidelines

- **The recorder must never stop recording.** In the daemon's event loop, malformed input, missing fields and I/O hiccups are logged and skipped. Avoid `unwrap()`/`expect()` outside tests and static invariants.
- **`mcp-wrap` must stay transparent.** It forwards MCP traffic byte for byte, never blocks on the daemon, and writes nothing but the server's own output to stdout.
- **Stable formats.** Two formats are effectively public APIs and must stay compatible: the IPC messages in `src/ipc.rs`, and the ledger's canonical JSON and hash material in `src/ledger.rs`. Changing either breaks running wrappers or the verification of existing flight records. Call such changes out explicitly in the PR.
- **No secrets at rest.** Anything that reaches the ledger, a webhook or an export goes through `redact_secrets` first.
- **Tests with every behaviour change.** Each module has unit tests next to the code. Keep them independent of root, of the machine's own processes, and of the network.
- Match the surrounding style: small functions, doc comments that explain *why*, and no new dependencies without a good reason.

## Pull requests

- Keep each PR focused on one change.
- Describe what changed and how you tested it. The PR template has a checklist.
- Add user-visible changes to `CHANGELOG.md` under *Unreleased*.

## License

sogar is licensed under [Apache-2.0](LICENSE). Unless you explicitly state otherwise, any contribution you submit is licensed under Apache-2.0 as well, without additional terms or conditions (section 5 of the license).
