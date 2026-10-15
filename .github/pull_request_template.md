## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## How it was tested

<!-- Unit tests added/updated? Did you run `sudo sogar watch` for changes to the daemon? -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] New behaviour is covered by tests
- [ ] No change to the IPC wire format or the ledger's canonical JSON, or the change is called out above
- [ ] `CHANGELOG.md` updated under *Unreleased* for user-visible changes
