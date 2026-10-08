# Tests before a stable release

Build checks:

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --release --locked
```

The [physical evidence](VALIDATION.md) covers initial scrolling and Bluetooth
reconnect on one Windows 11 machine. Still check:

- Horizontal scrolling in ordinary content, speed and direction.
- 30+ minutes idle, sleep/wake and cold reboot.
- Rollback and restoration of native movement/clicks.

Use disposable test machines for installer failures: missing administrator access,
existing files/services/filters, wrong hashes or signatures, driver-load refusal,
disk/write failures, device disappearance and restart/unload failures. Confirm
that only this installation is undone and unrelated filter entries are preserved.

Interrupt installation after each step to test recovery. The journal is not yet
fully crash-consistent. Windows refusal must stop installation; security settings
must remain unchanged. A running service alone does not prove scrolling works.
