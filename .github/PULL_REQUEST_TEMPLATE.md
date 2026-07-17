## What this changes

<!-- Summary of the change and the motivation. Link related issues. -->

## Failure modes considered

<!-- Changes touching route capture, DNS, SOCKS probing, bypasses, or engine
cleanup must explain what happens when things go wrong (leak? fail closed?
stale routes?). See CONTRIBUTING.md. -->

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --locked --all-targets`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] For routing-affecting changes: ran `Doctor` and the elevated live test, and confirmed no `ProxyBridgeRS` adapter or owned sing-box process remains after Stop
