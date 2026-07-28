# Release checklist

1. Confirm the version in `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and the package command.
2. Run `cargo fmt --all -- --check`, `cargo test --locked --all-targets`, and
   `cargo clippy --locked --all-targets -- -D warnings` on Windows.
3. Run `scripts\Build-Release.ps1` and
   `scripts\Package-Release.ps1 -Version <version>`.
4. Verify the ZIP with `SHA256SUMS.txt` on a clean Windows test account.
5. Run `Doctor` with the real SOCKS endpoint. Use TCP-only mode unless a real
   SOCKS5 UDP relay probe succeeds.
6. Run the elevated live test and record Windows version, proxy core/profile,
   mode, route result, DNS result, and latency samples.
7. Test Start, Stop, closing the GUI while active, repeated Stop clicks, and
   restarting after a failed start. Confirm no owned sing-box process or
   `LanternRoute` adapter remains after cleanup.
8. Push a `v<version>` tag to invoke `.github/workflows/release.yml`, or
   publish the ZIP, checksum, changelog, and source tag together manually. Do not
   publish `.runtime`, credentials, private proxy URLs, or local logs.

No release should claim universal UDP or "all packets" coverage unless the
upstream SOCKS endpoint and the live test prove that behavior.
