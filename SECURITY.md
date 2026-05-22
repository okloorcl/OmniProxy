# Security

## Dependency Vulnerability Response

OmniProxy uses RustSec and Dependabot signals for dependency security tracking.

For the 0.1.1 security refresh, the vulnerable dependency chain reported in
`Cargo.lock` was remediated as follows:

- `wasmtime` was upgraded from `38.0.4` to `45.0.0`.
- `rustls-webpki` was upgraded from `0.103.10` to `0.103.13`.
- `lru` was upgraded from `0.12.5` to `0.16.4` through the `ratatui` 0.30 line.
- `openssl`, `native-tls`, and `tokio-native-tls` were removed from the project
  dependency graph.
- `omni-transparentd` now uses the existing Rustls stack for upstream TLS instead
  of the removed native-tls/OpenSSL path.

## Local Verification

Run these commands before publishing a security update:

```bash
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
```

Useful dependency checks:

```bash
cargo tree -i wasmtime
cargo tree -i rustls-webpki
cargo tree -i lru
cargo tree -i openssl || true
cargo tree -i native-tls || true
cargo tree -i tokio-native-tls || true
```

Expected current state:

- `wasmtime v45.0.0`
- `rustls-webpki v0.103.13`
- `lru v0.16.4`
- no `openssl`
- no `native-tls`
- no `tokio-native-tls`
