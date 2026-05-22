# Changelog

## 0.1.1

Security refresh and hardening release.

- Upgraded vulnerable Rust dependencies reported by Dependabot/RustSec.
- Removed OpenSSL/native-tls from the dependency graph.
- Migrated transparent HTTPS upstream TLS handling to Rustls.
- Precompiled rule-engine regex matchers at rule load time.
- Added bounds to in-flight request correlation caches.
- Added stricter rule validation for response status rewrites.
- Cleaned up clippy warnings across binaries and core modules.

Validation:

- `cargo check`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo audit`
