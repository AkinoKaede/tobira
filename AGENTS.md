# Repository Guidelines

## Project Structure & Module Organization
- `src/main.rs` owns startup, reload, and shutdown orchestration.
- Core modules are split by concern: `src/relay/` (inbound listener and outbound transports), `src/http/` (subscription endpoints/auth), `src/subscription/` (fetch, parse, process), and `src/vmess/` (VMess parsing/auth/validation).
- Shared types and helpers live in files such as `src/config.rs`, `src/error.rs`, and `src/buf.rs`.
- Use `config.example.toml` as the baseline for local runtime configuration.
- CI automation is in `.github/workflows/`; `target/` is build output and should not be committed.

## Build, Test, and Development Commands
- `cargo run -- --config config.toml` starts the daemon with a specific config file.
- `cargo build` builds a debug binary; `cargo build --release` builds optimized output.
- `cargo test --all-features` runs the full test suite used by CI.
- `cargo fmt --all` formats Rust code with project defaults.
- `cargo clippy --all-targets --all-features -- -D warnings` enforces CI lint strictness.
- `cargo doc --all-features --no-deps --document-private-items` verifies docs compile warning-free.

## Coding Style & Naming Conventions
- Follow `.editorconfig`: 4-space indentation for `*.rs`, 2-space indentation for TOML/YAML/Markdown.
- Use standard `rustfmt` formatting and keep Clippy warnings at zero.
- Naming conventions: modules/files in `snake_case` (for example, `outbound_grpc.rs`), types/traits in `PascalCase`, functions and tests in `snake_case`.
- Keep modules focused; place protocol-specific behavior in `relay/` or `vmess/` rather than `main.rs`.

## Testing Guidelines
- Prefer colocated unit tests with `#[cfg(test)] mod tests` in the same file as implementation.
- Use `#[test]` for pure logic and `#[tokio::test]` for async flows.
- Add regression tests for parser edge cases, reload behavior, and transport/auth fixes.
- Never commit real subscription data, proxy nodes, URLs, domains, IPs, UUIDs, tokens, credentials, or user-identifying node names in tests or examples. Use `test` names, `.example` domains, and documentation-only address ranges such as `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.
- Run `cargo test --all-features` locally before opening a PR.
- Always run `cargo clippy --all-targets --all-features -- -D warnings` before pushing; PRs must be Clippy-clean.

## Commit & Pull Request Guidelines
- Follow Conventional Commit style already used in history (`feat:`, `fix:`, `chore:`, `docs:`).
- Keep commits small and single-purpose; explain behavior changes in the commit body when needed.
- PRs should describe user-visible impact, link related issues, and call out config/protocol changes.
- Include logs or request/response examples when modifying HTTP or relay behavior, and ensure CI checks pass before review.
