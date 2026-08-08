# Contributing

Thank you for your interest in contributing to `tower-http-shield`!

## How to contribute

1. Fork the repository and create a feature branch.
2. Make your changes with focused, well-described commits.
3. Add tests for any new behaviour or bug fixes.
4. Run `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`,
   and `cargo test --all-targets` locally before pushing.
5. Open a pull request with a clear description.

## Adding built-in rules

Built-in rules are defined as data in `crates/shield-core/src/defaults.rs`.
Rules must:

- Have a stable `id` following the `group.name` convention.
- Be high-confidence scanner probes, not generic application paths.
- Include a human-readable `description`.
- Be independently testable (add a test in the `defaults` module).

Adding a built-in rule is a **minor** version bump because it may block a
previously-allowed path. See `CHANGELOG.md` for the full versioning policy.

## Security issues

Please report security vulnerabilities privately. See `SECURITY.md`.

## Code of conduct

Be respectful and constructive in all interactions.
