# Contributing

Thank you for your interest in contributing to `towershield`!

## How to contribute

1. Fork the repository and create a feature branch.
2. Make your changes with focused, well-described commits.
3. Add tests for any new behaviour or bug fixes.
4. Run the local checks below.
5. Open a pull request with a clear description.

## Local checks

Run the same high-signal checks used by CI:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked --no-default-features
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
```

CI also checks the workspace with Rust 1.97, the minimum supported Rust
version declared in `Cargo.toml`.

## Adding built-in rules

Built-in rules are defined as data in `crates/shield-core/src/defaults.rs`.
Rules must:

- Have a stable `id` following the `group.name` convention.
- Be high-confidence scanner probes, not generic application paths.
- Include a human-readable `description`.
- Add representative blocked and allowed requests to
  `crates/shield-core/tests/fixtures/default_paths.tsv`; keep coverage
  data-driven rather than creating one test function per rule.

Adding a built-in rule is a **minor** version bump because it may block a
previously-allowed path. See `CHANGELOG.md` for the full versioning policy.

Run `cargo bench -p towershield-core --bench core_checker` when changing path
inspection or matching. The benchmark reports time, allocation count, total
bytes, and maximum live bytes for representative request batches.

## Updating public APIs

- Add rustdoc for every public item; each crate denies missing documentation.
- Update the README when installation, features, defaults, or integration
  boundaries change.
- Add an entry under `Unreleased` in `CHANGELOG.md`.
- Preserve serialized rule compatibility or document the required migration.

## Preparing a release

1. Move the relevant `Unreleased` entries to a versioned heading with an ISO
   date.
2. Update the shared workspace version and internal dependency requirements.
3. Run all local checks, fully verify the core crate, and assemble all three
   workspace archives together so unpublished internal versions resolve:

   ```bash
   cargo package -p towershield-core --locked
   cargo package --workspace --no-verify --locked
   ```
4. Publish `towershield-core` before packaging and publishing the dependent
   `towershield` and `towershield-cloudflare` crates.
5. Create a signed version tag after the published packages are verified.

## Security issues

Please report security vulnerabilities privately. See `SECURITY.md`.

## Code of conduct

Be respectful and constructive in all interactions.
