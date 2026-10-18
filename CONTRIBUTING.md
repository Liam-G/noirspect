# Contributing

Thank you for helping improve `noirspect`.

## Ground rules

- Report bugs found in third-party Noir code privately to its maintainers
  first (see [SECURITY.md](SECURITY.md)); never open a public issue or test
  fixture for an unfixed bug in someone else's circuit.
- Every rule needs at least 5 vulnerable circuits and 5 correct look-alikes in
  `tests/corpus/`, a docs page in `docs/rules/`, and a remediation.
- A rule that the Noir compiler starts catching itself should be removed.
- Open an issue before making a large behavioral or report-format change.

## Local workflow

1. Install Rust 1.89 or newer. `nargo` is not needed: the compiler crates are
   built in.
2. Add or update corpus cases. Mark each vulnerable function with
   `// expect: NUC-00X` on the line above `fn`.
3. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
   `cargo test`.
4. Use `noirspect ssa --program-dir DIR --function NAME` to see the SSA a rule
   runs on.
5. Update the README and the rule docs when behavior changes.

## Upgrading the supported nargo version

The compiler's internal crates change between betas. Bump every `tag` in
`Cargo.toml` together, run the full test suite, run
`scripts/mutation_recall.py tests/corpus/*`, and update the version in the
README, `src/report.rs` and the changelog.

Use short, imperative commit subjects. Pull requests should explain the
soundness bug the change targets, the corpus cases, and the effect on false
positives.
