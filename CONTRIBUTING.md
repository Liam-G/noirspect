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

1. Install Rust 1.89 or newer. noirspect builds the compiler crates in; the
   matching `nargo` (`noirup -v 1.0.0-rc.5`) is only needed to run the corpus
   packages' own tests.
2. Add or update corpus cases. Mark each vulnerable function with
   `// expect: NUC-00X` on the line above `fn`, and call every look-alike
   from the package's `honest_inputs_pass` test. A look-alike must be sound,
   not just unflagged: when in doubt, add an exploit to `tests/exploits` that
   the vulnerable version accepts and the look-alike rejects.
3. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
   `cargo test`, and `nargo test` in each corpus package and in
   `tests/exploits` (CI does this with the supported nargo release).
4. Use `noirspect ssa --program-dir DIR --function NAME` to see the SSA a rule
   runs on.
5. Update the README and the rule docs when behavior changes.

## Upgrading the supported nargo version

The compiler's internal crates change between releases. Bump every `tag` in
`Cargo.toml` together with `noir_version!` in `src/report.rs` (a test checks
they match) and the `toolchain` of the corpus job in `.github/workflows/ci.yml`.
Then run the full test suite, run `scripts/mutation_recall.py tests/corpus/*`,
rerun the real-world packages in the README, and update the README and the
changelog.

Use short, imperative commit subjects. Pull requests should explain the
soundness bug the change targets, the corpus cases, and the effect on false
positives.
