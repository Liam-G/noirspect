# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 - Unreleased

- Load Nargo packages and workspaces through the Noir compiler's own crates,
  pinned to nargo 1.0.0-beta.26, and analyze the optimized SSA it produces.
- Analyze `main` for binaries; for libraries, every concrete function and every
  instantiation of a generic function found in the crate (tests included).
- Add rules NUC-001 to NUC-008 (NUC-007 off by default).
- Add text, JSON and SARIF 2.1.0 output with hint and weak-check locations.
- Add `--min-severity`, `--disable`, `--enable`, `--config` policy files and
  `// noirspect-ignore` suppression comments.
- Lower entry points in worker processes with a per-entry time budget
  (`--entry-timeout`), so one slow function cannot stall a CI run.
- Add a seeded suite of 42 vulnerable circuits and 40 correct look-alikes.
- Add a composite GitHub Action that uploads findings to code scanning.
