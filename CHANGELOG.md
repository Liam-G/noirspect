# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - 2026-10-19

- Add NUC-009 One-directional bound: hint results tied to their inputs only by
  comparisons in one direction (a square root checked with `r * r <= y` alone).
- Report the other half of the is-zero bug in NUC-004: `x * inv == 1 - flag`
  without `x * flag == 0`.
- Add `--baseline REPORT` to leave out findings already in an earlier JSON
  report. Findings carry a fingerprint that survives edits to other lines.
- Add `--jobs N` to compile entry points in parallel worker processes
  (default: CPU count, at most 4; each worker holds its own copy of the crate).
- Publish prebuilt binaries for Linux (x86_64, arm64) and macOS (arm64) with
  every release; the GitHub Action downloads and verifies them instead of
  compiling noirspect, and falls back to `cargo install` elsewhere.
- Fix `action.yml`, which was not valid YAML in 0.1.0.
- Analyze functions that take references or vectors through their instances in
  callers instead of skipping them.
- Skip functions with function-typed parameters, whose checks are invisible
  when the closure is not known.
- Recognize multi-limb remainder bounds (bignum `validate_gt`) in NUC-002.
- Limit NUC-007 to source-level `Field as uN` casts, not truncations the
  compiler inserts for signed arithmetic.
- Bound the depth of linear-form expansion so very long addition chains cannot
  overflow the stack.

## 0.1.0 - 2026-10-18

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
