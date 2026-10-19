# Changelog

All notable changes to this project will be documented in this file.

## 0.3.0 - 2026-10-20

- Support nargo 1.0.0-rc.5 (was 1.0.0-beta.26). `noirspect --version` names
  the supported release, and a test keeps it in step with the pinned compiler
  crates.
- NUC-003 now also reports limbs that each fit their width but together reach
  past the field modulus, such as two 128-bit halves of a `Field`: `x` and
  `x + p` then both decompose. A comparison with the modulus, as in
  `std::field::bn254::decompose`, satisfies the rule.
- NUC-006 now also reports permutation checks that are too weak: hinted
  indices that may repeat (`s[i] == a[idx[i]]` with nothing showing the
  indices are distinct), and power sums that cannot pin the multiset (the sum
  and the sum of squares for four elements).
- NUC-009 now also reports a result pinned to one of several inputs but
  compared with only some of them: `(m == a) | (m == b)` with `m >= b` alone
  lets the maximum of 7 and 3 be 3.
- In library mode, NUC-001 no longer reports a hint result that is returned
  for the caller to check, like the other rules.
- Analyze generic functions that take `&mut` parameters through their
  instances. The compiler's in-place array write pass asserts that no memory
  is left, which fails when such an instance stands in for `main`; noirspect
  skips that pass for instances. Values that still pass through memory are
  not followed, which can hide a finding but never adds one. The standard
  library goes from 28 skipped entry points to 10.
- Count a constant upper bound as a range check: an asserted `x < C`, and a
  read from a fixed-size array at index `x`, which ACIR bounds checks. Lookup
  tables used as range checks (as in sha512) no longer raise NUC-003.
- NUC-008 skips `#[test]` functions, which are never part of a circuit.
- Give workers time to check and plan a large crate before their first entry:
  three times what the parent took, plus 30 seconds, instead of one entry's
  budget. Every entry of Aztec's private kernel library was skipped before.
- Fix the seeded suite. An audit found four look-alikes that were themselves
  under-constrained, and one that rejected honest inputs:
  - two hinted index maps without a distinctness check, two power sums for
    four elements, and two 128-bit halves past the modulus are now vulnerable
    cases, with sound look-alikes next to them;
  - a product check at a constant challenge now derives the challenge from a
    hash of both arrays;
  - a minimum check that underflowed when `b < a` now compares as `Field`.
- Run the seeded suite with nargo in CI: every look-alike accepts honest
  inputs, and `tests/exploits` shows a wrong witness accepted by each new
  vulnerable case and rejected by its fix.

## 0.2.1 - 2026-10-19

- Fix memory exhaustion on very large circuits. A package with benchmark
  circuits of tens of thousands of hints and over a million SSA instructions
  made 0.2.0 grow past 19 GiB and get killed by the operating system:
  - on Linux each worker gets a share of memory; an entry that outgrows it is
    stopped and retried at the end on its own, with most of the free memory;
  - workers are replaced after 256 entries, or once they have grown 2 GiB
    since loading the crate, because the compiler keeps memory from every
    entry it lowers;
  - leaf sets are shared between values and summarized past 64 leaves, and
    each hint's forward slice (bounded to 5,000 values) is computed when its
    rules run instead of all at once. Summaries and bounded slices can only
    hide a finding, never add one.
- Make `--entry-timeout` the total time an entry may take, including a first
  attempt that was stopped for memory.
- Decide whether a library function returns an unchecked value with a forward
  walk from that value, so large returned arrays no longer hide findings.

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
