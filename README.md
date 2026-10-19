# noirspect

`noirspect` is a static analyzer that finds under-constrained values in
[Noir](https://noir-lang.org) zero-knowledge circuits: values the prover
supplies through an unconstrained (Brillig) hint that are checked, but not
checked strongly enough to pin them down. It is meant for Noir developers in
CI and for auditors reviewing Noir code.

It goes beyond the Noir compiler's built-in security passes, which catch hint
results that are never checked. noirspect looks for checks that are present
but weak, such as a division hint verified with `q * d + r == n` and no
`r < d`. The compiler accepts every bug in [`examples/vulnerable`](examples/vulnerable)
without a warning; noirspect reports all of them, with the line of the hint
and the line of the weak check.

## Quick start

Download a prebuilt binary for Linux (x86_64, arm64) or macOS (arm64) from the
[latest release](https://github.com/Liam-G/noirspect/releases/latest), or build
from source with Rust 1.89 or newer. `nargo` is not needed either way:
noirspect builds the compiler crates of nargo 1.0.0-beta.26 into itself.

```console
cargo install --locked --git https://github.com/Liam-G/noirspect --tag v0.2.1
noirspect lint --program-dir examples/vulnerable
echo $?  # 2: findings were reported

noirspect lint --program-dir examples/fixed
echo $?  # 0: clean
```

```text
[HIGH] NUC-002: Missing remainder bound
  at: src/main.nr:11:27
  see: src/main.nr:12:5 (recombined here without bounding the remainder)
  entry: vulnerable::main
  the remainder from `div_hint` is recombined as `q * d + r` but never checked to be less than the divisor
  fix: Add `assert(r < d)` next to the recombination check.
  docs: https://github.com/Liam-G/noirspect/blob/main/docs/rules/NUC-002.md
```

Write SARIF for GitHub code scanning, or JSON for other tools:

```console
noirspect lint --workspace --format sarif --output noirspect.sarif
```

## Rules

| Rule | Severity | Default | Flags |
|---|---|---|---|
| [NUC-001](docs/rules/NUC-001.md) Constant-only check | high | on | A hint result only ever compared to constants (`assert(ok)` on a "verify" hint) |
| [NUC-002](docs/rules/NUC-002.md) Missing remainder bound | high | on | `q * d + r == n` without `r < d` |
| [NUC-003](docs/rules/NUC-003.md) Unchecked decomposition | high | on | Bits or limbs recombined into an input without a range check to their width |
| [NUC-004](docs/rules/NUC-004.md) One-sided is-zero | high | on | Only one of `x * flag == 0` and `x * inv == 1 - flag` |
| [NUC-005](docs/rules/NUC-005.md) Unchecked index | medium | on | A hinted index whose element is never compared to the needle |
| [NUC-006](docs/rules/NUC-006.md) Half-checked sort | medium | on | A hinted sort checked for order but not permutation, or the reverse |
| [NUC-007](docs/rules/NUC-007.md) Narrowing cast of an unchecked Field | medium | off | `x as u8` on a `Field` that is never range checked |
| [NUC-008](docs/rules/NUC-008.md) Empty safety comment | info | on | `// Safety:` comments that give no reason |
| [NUC-009](docs/rules/NUC-009.md) One-directional bound | medium | on | A hint bounded from one side only (`r * r <= y` for a square root) |

`noirspect rules` prints the same list. Rules for Aztec contracts (note
ownership, nullifiers, private/public boundaries) are planned as a separate
pack.

## How it works

noirspect loads the package with nargo's own crates, so it analyzes exactly
the program the compiler builds. It runs the compiler's SSA optimization
pipeline (the stage where the compiler's own security checks run) and prints
the result with source locations. On that SSA it traces every value back to
the circuit inputs and hint results it was computed from, then matches each
rule against the constraints that touch a hint.

Entry points (`--entry`):

- **Binaries** (`auto`, the default): `main`.
- **Libraries** (`auto`): every constrained function, analyzed with its
  parameters as circuit inputs. Generic functions, and functions taking
  references or vectors, cannot be lowered on their own. noirspect analyzes
  each of their concrete instantiations, found in callers and `#[test]`
  functions. In library mode a value that is returned unchecked is not
  reported for NUC-002, NUC-003 and NUC-005, because the caller may check it.
- `all` applies the library behavior to binaries too; `main` analyzes `main` only.

Each entry point is compiled in a worker process with a time budget
(`--entry-timeout`, 120 seconds by default; 0 compiles in-process with no
limit), with up to `--jobs` workers at once (the CPU count, at most 4, by
default). An entry that runs over budget, or that the compiler cannot lower,
is listed as skipped in every report format rather than failing the run.

Some circuits need many gigabytes to compile. On Linux each worker gets a
share of memory (half the machine divided by `--jobs`); an entry that outgrows
it is stopped and retried at the end on its own, with most of the free memory
and whatever is left of its time budget. On very large circuits the analysis
summarizes values derived from more than 64 inputs and hints, which can hide
a finding but never adds one.

Use `noirspect ssa --program-dir DIR --function NAME` to see the SSA a rule
runs on.

## CI

The repository is a GitHub Action. It installs noirspect, uploads findings to
code scanning and fails the job on findings:

```yaml
jobs:
  noirspect:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: Liam-G/noirspect@v0.2.1
        with:
          program-dir: circuits
          args: --workspace
```

The Action downloads the release binary for the runner and checks its SHA-256
checksum; on other platforms it builds noirspect from source. SARIF paths are
relative to the directory noirspect runs in, so they resolve in code scanning
when `program-dir` is a subdirectory.

### Adopting on existing code

Accept today's findings once, commit the report, and fail CI only on new ones:

```console
noirspect lint --workspace --format json --output noirspect-baseline.json
noirspect lint --workspace --baseline noirspect-baseline.json
```

A finding's fingerprint is its rule, its file and the text of the flagged line,
so edits elsewhere in the file keep it accepted. Changing the flagged line
itself makes it a new finding to review.

### Exit codes

The same as jwt-audit and oidc-audit:

| Code | Meaning |
|---:|---|
| `0` | No finding met the selected severity threshold. |
| `1` | The command or input was invalid, or the package does not compile. |
| `2` | One or more findings met the selected severity threshold. |

## Configuration

Use `--min-severity` for the CI threshold, `--disable RULE_ID` for reviewed
exceptions and `--enable NUC-007` for rules that are off by default. Shared
policy can live in TOML:

```toml
[noirspect]
format = "sarif"
min-severity = "medium"
disable = ["NUC-008"]
entry-timeout = 300
jobs = 4
baseline = "noirspect-baseline.json"
```

```console
noirspect lint --config noirspect.toml
```

Explicit options override the file; `--disable` and `--enable` add to it.

Silence a reviewed finding on the line of the hint call, or the line above it:

```rust
// noirspect-ignore: NUC-005 the index is checked by the caller
let i = unsafe { find_hint(keys, key) };
```

`// noirspect-ignore` without a rule id silences every rule on that line.

## Evaluation

A linter is only kept switched on if its findings are usually real, so
precision is measured from the start.

**Seeded suite.** [`tests/corpus`](tests/corpus) holds 47 vulnerable circuits
and 45 correct look-alikes, at least 5 of each per rule. `cargo test` requires
every vulnerable circuit to be flagged with exactly its rule, and no
look-alike to be flagged at all. Both hold.

**Mutation recall.** [`scripts/mutation_recall.py`](scripts/mutation_recall.py)
deletes one assertion at a time from the correct look-alikes of NUC-001 to
NUC-006 and checks whether noirspect flags the mutant. Of 50 mutants, triaged
by hand:

| Outcome | Mutants |
|---|---:|
| Flagged by noirspect | 31 |
| Not under-constrained (the deleted check was redundant) | 6 |
| Hint result left with no constraint at all, which the compiler reports (3 spot-checked with `nargo compile`) | 9 |
| Missed by both: a partial `max` check, a weakened multiset check | 4 |

Of the 44 mutants that are under-constrained, noirspect flags 31 (25 in 0.1),
the compiler's own check reports 9 others, and 4 are caught by neither.

**Real-world runs.** Run with all rules on, including NUC-007, on the Noir
standard library and libraries from Noir's own external-library CI. All
packages ran to completion.

| Package | Entry points | Skipped | Time |
|---|---:|---:|---:|
| Noir standard library (beta.26) | 447 | 28 | 13 s |
| noir_sort | 3 | 0 | 1 s |
| noir_check_shuffle | 4 | 0 | 1 s |
| noir_string_search | 11 | 0 | 1 s |
| sparse_array | 16 | 2 | 1 s |
| noir_base64 | 19 | 0 | 8 s |
| noir_json_parser | 104 | 10 (4 over the time budget) | 9.5 min |
| noir-bignum | 915 | 44 | 61 s |

Measured with 0.2.1 and the default `--jobs` (4) on a 14-core machine with
30 GB of memory. Skipped entry points are functions the compiler cannot lower
as an entry point, or that ran over the time budget. noir_json_parser's time
is dominated by four benchmark circuits that each need around 10 GB and more
than 120 seconds to compile, so they run one at a time and are then skipped.

Findings in third-party code are triaged by hand and, when real, reported
privately to the maintainers first. Per-rule precision on public code will be
published here once those reports are resolved. The one measured so far:
NUC-007 reports 9 truncations in the standard library, all intended (wrapping
arithmetic), which is why it is off by default.

## Limitations

- noirspect supports exactly one nargo version per release (currently
  1.0.0-beta.26), because the compiler's internal crates change between betas.
  A package that requires a different compiler version may not compile.
- The analysis is heuristic. It recognizes specific weak-check patterns; a
  check written in an unusual form can be missed or mistaken for a bound. It
  does not prove circuits correct. For that, hand a flagged function to a
  solver-based tool such as [NAVe](https://arxiv.org/abs/2601.09372).
- In library mode, functions are analyzed without their callers, so a
  constraint a caller is expected to add is not seen.
- Functions taking function-typed parameters are not analyzed on their own,
  because a constraint passed in as a closure would be invisible.
- Contracts (`contract` packages, Aztec) are not analyzed yet.

## Prior art

| Tool | Approach | Relation to noirspect |
|---|---|---|
| [Noir compiler security passes](https://noir-lang.org/docs/noir/concepts/unconstrained) | Independent-subgraph and missing-Brillig-constraint checks | Catch hint results with no constraint at all; noirspect targets weak constraints and drops any rule the compiler starts covering |
| [Walnut noir-static-analyzer](https://github.com/walnuthq/noir-static-analyzer) | Clippy-style AST linter | Under-constraint analysis is on its roadmap |
| [NAVe](https://arxiv.org/abs/2601.09372) | SMT-based formal verification of ACIR | Complements noirspect: slower, but proves full constraint |
| [zkFuzz](https://arxiv.org/abs/2504.11961) | Fuzzing for under- and over-constrained circuits | Evaluated on Circom |
| [Circomspect](https://github.com/trailofbits/circomspect) | Static analysis passes for Circom | The model for noirspect, for a different language |

## License

MIT. See [LICENSE](LICENSE).
