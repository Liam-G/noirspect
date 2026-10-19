//! The rule catalogue and the SSA-level rules.

use crate::graph::{
    Atom, Constraint, ConstraintKind, Graph, HintCall, HintSlice, Leaf, Leaves, Linear, ratio_bits,
};
use crate::ssa::{BinOp, Instr, Kind, Loc, Operand, Val, array_len, int_bits, is_array, is_field};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(value: &str) -> Option<Severity> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub default_enabled: bool,
    pub summary: &'static str,
    pub remediation: &'static str,
}

impl Rule {
    pub fn help_uri(&self) -> String {
        format!(
            "https://github.com/Liam-G/noirspect/blob/main/docs/rules/{}.md",
            self.id
        )
    }
}

pub const RULES: [Rule; 9] = [
    Rule {
        id: "NUC-001",
        title: "Constant-only check",
        severity: Severity::High,
        default_enabled: true,
        summary: "A hint result is only ever compared to constants, so the circuit checks the hint's claim rather than the computation behind it.",
        remediation: "Recompute the claim in constrained code, or constrain the hint result against the hint's inputs.",
    },
    Rule {
        id: "NUC-002",
        title: "Missing remainder bound",
        severity: Severity::High,
        default_enabled: true,
        summary: "A quotient and remainder from a hint are checked with `q * d + r == n` but `r < d` is never asserted, so a prover can return `q - 1` and `r + d`.",
        remediation: "Add `assert(r < d)` next to the recombination check.",
    },
    Rule {
        id: "NUC-003",
        title: "Unchecked decomposition",
        severity: Severity::High,
        default_enabled: true,
        summary: "Limbs or bits from a hint are recombined into an input, but a limb is not range checked to its width, or the limbs reach past the field modulus, so the decomposition is not unique.",
        remediation: "Range check every limb to its width (`assert_max_bit_size`, a `u8`/`bool` hint return type, or `b * (1 - b) == 0` for bits); when the limbs reach 254 bits, also compare them to the modulus, as `std::field::bn254::decompose` does.",
    },
    Rule {
        id: "NUC-004",
        title: "One-sided is-zero",
        severity: Severity::High,
        default_enabled: true,
        summary: "An is-zero flag from a hint is only checked by `x * flag == 0`, which a prover satisfies with `flag = 0` for any `x`.",
        remediation: "Also return the inverse and assert `x * inv == 1 - flag`, or compute `x == 0` in constrained code.",
    },
    Rule {
        id: "NUC-005",
        title: "Unchecked index",
        severity: Severity::Medium,
        default_enabled: true,
        summary: "An index from a hint is used to read an array, but the element read is never compared to what was searched for.",
        remediation: "Assert that the element at the returned index equals the needle.",
    },
    Rule {
        id: "NUC-006",
        title: "Half-checked sort",
        severity: Severity::Medium,
        default_enabled: true,
        summary: "A sorted array from a hint is checked for order but not shown to be a permutation of the input (or the reverse), or the permutation check is too weak: hinted indices that may repeat, or fewer power sums than elements.",
        remediation: "Check both properties: adjacent elements are ordered, and the output is a permutation of the input (a hinted index map with distinct indices, the sums of powers 1 to n, or a product check at a challenge derived from both arrays).",
    },
    Rule {
        id: "NUC-007",
        title: "Narrowing cast of an unchecked Field",
        severity: Severity::Medium,
        default_enabled: false,
        summary: "A `Field` is cast to a smaller integer type without being range checked first, so the cast silently drops the high bits.",
        remediation: "Range check the `Field` before the cast (`x.assert_max_bit_size::<8>()`) when the value is meant to fit.",
    },
    Rule {
        id: "NUC-008",
        title: "Empty safety comment",
        severity: Severity::Info,
        default_enabled: true,
        summary: "A `// Safety:` comment gives no reason why the unconstrained call is sound.",
        remediation: "Say which constraints check the hint's results, so a reviewer can verify them.",
    },
    Rule {
        id: "NUC-009",
        title: "One-directional bound",
        severity: Severity::Medium,
        default_enabled: true,
        summary: "A hint result is tied to its inputs only by comparisons that all point the same way, or pinned to one of several values but compared with only some of them, so the prover can return a larger (or smaller) value than intended.",
        remediation: "Bound the result from both sides (for a square root, `r * r <= y` and `y < (r + 1) * (r + 1)`), or pin it with an equality (for a maximum, `(m == a) | (m == b)`).",
    },
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id.eq_ignore_ascii_case(id))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Related {
    pub loc: Loc,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub message: String,
    pub loc: Option<Loc>,
    pub related: Vec<Related>,
    /// The function the finding was found in, as an analysis entry point.
    pub entry: String,
    pub package: String,
    /// Stable across edits that do not touch the flagged line; see `--baseline`.
    pub fingerprint: String,
    #[serde(skip)]
    pub escapes: bool,
}

impl Finding {
    pub fn rule(&self) -> &'static Rule {
        rule(self.rule).expect("findings use catalogue rule ids")
    }
}

struct Ctx<'g, 'a> {
    g: &'g Graph<'a>,
    findings: Vec<Finding>,
    returned: Leaves,
}

impl<'g> Ctx<'g, '_> {
    fn related(&self, idx: usize, label: &str) -> Vec<Related> {
        self.g
            .loc(idx)
            .map(|loc| Related {
                loc: loc.clone(),
                label: label.to_string(),
            })
            .into_iter()
            .collect()
    }

    fn push(
        &mut self,
        rule: &'static str,
        hint: &HintCall,
        message: String,
        related: Vec<Related>,
        escapes: bool,
    ) {
        self.findings.push(Finding {
            rule,
            message,
            loc: self.g.loc(hint.instr).cloned(),
            related,
            entry: String::new(),
            package: String::new(),
            fingerprint: String::new(),
            escapes,
        });
    }

    fn escapes(&self, leaves: impl IntoIterator<Item = Leaf>) -> bool {
        leaves.into_iter().any(|l| {
            let exact = |leaf: &Leaf| self.returned.exact().is_some_and(|set| set.contains(leaf));
            // The summary of all returned leaves is cheap but coarse; walk
            // forward from the leaf when it cannot answer.
            exact(&l)
                || exact(&base(l))
                || (self.returned.is_many() && self.g.leaf_may_reach_return(l))
        })
    }

    /// Some result of the hint at `call`, or an element of one, is returned.
    fn hint_escapes(&self, hint: &HintCall) -> bool {
        match self.returned.exact() {
            Some(set) => set.iter().any(|l| l.hint_call() == Some(hint.instr)),
            None => (0..hint.results.len()).any(|pos| {
                self.g.leaf_may_reach_return(Leaf::Hint {
                    call: hint.instr,
                    pos,
                    elem: None,
                })
            }),
        }
    }

    /// The forward slice of the hint at `call`, computed on demand.
    fn slice(&self, call: usize) -> HintSlice {
        self.g.slice(self.hint(call))
    }

    fn hint(&self, call: usize) -> &'g HintCall {
        self.g
            .hints
            .iter()
            .find(|h| h.instr == call)
            .expect("hint call")
    }
}

fn base(leaf: Leaf) -> Leaf {
    match leaf {
        Leaf::Hint { call, pos, .. } => Leaf::Hint {
            call,
            pos,
            elem: None,
        },
        other => other,
    }
}

fn has_live_args(g: &Graph, hint: &HintCall) -> bool {
    hint.args.iter().any(|a| !g.leaves_of(a).is_empty())
}

/// Run every SSA rule over one constrained function.
pub fn check_function(g: &Graph) -> Vec<Finding> {
    let mut ctx = Ctx {
        g,
        findings: Vec::new(),
        returned: g.returned_leaves(),
    };
    // One hint's slice at a time: large circuits have tens of thousands of hints.
    for hint in &g.hints {
        let slice = g.slice(hint);
        constant_only(&mut ctx, hint, &slice);
        one_sided_is_zero(&mut ctx, hint, &slice);
        inverse_only_is_zero(&mut ctx, hint, &slice);
        unchecked_index(&mut ctx, hint, &slice);
        half_checked_sort(&mut ctx, hint, &slice);
        indices_not_distinct(&mut ctx, hint, &slice);
        one_directional_bound(&mut ctx, hint, &slice);
        partial_selection(&mut ctx, hint, &slice);
    }
    for c in &g.constraints {
        if c.kind == ConstraintKind::Equal {
            missing_remainder_bound(&mut ctx, c.instr);
            unchecked_decomposition(&mut ctx, c.instr);
        }
    }
    narrowing_casts(&mut ctx);
    ctx.findings
}

/// The constraints a hint's slice reaches, other than array bounds checks.
fn touching<'g>(g: &'g Graph, slice: &'g HintSlice) -> impl Iterator<Item = &'g Constraint> + 'g {
    slice
        .constraints
        .iter()
        .map(|i| &g.constraints[*i])
        .filter(|c| !c.bounds_check)
}

/// The hint's values reach an array index (NUC-005's concern).
fn used_as_index(g: &Graph, slice: &HintSlice, call: usize) -> bool {
    slice.instrs.iter().any(|i| {
        matches!(&g.instrs[*i].kind, Kind::ArrayGet { index, .. } if g.leaves_of(index).may_touch_call(call))
    }) || slice
        .constraints
        .iter()
        .any(|i| g.constraints[*i].bounds_check)
}

/// The `lt` comparisons a slice reaches, as (instruction, lhs, rhs).
fn comparisons<'g>(
    g: &'g Graph,
    slice: &'g HintSlice,
) -> impl Iterator<Item = (usize, &'g Operand, &'g Operand)> + 'g {
    slice
        .instrs
        .iter()
        .filter_map(|i| match &g.instrs[*i].kind {
            Kind::Binary {
                op: BinOp::Lt,
                lhs,
                rhs,
                ..
            } => Some((*i, lhs, rhs)),
            _ => None,
        })
}

/// NUC-001: every constraint touching the hint involves only the hint and constants.
fn constant_only(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if !has_live_args(g, hint) || slice.truncated || used_as_index(g, slice, hint.instr) {
        return;
    }
    let touching: Vec<_> = touching(g, slice).collect();
    if touching.is_empty() {
        return;
    }
    // Linked: some constraint involves an input or another hint. Two of the
    // hint's own values compared to each other (an order check) is not a
    // constant-only check either; NUC-006 covers that shape.
    let linked = touching
        .iter()
        .any(|c| c.leaves.may_reach_beyond(hint.instr) || c.leaves.may_be_several());
    if linked {
        return;
    }
    // A library function may return the result for its caller to tie down.
    let escapes = ctx.hint_escapes(hint);
    let related = ctx.related(touching[0].instr, "only checked against a constant here");
    ctx.push(
        "NUC-001",
        hint,
        format!(
            "the result of `{}` is only compared to constants; no constraint ties it to the inputs it was computed from",
            hint.callee
        ),
        related,
        escapes,
    );
}

/// NUC-002: `n == q·d + r` with `q`, `r` from one hint and no `r < d` check.
fn missing_remainder_bound(ctx: &mut Ctx, idx: usize) {
    let g = ctx.g;
    let Some(eq) = g.equation(idx) else { return };
    for (atom, coeff) in &eq.terms {
        let Atom::Product(a, b) = atom else { continue };
        for (q, d) in [(*a, *b), (*b, *a)] {
            let Some(q_leaf) = g.hint_value(&Operand::Val(q)) else {
                continue;
            };
            let call = q_leaf.hint_call().expect("hint leaf");
            let d_leaves = g.leaves_of_val(d);
            if d_leaves.is_empty() || d_leaves.may_touch_call(call) {
                continue;
            }
            let remainder = eq.terms.iter().find_map(|(other, c)| match other {
                Atom::Value(r) if c.abs() == coeff.abs() => g
                    .hint_value(&Operand::Val(*r))
                    .filter(|l| l.hint_call() == Some(call) && *l != q_leaf)
                    .map(|l| (*r, l)),
                _ => None,
            });
            let Some((r, r_leaf)) = remainder else {
                continue;
            };
            let rest_from_outside = eq.terms.keys().any(|other| {
                *other != *atom
                    && *other != Atom::Value(r)
                    && !g.atom_leaves(other).may_touch_call(call)
            });
            if !rest_from_outside {
                continue;
            }
            let slice = ctx.slice(call);
            if slice.truncated || remainder_is_bounded(g, &slice, r, d, idx) {
                return;
            }
            let hint = ctx.hint(call);
            let escapes = ctx.escapes([r_leaf]);
            let related = ctx.related(idx, "recombined here without bounding the remainder");
            ctx.push(
                "NUC-002",
                hint,
                format!(
                    "the remainder from `{}` is recombined as `q * d + r` but never checked to be less than the divisor",
                    hint.callee
                ),
                related,
                escapes,
            );
            return;
        }
    }
}

/// `op` may be computed from all of `target` (true when unknown).
fn may_derive_from(g: &Graph, op: &Operand, target: &Leaves) -> bool {
    !target.is_empty() && g.leaves_of(op).may_include(target)
}

/// `op` is certainly computed from all of `target`.
fn surely_derives_from(g: &Graph, op: &Operand, target: &Leaves) -> bool {
    g.leaves_of(op).surely_includes(target)
}

/// `r < d` in some form: a comparison, a checked unsigned `d - r`, or (for
/// multi-limb code such as bignum `validate_gt`) any other equality or range
/// constraint relating the two, except a comparison the wrong way round.
fn remainder_is_bounded(
    g: &Graph,
    slice: &HintSlice,
    r: crate::ssa::Val,
    d: crate::ssa::Val,
    recombination: usize,
) -> bool {
    let r_leaves = g.leaves_of_val(r);
    let d_leaves = g.leaves_of_val(d);
    let wrong_way = |op: &Operand| {
        let Some(Kind::Binary {
            op: BinOp::Lt,
            lhs,
            rhs,
            ..
        }) = op.val().and_then(|v| g.def(v)).map(|i| &i.kind)
        else {
            return false;
        };
        surely_derives_from(g, lhs, &d_leaves) && surely_derives_from(g, rhs, &r_leaves)
    };
    let related = slice
        .constraints
        .iter()
        .map(|i| &g.constraints[*i])
        .any(|c| {
            let relates = c.instr != recombination
                && !c.bounds_check
                && c.kind != ConstraintKind::NotEqual
                && c.leaves.may_include(&r_leaves)
                && c.leaves.may_include(&d_leaves);
            relates
                && match &g.instrs[c.instr].kind {
                    Kind::Constrain { lhs, rhs, .. } => !wrong_way(lhs) && !wrong_way(rhs),
                    _ => true,
                }
        });
    if related {
        return true;
    }
    let call = r_call(g, r);
    let compares = comparisons(g, slice).any(|(_, lhs, rhs)| {
        may_derive_from(g, lhs, &r_leaves)
            && may_derive_from(g, rhs, &d_leaves)
            && !g
                .leaves_of(rhs)
                .exact()
                .is_some_and(|l| l.iter().any(|x| x.hint_call() == Some(call)))
    });
    let subtracts = slice
        .instrs
        .iter()
        .map(|i| g.instrs[*i])
        .any(|i| match &i.kind {
            Kind::Binary {
                op: BinOp::Sub,
                unchecked: false,
                lhs,
                rhs,
            } => {
                let unsigned = i
                    .results
                    .first()
                    .and_then(|v| g.type_of(*v))
                    .is_some_and(|t| t.starts_with('u'));
                unsigned && may_derive_from(g, lhs, &d_leaves) && may_derive_from(g, rhs, &r_leaves)
            }
            _ => false,
        });
    compares || subtracts
}

fn r_call(g: &Graph, r: crate::ssa::Val) -> usize {
    g.hint_value(&Operand::Val(r))
        .and_then(|l| l.hint_call())
        .unwrap_or(usize::MAX)
}

/// NUC-003: limbs from one hint recombined with constant weights into an outside value.
fn unchecked_decomposition(ctx: &mut Ctx, idx: usize) {
    let g = ctx.g;
    let Some(eq) = g.equation(idx) else { return };
    let mut by_call: std::collections::BTreeMap<usize, Vec<(crate::ssa::Val, BigInt, Leaf)>> =
        Default::default();
    let mut outside = false;
    for (atom, coeff) in &eq.terms {
        match atom {
            Atom::Value(v) => match g.hint_value(&Operand::Val(*v)) {
                Some(leaf) => by_call
                    .entry(leaf.hint_call().expect("hint"))
                    .or_default()
                    .push((*v, coeff.clone(), leaf)),
                None => outside |= !g.leaves_of_val(*v).is_empty(),
            },
            Atom::Product(..) => return,
        }
    }
    if !outside {
        return;
    }
    for (call, mut limbs) in by_call {
        let weights: BTreeSet<BigInt> = limbs.iter().map(|(_, c, _)| c.abs()).collect();
        if limbs.len() < 2 || weights.len() != limbs.len() {
            continue;
        }
        limbs.sort_by_key(|(_, c, _)| c.abs());
        let widths: Vec<Option<u32>> = limbs
            .windows(2)
            .map(|w| ratio_bits(&w[0].1, &w[1].1))
            .collect();
        if widths.iter().any(Option::is_none) {
            continue;
        }
        let mut unchecked = Vec::new();
        for (i, (v, _, leaf)) in limbs.iter().enumerate() {
            let needed = widths.get(i).copied().flatten();
            let ok = match needed {
                Some(width) => limb_bound(g, *v).is_some_and(|bits| bits <= width),
                None => {
                    limb_bound(g, *v).is_some() || {
                        let slice = ctx.slice(call);
                        slice.truncated || is_bounded_by_comparison(g, &slice, *v)
                    }
                }
            };
            if !ok {
                unchecked.push(*leaf);
            }
        }
        if unchecked.is_empty() {
            modulus_aliasing(ctx, idx, call, &limbs);
            continue;
        }
        let hint = ctx.hint(call);
        let escapes = ctx.escapes(unchecked.iter().copied());
        let related = ctx.related(idx, "recombined here");
        ctx.push(
            "NUC-003",
            hint,
            format!(
                "{} of {} limbs from `{}` are recombined into an input without a range check to their width",
                unchecked.len(),
                limbs.len(),
                hint.callee
            ),
            related,
            escapes,
        );
    }
}

/// NUC-003, second form: every limb fits its slot, but the top limb's range
/// reaches the field modulus, so `x` and `x + p` both decompose. The stdlib's
/// `decompose` closes this by comparing the limbs to the modulus; any further
/// constraint on the top limb is taken as such a comparison.
fn modulus_aliasing(ctx: &mut Ctx, idx: usize, call: usize, limbs: &[(Val, BigInt, Leaf)]) {
    let g = ctx.g;
    let Some((top, weight, leaf)) = limbs.last() else {
        return;
    };
    let (Some(bound), Some(weight_bits)) =
        (limb_bound(g, *top), ratio_bits(&BigInt::from(1), weight))
    else {
        return;
    };
    let reach = weight_bits + bound;
    if reach < FIELD_BITS {
        return;
    }
    let slice = ctx.slice(call);
    let top_value = g.strip_casts(*top);
    let compared = slice.truncated
        || touching(g, &slice).any(|c| {
            let own_range = matches!(
                &g.instrs[c.instr].kind,
                Kind::RangeCheck { value: Operand::Val(v), .. } if g.strip_casts(*v) == top_value
            );
            c.instr != idx && !own_range && c.leaves.may_include(&Leaves::single(*leaf))
        });
    if compared {
        return;
    }
    let hint = ctx.hint(call);
    let escapes = ctx.escapes([*leaf]);
    let related = ctx.related(idx, "recombined here");
    ctx.push(
        "NUC-003",
        hint,
        format!(
            "the limbs from `{}` can represent values up to 2^{reach}, past the field modulus, so the input has more than one decomposition; compare the limbs to the modulus as `std::field::bn254::decompose` does",
            hint.callee
        ),
        related,
        escapes,
    );
}

/// Bits a limb is proven to fit in: its type, a range check, or a boolean check.
fn limb_bound(g: &Graph, v: crate::ssa::Val) -> Option<u32> {
    let stripped = g.strip_casts(v);
    if g.boolean_checked().contains(&stripped) {
        return Some(1);
    }
    match (g.proven_bits(v), g.proven_bits(stripped)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn is_bounded_by_comparison(g: &Graph, slice: &HintSlice, v: crate::ssa::Val) -> bool {
    let leaves = g.leaves_of_val(v);
    comparisons(g, slice).any(|(_, lhs, rhs)| {
        g.leaves_of(lhs).may_equal(&leaves) || g.leaves_of(rhs).may_equal(&leaves)
    })
}

/// Another constraint ties the hint down, beyond `except` and boolean checks.
fn has_other_checks(g: &Graph, slice: &HintSlice, except: usize) -> bool {
    slice.truncated
        || touching(g, slice).any(|o| {
            o.instr != except
                && !matches!(o.kind, ConstraintKind::Range(_))
                && g.is_boolean_check(o.instr).is_none()
        })
}

/// NUC-004: `x · flag == 0` is the only constraint tying the hint to `x`.
fn one_sided_is_zero(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    for c in touching(g, slice) {
        let Some(eq) = g.equation(c.instr) else {
            continue;
        };
        if !eq.constant.is_zero() || eq.terms.len() != 1 {
            continue;
        }
        let Some((Atom::Product(a, b), _)) = eq.terms.iter().next() else {
            continue;
        };
        for (flag, x) in [(*a, *b), (*b, *a)] {
            let Some(flag_leaf) = g.hint_value(&Operand::Val(flag)) else {
                continue;
            };
            if flag_leaf.hint_call() != Some(hint.instr) {
                continue;
            }
            let x_leaves = g.leaves_of_val(x);
            if x_leaves.is_empty() || x_leaves.may_touch_call(hint.instr) {
                continue;
            }
            if has_other_checks(g, slice, c.instr) {
                return;
            }
            let related = ctx.related(c.instr, "only `x * flag == 0` is asserted here");
            ctx.push(
                "NUC-004",
                hint,
                format!(
                    "the flag from `{}` is only checked by `x * flag == 0`, which `flag = 0` satisfies for every `x`",
                    hint.callee
                ),
                related,
                false,
            );
            return;
        }
    }
}

/// NUC-004, other side: `x · inv == 1 - flag` alone. For `x ≠ 0` the prover
/// picks `inv = 0` and with it `flag = 1`, claiming `x` is zero.
fn inverse_only_is_zero(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    for c in touching(g, slice) {
        let Some(eq) = g.equation(c.instr) else {
            continue;
        };
        if eq.terms.len() != 2 {
            continue;
        }
        let mut product = None;
        let mut flag = None;
        for (atom, coeff) in &eq.terms {
            match atom {
                Atom::Product(a, b) => product = Some((*a, *b, coeff.clone())),
                Atom::Value(v) => flag = Some((*v, coeff.clone())),
            }
        }
        let (Some((a, b, c_product)), Some((flag, c_flag))) = (product, flag) else {
            continue;
        };
        if c_product != c_flag || eq.constant != -c_flag {
            continue;
        }
        let from_hint = |v| {
            g.hint_value(&Operand::Val(v))
                .filter(|l| l.hint_call() == Some(hint.instr))
        };
        let Some(flag_leaf) = from_hint(flag) else {
            continue;
        };
        let shape = [(a, b), (b, a)].into_iter().find(|(inv, x)| {
            let x_leaves = g.leaves_of_val(*x);
            from_hint(*inv).is_some_and(|l| l != flag_leaf)
                && !x_leaves.is_empty()
                && !x_leaves.may_touch_call(hint.instr)
        });
        if shape.is_none() {
            continue;
        }
        if has_other_checks(g, slice, c.instr) {
            return;
        }
        let related = ctx.related(c.instr, "only `x * inv == 1 - flag` is asserted here");
        ctx.push(
            "NUC-004",
            hint,
            format!(
                "the flag from `{}` is only checked by `x * inv == 1 - flag`; with `inv = 0` the prover claims any `x` is zero",
                hint.callee
            ),
            related,
            false,
        );
        return;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    Upper,
    Lower,
}

/// The direction in which constraint `c` bounds the hint's values, when `c`
/// asserts a comparison with the hint on one side only and the hint side
/// grows with the hint's values (all its hint terms have positive weight).
fn comparison_bound(g: &Graph, c: usize, call: usize) -> Option<Bound> {
    comparison_with(g, c, call).map(|(bound, _)| bound)
}

/// [`comparison_bound`], with the operand the hint is compared to.
fn comparison_with<'a>(g: &Graph<'a>, c: usize, call: usize) -> Option<(Bound, &'a Operand)> {
    let instr: &'a Instr = g.instrs[c];
    let Kind::Constrain { lhs, rhs, .. } = &instr.kind else {
        return None;
    };
    let (value, expected) = match (lhs, rhs) {
        (Operand::Val(v), Operand::Const { value, .. })
        | (Operand::Const { value, .. }, Operand::Val(v)) => (*v, !value.is_zero()),
        _ => return None,
    };
    let (mut holds, mut v) = (expected, value);
    if let Some(Kind::Not(Operand::Val(inner))) = g.def(v).map(|i| &i.kind) {
        holds = !holds;
        v = *inner;
    }
    let Some(Kind::Binary {
        op: BinOp::Lt,
        lhs: a,
        rhs: b,
        ..
    }) = g.def(v).map(|i| &i.kind)
    else {
        return None;
    };
    let (hint_on_a, hint_on_b) = (
        g.leaves_of(a).may_touch_call(call),
        g.leaves_of(b).may_touch_call(call),
    );
    let increasing = |side: &Operand| {
        g.linear(side)
            .terms
            .iter()
            .all(|(atom, coeff)| !g.atom_leaves(atom).may_touch_call(call) || coeff.is_positive())
    };
    // `a < b` holds when `holds`, otherwise `a >= b`.
    match (hint_on_a, hint_on_b) {
        (true, false) if increasing(a) => {
            Some((if holds { Bound::Upper } else { Bound::Lower }, b))
        }
        (false, true) if increasing(b) => {
            Some((if holds { Bound::Lower } else { Bound::Upper }, a))
        }
        _ => None,
    }
}

/// The values constraint `c` says the hint's result equals one of:
/// `(m == a) | (m == b)` asserted true, or `(m - a) * (m - b) == 0`.
fn selection<'a>(g: &Graph<'a>, c: usize, call: usize) -> Option<Vec<&'a Operand>> {
    let instr: &'a Instr = g.instrs[c];
    let Kind::Constrain { lhs, rhs, .. } = &instr.kind else {
        return None;
    };
    let (Operand::Val(v), Some(expected)) = (lhs, rhs.constant()) else {
        return None;
    };
    let is_result = |op: &Operand| {
        g.hint_value(op)
            .is_some_and(|leaf| leaf.hint_call() == Some(call))
    };
    let mut options = Vec::new();
    if expected.is_zero() {
        // (m - a) * (m - b) == 0
        let Some(Kind::Binary {
            op: BinOp::Mul,
            lhs: f1,
            rhs: f2,
            ..
        }) = g.def(g.strip_casts(*v)).map(|i| &i.kind)
        else {
            return None;
        };
        for factor in [f1, f2] {
            let Some(Kind::Binary {
                op: BinOp::Sub,
                lhs: p,
                rhs: q,
                ..
            }) = factor
                .val()
                .and_then(|f| g.def(g.strip_casts(f)))
                .map(|i| &i.kind)
            else {
                return None;
            };
            match (is_result(p), is_result(q)) {
                (true, false) => options.push(q),
                (false, true) => options.push(p),
                _ => return None,
            }
        }
    } else {
        // (m == a) | (m == b) | ...
        let mut stack = vec![*v];
        while let Some(v) = stack.pop() {
            match g.def(v).map(|i| &i.kind) {
                Some(Kind::Binary {
                    op: BinOp::Or,
                    lhs: Operand::Val(a),
                    rhs: Operand::Val(b),
                    ..
                }) => stack.extend([*a, *b]),
                Some(Kind::Binary {
                    op: BinOp::Eq,
                    lhs: p,
                    rhs: q,
                    ..
                }) => match (is_result(p), is_result(q)) {
                    (true, false) => options.push(q),
                    (false, true) => options.push(p),
                    _ => return None,
                },
                _ => return None,
            }
        }
    }
    (options.len() >= 2).then_some(options)
}

/// NUC-009, selection form: the result is pinned to one of several inputs and
/// compared in one direction with some of them but not all, so it can be an
/// input that is not the maximum (or minimum).
fn partial_selection(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if slice.truncated || hint.results.len() != 1 {
        return;
    }
    let linking: Vec<_> = touching(g, slice)
        .filter(|c| c.leaves.may_reach_beyond(hint.instr))
        .collect();
    let Some((select_at, options)) = linking
        .iter()
        .find_map(|c| selection(g, c.instr, hint.instr).map(|o| (c.instr, o)))
    else {
        return;
    };
    let mut directions = BTreeSet::new();
    let mut compared = Vec::new();
    for c in &linking {
        if c.instr == select_at {
            continue;
        }
        let Some((bound, other)) = comparison_with(g, c.instr, hint.instr) else {
            return;
        };
        directions.insert(bound == Bound::Upper);
        compared.push(g.leaves_of(other));
    }
    if directions.len() != 1 {
        return;
    }
    let missing = options
        .iter()
        .filter(|option| {
            let leaves = g.leaves_of(option);
            !compared
                .iter()
                .any(|c| c.exact().is_some() && c.exact() == leaves.exact())
        })
        .count();
    if missing == 0 || compared.is_empty() {
        return;
    }
    let upper = directions.contains(&true);
    let related = ctx.related(select_at, "pinned to one of the inputs here");
    ctx.push(
        "NUC-009",
        hint,
        format!(
            "the result of `{}` equals one of {} values but is compared with only {} of them, so it can be one that is not the {}",
            hint.callee,
            options.len(),
            options.len() - missing,
            if upper { "minimum" } else { "maximum" },
        ),
        related,
        false,
    );
}

/// NUC-009: every constraint tying the hint to its inputs is a comparison in the same direction.
fn one_directional_bound(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if !has_live_args(g, hint) || slice.truncated || used_as_index(g, slice, hint.instr) {
        return;
    }
    let linking: Vec<_> = touching(g, slice)
        .filter(|c| c.leaves.may_reach_beyond(hint.instr))
        .collect();
    let mut directions = BTreeSet::new();
    for c in &linking {
        match comparison_bound(g, c.instr, hint.instr) {
            Some(bound) => directions.insert(bound == Bound::Upper),
            None => return,
        };
    }
    if directions.len() != 1 {
        return;
    }
    let upper = directions.contains(&true);
    let related = ctx.related(
        linking[0].instr,
        if upper {
            "only bounded from above here"
        } else {
            "only bounded from below here"
        },
    );
    ctx.push(
        "NUC-009",
        hint,
        format!(
            "the result of `{}` is only bounded from {} by its inputs, so the prover can return any {} value",
            hint.callee,
            if upper { "above" } else { "below" },
            if upper { "smaller" } else { "larger" },
        ),
        related,
        false,
    );
}

/// NUC-005: a hint index reads an array, but nothing compares the element read to the needle.
fn unchecked_index(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if slice.truncated {
        return;
    }
    let needle = hint
        .args
        .iter()
        .filter(|a| {
            a.val()
                .and_then(|v| g.type_of(v))
                .is_some_and(|t| !is_array(t))
        })
        .fold(Leaves::default(), |acc, a| acc.union(&g.leaves_of(a)));
    if needle.is_empty() {
        return;
    }
    for pos in 0..hint.results.len() {
        let Some(bits) = hint.result_types.get(pos).and_then(|t| int_bits(t)) else {
            continue;
        };
        if bits == 1 {
            continue;
        }
        let leaf = Leaf::Hint {
            call: hint.instr,
            pos,
            elem: None,
        };
        let read_at = slice.instrs.iter().copied().find(|i| {
            matches!(&g.instrs[*i].kind, Kind::ArrayGet { array, index }
                if g.leaves_of(index).exact().is_some_and(|l| l.contains(&leaf))
                    && !g.leaves_of(array).is_empty()
                    && !g.leaves_of(array).may_touch_call(hint.instr))
        });
        let bounds = slice
            .constraints
            .iter()
            .map(|i| &g.constraints[*i])
            .find(|c| c.bounds_check && c.leaves.exact().is_some_and(|l| l.contains(&leaf)));
        let Some(read_idx) = read_at.or(bounds.map(|c| c.instr)) else {
            continue;
        };
        let compared = touching(g, slice)
            .any(|c| c.leaves.may_contain(&leaf) && c.leaves.may_intersect(&needle));
        if compared {
            continue;
        }
        let escapes = ctx.escapes([leaf]);
        let related = ctx.related(read_idx, "array read with the hinted index");
        ctx.push(
            "NUC-005",
            hint,
            format!(
                "the index returned by `{}` is used to read an array, but the element read is never compared to the value searched for",
                hint.callee
            ),
            related,
            escapes,
        );
    }
}

/// NUC-006: a hinted sorted array is checked for order but not permutation, or the reverse.
fn half_checked_sort(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if slice.truncated {
        return;
    }
    let inputs: Vec<(Leaves, &str)> = hint
        .args
        .iter()
        .filter_map(|a| {
            let typ = g.type_of(a.val()?)?;
            let leaves = g.leaves_of(a);
            (is_array(typ) && !leaves.is_empty() && !leaves.may_touch_call(hint.instr))
                .then_some((leaves, typ))
        })
        .collect();
    for (pos, typ) in hint.result_types.iter().enumerate() {
        let Some((input, _)) = inputs.iter().find(|(_, t)| *t == typ) else {
            continue;
        };
        let of_output = |op: &Operand| matches!(g.hint_value(op), Some(Leaf::Hint { call, pos: p, elem: Some(_) }) if call == hint.instr && p == pos);
        let order_check = comparisons(g, slice).find(|(_, lhs, rhs)| {
            of_output(lhs) && of_output(rhs) && g.hint_value(lhs) != g.hint_value(rhs)
        });
        let output_leaf = |l: &Leaf| matches!(l, Leaf::Hint { call, pos: p, .. } if *call == hint.instr && *p == pos);
        let mut permutation_maybe = false;
        let mut permutation_surely = false;
        let mut evidence = Vec::new();
        let mut opaque = false;
        for c in touching(g, slice) {
            match c.leaves.exact() {
                Some(leaves) => {
                    if leaves.iter().any(output_leaf) && c.leaves.may_intersect(input) {
                        permutation_maybe = true;
                        permutation_surely |= !input.is_many();
                        evidence.push(c.instr);
                    }
                }
                None => {
                    permutation_maybe = true;
                    opaque = true;
                }
            }
        }
        // An index map (outputs used to index arrays) is not itself a sorted array.
        let used_as_index = slice.instrs.iter().any(
            |i| matches!(&g.instrs[*i].kind, Kind::ArrayGet { index, .. } if of_output(index)),
        );
        // Sums of powers pin down n elements only when the sums of powers 1 to n
        // all match (Newton's identities); fewer leave other multisets possible.
        let weak_power_sums = (order_check.is_some() && permutation_surely && !opaque)
            .then(|| power_sums_only(g, hint.instr, pos, typ, &evidence))
            .flatten();
        let message = match (order_check, permutation_maybe, permutation_surely) {
            (Some(_), _, _) if weak_power_sums.is_some() => {
                let (powers, n) = weak_power_sums.expect("checked");
                format!(
                    "the array from `{}` is matched to the input only by its sums of powers {powers}; a permutation of {n} elements needs the sums of powers 1 to {n}",
                    hint.callee
                )
            }
            (Some(_), false, _) => format!(
                "the array from `{}` is checked to be ordered but never shown to be a permutation of the input",
                hint.callee
            ),
            (None, _, true)
                if !used_as_index && hint.callee.to_ascii_lowercase().contains("sort") =>
            {
                format!(
                    "the array from `{}` is checked against the input but its order is never checked",
                    hint.callee
                )
            }
            _ => continue,
        };
        let related = match order_check {
            Some((idx, _, _)) => ctx.related(idx, "order checked here"),
            None => Vec::new(),
        };
        ctx.push("NUC-006", hint, message, related, false);
    }
}

/// The exponents, when every constraint relating result `pos` of hint `call` to
/// its input is a power sum `c·Σ s[i]^k` plus terms free of the result, and
/// they are not all of 1 to n; `None` otherwise.
fn power_sums_only(
    g: &Graph,
    call: usize,
    pos: usize,
    typ: &str,
    evidence: &[usize],
) -> Option<(String, u64)> {
    let n = array_len(typ)?;
    if n < 2 || evidence.is_empty() {
        return None;
    }
    let mut powers = BTreeSet::new();
    for idx in evidence {
        powers.insert(power_sum_exponent(g, call, pos, n, &g.equation(*idx)?)?);
    }
    if (1..=n).all(|k| powers.contains(&(k as u32))) {
        return None;
    }
    let list: Vec<String> = powers.iter().map(u32::to_string).collect();
    Some((list.join(" and "), n))
}

/// `k` when the equation's terms on the result are `c·s[i]^k` for each of
/// its `n` elements, with one `c` and one `k`.
fn power_sum_exponent(g: &Graph, call: usize, pos: usize, n: u64, eq: &Linear) -> Option<u32> {
    let mut seen: std::collections::BTreeMap<u64, (u32, &BigInt)> = Default::default();
    let touches = |v: Val| g.leaves_of_val(v).may_touch_call(call);
    for (atom, coeff) in &eq.terms {
        let power = match atom {
            Atom::Value(v) => output_power(g, call, pos, *v, 0),
            Atom::Product(a, b) => {
                match (
                    output_power(g, call, pos, *a, 0),
                    output_power(g, call, pos, *b, 0),
                ) {
                    (Some((ea, ka)), Some((eb, kb))) if ea == eb => Some((ea, ka + kb)),
                    (None, None) => None,
                    _ => return None,
                }
            }
        };
        match (power, atom) {
            (Some((elem, k)), _) => {
                if seen.insert(elem, (k, coeff)).is_some() {
                    return None;
                }
            }
            // Terms free of the result (the input side) can be anything.
            (None, Atom::Value(v)) if !touches(*v) => {}
            (None, Atom::Product(a, b)) if !touches(*a) && !touches(*b) => {}
            (None, _) => return None,
        }
    }
    let mut terms = seen.values();
    let (k, c) = terms.next()?;
    (seen.len() as u64 == n && terms.all(|(k2, c2)| k2 == k && c2 == c)).then_some(*k)
}

/// `(i, k)` when `v` is `s[i]^k` for element `i` of result `pos` of hint `call`.
fn output_power(g: &Graph, call: usize, pos: usize, v: Val, depth: u32) -> Option<(u64, u32)> {
    if depth > 8 {
        return None;
    }
    let v = g.strip_casts(v);
    if let Some(Leaf::Hint {
        call: c,
        pos: p,
        elem: Some(elem),
    }) = g.hint_value(&Operand::Val(v))
    {
        return (c == call && p == pos).then_some((elem, 1));
    }
    match &g.def(v)?.kind {
        Kind::Binary {
            op: BinOp::Mul,
            lhs: Operand::Val(a),
            rhs: Operand::Val(b),
            ..
        } => {
            let (ea, ka) = output_power(g, call, pos, *a, depth + 1)?;
            let (eb, kb) = output_power(g, call, pos, *b, depth + 1)?;
            (ea == eb).then_some((ea, ka + kb))
        }
        _ => None,
    }
}

/// NUC-006, index form: a hinted array of indices reads every position of an
/// array of its own length (a permutation given as indices), but nothing shows
/// the indices are distinct, so one element can be read twice and another
/// skipped. Distinctness shows as a constraint on two of the indices
/// (`idx[i] != idx[j]`) or as a read of the index array at a hinted position
/// (the inverse-map check of `std`'s `check_shuffle`).
fn indices_not_distinct(ctx: &mut Ctx, hint: &HintCall, slice: &HintSlice) {
    let g = ctx.g;
    if slice.truncated {
        return;
    }
    for (pos, typ) in hint.result_types.iter().enumerate() {
        let Some(n) = array_len(typ).filter(|n| *n >= 2) else {
            continue;
        };
        if !typ.starts_with("[u") {
            continue;
        }
        let Some(result) = hint.results.get(pos) else {
            continue;
        };
        let elem_of = |op: &Operand| match g.hint_value(op) {
            Some(Leaf::Hint {
                call,
                pos: p,
                elem: Some(e),
            }) if call == hint.instr && p == pos => Some(e),
            _ => None,
        };
        let mut reads: std::collections::BTreeMap<Val, BTreeSet<u64>> = Default::default();
        let mut inverse_read = false;
        for i in &slice.instrs {
            let Kind::ArrayGet { array, index } = &g.instrs[*i].kind else {
                continue;
            };
            if array.val() == Some(*result) && index.constant().is_none() {
                inverse_read = true;
            }
            if let (Some(e), Some(target)) = (elem_of(index), array.val()) {
                reads.entry(target).or_default().insert(e);
            }
        }
        let permutes = reads.iter().any(|(target, elems)| {
            elems.len() as u64 == n
                && g.type_of(*target).and_then(array_len) == Some(n)
                && !g.leaves_of_val(*target).may_touch_call(hint.instr)
        });
        if !permutes || inverse_read {
            continue;
        }
        let relates_two = touching(g, slice).any(|c| {
            let mut elems = BTreeSet::new();
            for op in g.instrs[c.instr].kind.operands() {
                index_elems(g, op, &elem_of, &mut elems, 0);
            }
            elems.len() >= 2
        });
        if relates_two {
            continue;
        }
        ctx.push(
            "NUC-006",
            hint,
            format!(
                "the indices from `{}` read all {n} positions of an array but are never shown to be distinct, so one element can be read twice and another skipped",
                hint.callee
            ),
            Vec::new(),
            false,
        );
    }
}

/// The index elements `op` is computed from directly, through arithmetic and
/// comparisons but not through array reads.
fn index_elems(
    g: &Graph,
    op: &Operand,
    elem_of: &dyn Fn(&Operand) -> Option<u64>,
    out: &mut BTreeSet<u64>,
    depth: u32,
) {
    if let Some(e) = elem_of(op) {
        out.insert(e);
        return;
    }
    let Some(v) = op.val() else {
        return;
    };
    if depth > 4 {
        return;
    }
    let Some(instr) = g.def(v) else {
        return;
    };
    if matches!(
        instr.kind,
        Kind::Binary { .. } | Kind::Not(_) | Kind::Cast { .. }
    ) {
        for inner in instr.kind.operands() {
            index_elems(g, inner, elem_of, out, depth + 1);
        }
    }
}

/// Bit width of the BN254 scalar field, the `max_bit_size` of a `Field` truncation.
const FIELD_BITS: u32 = 254;

/// NUC-007: `truncate` of a non-constant `Field` that nothing range checks first.
fn narrowing_casts(ctx: &mut Ctx) {
    let g = ctx.g;
    for instr in &g.instrs {
        // A source-level `Field as uN` truncates from the full field width; the
        // compiler's own truncations (signed arithmetic lowering) use narrower ones.
        let Kind::Truncate {
            value: Operand::Val(x),
            bits,
            max_bits: FIELD_BITS,
        } = &instr.kind
        else {
            continue;
        };
        if !g.type_of(*x).is_some_and(is_field) || g.leaves_of_val(*x).is_empty() {
            continue;
        }
        let Some(result) = instr.results.first() else {
            continue;
        };
        let cast =
            g.uses
                .get(result)
                .into_iter()
                .flatten()
                .find_map(|u| match &g.instrs[*u].kind {
                    Kind::Cast { typ, .. } if int_bits(typ) == Some(*bits) => Some(typ.clone()),
                    _ => None,
                });
        let Some(target) = cast else { continue };
        if g.proven_bits(*x).is_some_and(|b| b <= *bits) {
            continue;
        }
        let Some(loc) = instr.loc.clone() else {
            continue;
        };
        ctx.findings.push(Finding {
            rule: "NUC-007",
            message: format!(
                "a `Field` is cast to `{target}` without a range check, so its high bits are silently dropped"
            ),
            loc: Some(loc),
            related: Vec::new(),
            entry: String::new(),
            package: String::new(),
            fingerprint: String::new(),
            escapes: false,
        });
    }
}
