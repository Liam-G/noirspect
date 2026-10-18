//! The rule catalogue and the SSA-level rules.

use crate::graph::{Atom, ConstraintKind, Graph, HintCall, Leaf, Leaves, ratio_bits};
use crate::ssa::{BinOp, Kind, Loc, Operand, int_bits, is_array, is_field};
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

pub const RULES: [Rule; 8] = [
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
        summary: "Limbs or bits from a hint are recombined into an input, but a limb is not range checked to its width, so the decomposition is not unique.",
        remediation: "Range check every limb to its width (`assert_max_bit_size`, a `u8`/`bool` hint return type, or `b * (1 - b) == 0` for bits).",
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
        summary: "A sorted array from a hint is checked for order but not shown to be a permutation of the input (or the reverse).",
        remediation: "Check both properties: adjacent elements are ordered, and the output is a permutation of the input (for example with a hinted index map checked element by element).",
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

impl Ctx<'_, '_> {
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
            escapes,
        });
    }

    fn escapes(&self, leaves: impl IntoIterator<Item = Leaf>) -> bool {
        leaves
            .into_iter()
            .any(|l| self.returned.contains(&l) || self.returned.contains(&base(l)))
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
    for hint in &g.hints {
        constant_only(&mut ctx, hint);
        one_sided_is_zero(&mut ctx, hint);
        inverse_only_is_zero(&mut ctx, hint);
        unchecked_index(&mut ctx, hint);
        half_checked_sort(&mut ctx, hint);
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

/// NUC-001: every constraint touching the hint involves only the hint and constants.
fn constant_only(ctx: &mut Ctx, hint: &HintCall) {
    let g = ctx.g;
    if !has_live_args(g, hint) {
        return;
    }
    // A hinted index is NUC-005's concern.
    let used_as_index = g.instrs.iter().any(|i| {
        matches!(&i.kind, Kind::ArrayGet { index, .. } if g.touches_call(&g.leaves_of(index), hint.instr))
    }) || g.constraints.iter().any(|c| c.bounds_check && g.touches_call(&c.leaves, hint.instr));
    if used_as_index {
        return;
    }
    let touching: Vec<_> = g
        .constraints
        .iter()
        .filter(|c| !c.bounds_check && g.touches_call(&c.leaves, hint.instr))
        .collect();
    if touching.is_empty() {
        return;
    }
    // Linked: some constraint involves an input or another hint. Two of the
    // hint's own values compared to each other (an order check) is not a
    // constant-only check either; NUC-006 covers that shape.
    let linked = touching
        .iter()
        .any(|c| c.leaves.iter().any(|l| l.hint_call() != Some(hint.instr)) || c.leaves.len() > 1);
    if linked {
        return;
    }
    let related = ctx.related(touching[0].instr, "only checked against a constant here");
    ctx.push(
        "NUC-001",
        hint,
        format!(
            "the result of `{}` is only compared to constants; no constraint ties it to the inputs it was computed from",
            hint.callee
        ),
        related,
        false,
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
            if d_leaves.is_empty() || g.touches_call(&d_leaves, call) {
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
                    && !g
                        .atom_leaves(other)
                        .iter()
                        .any(|l| l.hint_call() == Some(call))
            });
            if !rest_from_outside {
                continue;
            }
            if remainder_is_bounded(g, r, d, idx) {
                return;
            }
            let hint = g
                .hints
                .iter()
                .find(|h| h.instr == call)
                .expect("hint call")
                .clone();
            let escapes = ctx.escapes([r_leaf]);
            let related = ctx.related(idx, "recombined here without bounding the remainder");
            ctx.push(
                "NUC-002",
                &hint,
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

fn derived_from(g: &Graph, op: &Operand, target: &Leaves) -> bool {
    let leaves = g.leaves_of(op);
    !target.is_empty() && target.is_subset(&leaves)
}

/// `r < d` in some form: a comparison, a checked unsigned `d - r`, or (for
/// multi-limb code such as bignum `validate_gt`) any other equality or range
/// constraint relating the two, except a comparison the wrong way round.
fn remainder_is_bounded(
    g: &Graph,
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
        derived_from(g, lhs, &d_leaves) && derived_from(g, rhs, &r_leaves)
    };
    let related = g.constraints.iter().any(|c| {
        let relates = c.instr != recombination
            && !c.bounds_check
            && c.kind != ConstraintKind::NotEqual
            && r_leaves.is_subset(&c.leaves)
            && d_leaves.is_subset(&c.leaves);
        relates
            && match &g.instrs[c.instr].kind {
                Kind::Constrain { lhs, rhs, .. } => !wrong_way(lhs) && !wrong_way(rhs),
                _ => true,
            }
    });
    if related {
        return true;
    }
    let compares = g.comparisons().any(|(_, lhs, rhs)| {
        derived_from(g, lhs, &r_leaves)
            && derived_from(g, rhs, &d_leaves)
            && !g.touches_call(&g.leaves_of(rhs), r_call(g, r))
    });
    let subtracts = g.instrs.iter().any(|i| match &i.kind {
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
            unsigned && derived_from(g, lhs, &d_leaves) && derived_from(g, rhs, &r_leaves)
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
                None => limb_bound(g, *v).is_some() || is_bounded_by_comparison(g, *v),
            };
            if !ok {
                unchecked.push(*leaf);
            }
        }
        if unchecked.is_empty() {
            continue;
        }
        let hint = g
            .hints
            .iter()
            .find(|h| h.instr == call)
            .expect("hint call")
            .clone();
        let escapes = ctx.escapes(unchecked.iter().copied());
        let related = ctx.related(idx, "recombined here");
        ctx.push(
            "NUC-003",
            &hint,
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

/// Bits a limb is proven to fit in: its type, a range check, or a boolean check.
fn limb_bound(g: &Graph, v: crate::ssa::Val) -> Option<u32> {
    let mut best = g.proven_bits(v);
    let stripped = g.strip_casts(v);
    let boolean = g
        .constraints
        .iter()
        .any(|c| g.is_boolean_check(c.instr) == Some(stripped));
    if boolean {
        best = Some(1);
    }
    if let Some(bits) = g.proven_bits(stripped) {
        best = Some(best.map_or(bits, |b| b.min(bits)));
    }
    best
}

fn is_bounded_by_comparison(g: &Graph, v: crate::ssa::Val) -> bool {
    let leaves = g.leaves_of_val(v);
    g.comparisons()
        .any(|(_, lhs, rhs)| g.leaves_of(lhs) == leaves || g.leaves_of(rhs) == leaves)
}

/// NUC-004: `x · flag == 0` is the only constraint tying the hint to `x`.
fn one_sided_is_zero(ctx: &mut Ctx, hint: &HintCall) {
    let g = ctx.g;
    for c in &g.constraints {
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
            if x_leaves.is_empty() || g.touches_call(&x_leaves, hint.instr) {
                continue;
            }
            let other_checks = g.constraints.iter().any(|o| {
                o.instr != c.instr
                    && !o.bounds_check
                    && !matches!(o.kind, ConstraintKind::Range(_))
                    && g.touches_call(&o.leaves, hint.instr)
                    && g.is_boolean_check(o.instr).is_none()
            });
            if other_checks {
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
fn inverse_only_is_zero(ctx: &mut Ctx, hint: &HintCall) {
    let g = ctx.g;
    for c in &g.constraints {
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
                && !g.touches_call(&x_leaves, hint.instr)
        });
        if shape.is_none() {
            continue;
        }
        let other_checks = g.constraints.iter().any(|o| {
            o.instr != c.instr
                && !o.bounds_check
                && !matches!(o.kind, ConstraintKind::Range(_))
                && g.touches_call(&o.leaves, hint.instr)
                && g.is_boolean_check(o.instr).is_none()
        });
        if other_checks {
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

/// NUC-005: a hint index reads an array, but nothing compares the element read to the needle.
fn unchecked_index(ctx: &mut Ctx, hint: &HintCall) {
    let g = ctx.g;
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
        let mut read_at = None;
        for (idx, instr) in g.instrs.iter().enumerate() {
            if let Kind::ArrayGet { array, index } = &instr.kind
                && g.leaves_of(index).contains(&leaf)
                && !g.leaves_of(array).is_empty()
                && !g.touches_call(&g.leaves_of(array), hint.instr)
            {
                read_at.get_or_insert(idx);
            }
        }
        let bounds = g
            .constraints
            .iter()
            .find(|c| c.bounds_check && c.leaves.contains(&leaf));
        let Some(read_idx) = read_at.or(bounds.map(|c| c.instr)) else {
            continue;
        };
        let needle: Leaves = hint
            .args
            .iter()
            .filter(|a| {
                a.val()
                    .and_then(|v| g.type_of(v))
                    .is_some_and(|t| !is_array(t))
            })
            .flat_map(|a| g.leaves_of(a))
            .collect();
        if needle.is_empty() {
            continue;
        }
        let compared = g.constraints.iter().any(|c| {
            !c.bounds_check
                && c.leaves.contains(&leaf)
                && c.leaves.iter().any(|l| needle.contains(l))
        });
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
fn half_checked_sort(ctx: &mut Ctx, hint: &HintCall) {
    let g = ctx.g;
    let inputs: Vec<(Leaves, &str)> = hint
        .args
        .iter()
        .filter_map(|a| {
            let typ = g.type_of(a.val()?)?;
            let leaves = g.leaves_of(a);
            (is_array(typ) && !leaves.is_empty() && !g.touches_call(&leaves, hint.instr))
                .then_some((leaves, typ))
        })
        .collect();
    for (pos, typ) in hint.result_types.iter().enumerate() {
        let Some((input, _)) = inputs.iter().find(|(_, t)| *t == typ) else {
            continue;
        };
        let of_output = |op: &Operand| matches!(g.hint_value(op), Some(Leaf::Hint { call, pos: p, elem: Some(_) }) if call == hint.instr && p == pos);
        let order_check = g.comparisons().find(|(_, lhs, rhs)| {
            of_output(lhs) && of_output(rhs) && g.hint_value(lhs) != g.hint_value(rhs)
        });
        let touches_output = |leaves: &Leaves| {
            leaves.iter().any(|l| matches!(l, Leaf::Hint { call, pos: p, .. } if *call == hint.instr && *p == pos))
        };
        let permutation = g.constraints.iter().any(|c| {
            !c.bounds_check
                && touches_output(&c.leaves)
                && c.leaves.iter().any(|l| input.contains(l))
        });
        // An index map (outputs used to index arrays) is not itself a sorted array.
        let used_as_index = g
            .instrs
            .iter()
            .any(|i| matches!(&i.kind, Kind::ArrayGet { index, .. } if of_output(index)));
        let message = match (order_check, permutation) {
            (Some(_), false) => format!(
                "the array from `{}` is checked to be ordered but never shown to be a permutation of the input",
                hint.callee
            ),
            (None, true) if !used_as_index && hint.callee.to_ascii_lowercase().contains("sort") => {
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
            escapes: false,
        });
    }
}
