//! Data-flow facts about one constrained (ACIR) SSA function.
//!
//! Every value is traced back to its *leaves*: the circuit inputs and the
//! results of unconstrained hint calls it was computed from. A constraint
//! "touches" a hint when one of the hint's leaves is among the constraint's
//! leaves. Rules are written against these facts and against linear views of
//! constraint expressions.

use crate::ssa::{BinOp, Function, Instr, Kind, Operand, Program, Val, int_bits};
use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Leaf {
    /// A function parameter or another value of unknown origin.
    Input(Val),
    /// Result `pos` of the hint call at instruction `call`, optionally one array element.
    Hint {
        call: usize,
        pos: usize,
        elem: Option<u64>,
    },
}

impl Leaf {
    pub fn hint_call(&self) -> Option<usize> {
        match self {
            Leaf::Hint { call, .. } => Some(*call),
            Leaf::Input(_) => None,
        }
    }
}

pub type Leaves = BTreeSet<Leaf>;

#[derive(Debug, Clone)]
pub struct HintCall {
    pub instr: usize,
    pub callee: String,
    pub args: Vec<Operand>,
    pub results: Vec<Val>,
    pub result_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintKind {
    Equal,
    NotEqual,
    Range(u32),
}

#[derive(Debug, Clone)]
pub struct Constraint {
    pub instr: usize,
    pub kind: ConstraintKind,
    pub leaves: Leaves,
    /// The compiler's own array bounds check, which says nothing about intent.
    pub bounds_check: bool,
}

/// `Σ coeff·atom + constant`, where an atom is a value or a product of two values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Linear {
    pub terms: BTreeMap<Atom, BigInt>,
    pub constant: BigInt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Atom {
    Value(Val),
    Product(Val, Val),
}

impl Linear {
    fn constant(value: BigInt) -> Self {
        Linear {
            terms: BTreeMap::new(),
            constant: value,
        }
    }

    fn atom(atom: Atom) -> Self {
        let mut terms = BTreeMap::new();
        terms.insert(atom, BigInt::one());
        Linear {
            terms,
            constant: BigInt::zero(),
        }
    }

    fn add_scaled(&mut self, other: &Linear, scale: &BigInt) {
        for (atom, coeff) in &other.terms {
            let entry = self.terms.entry(*atom).or_default();
            *entry += coeff * scale;
        }
        self.terms.retain(|_, c| !c.is_zero());
        self.constant += &other.constant * scale;
    }

    fn scaled(&self, scale: &BigInt) -> Linear {
        let mut out = Linear::default();
        out.add_scaled(self, scale);
        out
    }
}

pub struct Graph<'a> {
    pub func: &'a Function,
    pub instrs: Vec<&'a Instr>,
    pub defs: HashMap<Val, (usize, usize)>,
    pub types: HashMap<Val, String>,
    pub leaves: HashMap<Val, Leaves>,
    pub hints: Vec<HintCall>,
    pub constraints: Vec<Constraint>,
    pub uses: HashMap<Val, Vec<usize>>,
    linear_cache: std::cell::RefCell<HashMap<Val, Linear>>,
    linear_depth: std::cell::Cell<usize>,
}

const LINEAR_MAX_TERMS: usize = 512;
const LINEAR_MAX_DEPTH: usize = 1024;

impl<'a> Graph<'a> {
    pub fn build(program: &'a Program, func: &'a Function) -> Graph<'a> {
        let instrs: Vec<&Instr> = func.blocks.iter().flat_map(|b| &b.instructions).collect();
        let mut graph = Graph {
            func,
            instrs,
            defs: HashMap::new(),
            types: HashMap::new(),
            leaves: HashMap::new(),
            hints: Vec::new(),
            constraints: Vec::new(),
            uses: HashMap::new(),
            linear_cache: Default::default(),
            linear_depth: Default::default(),
        };
        for block in &func.blocks {
            for (val, typ) in &block.params {
                graph.types.insert(*val, typ.clone());
                graph.leaves.insert(*val, Leaves::from([Leaf::Input(*val)]));
            }
        }
        for idx in 0..graph.instrs.len() {
            graph.visit(program, idx);
        }
        graph
    }

    fn visit(&mut self, program: &Program, idx: usize) {
        let instr = self.instrs[idx];
        for (pos, result) in instr.results.iter().enumerate() {
            self.defs.insert(*result, (idx, pos));
            if let Some(typ) = instr.result_types.get(pos) {
                self.types.insert(*result, typ.clone());
            }
        }
        for op in instr.kind.operands() {
            if let Some(v) = op.val() {
                self.uses.entry(v).or_default().push(idx);
            }
        }
        if let Some(result) = instr.results.first()
            && instr.result_types.is_empty()
            && let Some(typ) = self.infer_type(&instr.kind)
        {
            self.types.insert(*result, typ);
        }

        let is_hint = matches!(&instr.kind, Kind::Call { func: Operand::Func(f), .. } if program.is_brillig(f));
        if let (
            true,
            Kind::Call {
                func: Operand::Func(f),
                args,
            },
        ) = (is_hint, &instr.kind)
        {
            for (pos, result) in instr.results.iter().enumerate() {
                self.leaves.insert(
                    *result,
                    Leaves::from([Leaf::Hint {
                        call: idx,
                        pos,
                        elem: None,
                    }]),
                );
            }
            let callee = program
                .functions
                .get(f)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| f.clone());
            self.hints.push(HintCall {
                instr: idx,
                callee,
                args: args.clone(),
                results: instr.results.clone(),
                result_types: instr.result_types.clone(),
            });
            return;
        }

        let derived = match &instr.kind {
            Kind::ArrayGet { array, index } => match (self.hint_value(array), index.constant()) {
                (
                    Some(Leaf::Hint {
                        call,
                        pos,
                        elem: None,
                    }),
                    Some(i),
                ) => {
                    let elem = u64::try_from(i).ok();
                    Leaves::from([Leaf::Hint { call, pos, elem }])
                }
                _ => self.union_of(&[array, index]),
            },
            Kind::Constrain { lhs, rhs, .. } | Kind::ConstrainNotEqual { lhs, rhs, .. } => {
                self.union_of(&[lhs, rhs])
            }
            Kind::Call { args, .. } => self.union_of(&args.iter().collect::<Vec<_>>()),
            kind => self.union_of(&kind.operands()),
        };

        match &instr.kind {
            Kind::Constrain { msg, .. } => self.constraints.push(Constraint {
                instr: idx,
                kind: ConstraintKind::Equal,
                bounds_check: msg.as_deref().is_some_and(|m| m.contains("out of bounds")),
                leaves: derived.clone(),
            }),
            Kind::ConstrainNotEqual { .. } => self.constraints.push(Constraint {
                instr: idx,
                kind: ConstraintKind::NotEqual,
                bounds_check: false,
                leaves: derived.clone(),
            }),
            Kind::RangeCheck { bits, .. } => self.constraints.push(Constraint {
                instr: idx,
                kind: ConstraintKind::Range(*bits),
                bounds_check: false,
                leaves: derived.clone(),
            }),
            _ => {}
        }
        for result in &instr.results {
            self.leaves.insert(*result, derived.clone());
        }
    }

    /// The printer omits result types for most instructions; recover them from operands.
    fn infer_type(&self, kind: &Kind) -> Option<String> {
        let of = |op: &Operand| match op {
            Operand::Val(v) => self.types.get(v).cloned(),
            Operand::Const { typ, .. } => Some(typ.clone()),
            _ => None,
        };
        match kind {
            Kind::Cast { typ, .. } => Some(typ.clone()),
            Kind::Binary {
                op: BinOp::Eq | BinOp::Lt,
                ..
            } => Some("u1".to_string()),
            Kind::Binary { lhs, rhs, .. } => of(lhs).or_else(|| of(rhs)),
            Kind::Not(value) | Kind::Truncate { value, .. } => of(value),
            Kind::IfElse {
                then_val, else_val, ..
            } => of(then_val).or_else(|| of(else_val)),
            _ => None,
        }
    }

    fn union_of(&self, ops: &[&Operand]) -> Leaves {
        let mut out = Leaves::new();
        for op in ops {
            if let Some(v) = op.val() {
                out.extend(self.leaves_of_val(v));
            }
        }
        out
    }

    pub fn leaves_of_val(&self, v: Val) -> Leaves {
        match self.leaves.get(&v) {
            Some(l) => l.clone(),
            // Globals and values without a known definition are constants or inputs.
            None if v.global => Leaves::new(),
            None => Leaves::from([Leaf::Input(v)]),
        }
    }

    pub fn leaves_of(&self, op: &Operand) -> Leaves {
        op.val().map(|v| self.leaves_of_val(v)).unwrap_or_default()
    }

    pub fn def(&self, v: Val) -> Option<&'a Instr> {
        self.defs.get(&v).map(|(idx, _)| self.instrs[*idx])
    }

    /// Follow casts back to the value they were made from.
    pub fn strip_casts(&self, mut v: Val) -> Val {
        while let Some(Kind::Cast {
            value: Operand::Val(inner),
            ..
        }) = self.def(v).map(|i| &i.kind)
        {
            v = *inner;
        }
        v
    }

    /// The hint leaf `op` *is* (possibly through casts and a constant-index array read).
    pub fn hint_value(&self, op: &Operand) -> Option<Leaf> {
        let v = self.strip_casts(op.val()?);
        let leaves = self.leaves.get(&v)?;
        if leaves.len() != 1 {
            return None;
        }
        let leaf = *leaves.iter().next()?;
        let direct = match self.defs.get(&v) {
            Some((idx, _)) => match &self.instrs[*idx].kind {
                Kind::Call { .. } => true,
                Kind::ArrayGet { index, .. } => index.constant().is_some(),
                _ => false,
            },
            None => false,
        };
        (direct && leaf.hint_call().is_some()).then_some(leaf)
    }

    pub fn type_of(&self, v: Val) -> Option<&str> {
        self.types.get(&v).map(String::as_str)
    }

    /// The tightest bit width the value's own type or a range check proves.
    pub fn proven_bits(&self, v: Val) -> Option<u32> {
        let mut best: Option<u32> = None;
        let mut consider = |bits: u32| best = Some(best.map_or(bits, |b: u32| b.min(bits)));
        let mut current = Some(v);
        while let Some(value) = current {
            // Integer-typed values are always in range in ACIR: inputs through the
            // ABI, hint outputs through generated range checks, arithmetic through
            // overflow checks.
            if let Some(bits) = self.type_of(value).and_then(int_bits) {
                consider(bits);
            }
            for idx in self.uses.get(&value).into_iter().flatten() {
                if let Kind::RangeCheck {
                    value: Operand::Val(checked),
                    bits,
                    ..
                } = &self.instrs[*idx].kind
                    && *checked == value
                {
                    consider(*bits);
                }
            }
            current = match self.def(value).map(|i| &i.kind) {
                Some(Kind::Cast {
                    value: Operand::Val(inner),
                    ..
                }) => Some(*inner),
                _ => None,
            };
        }
        // A range check on a cast of the value bounds the value too.
        for idx in self.uses.get(&v).into_iter().flatten() {
            if let Kind::Cast { .. } = &self.instrs[*idx].kind
                && let Some(result) = self.instrs[*idx].results.first()
            {
                for use_idx in self.uses.get(result).into_iter().flatten() {
                    if let Kind::RangeCheck { bits, .. } = &self.instrs[*use_idx].kind {
                        consider(*bits);
                    }
                }
            }
        }
        best
    }

    /// Linear view of a value, looking through additions, subtractions,
    /// scaling by constants and casts.
    pub fn linear(&self, op: &Operand) -> Linear {
        match op {
            Operand::Const { value, .. } => Linear::constant(value.clone()),
            Operand::Val(v) => self.linear_val(*v),
            _ => Linear::default(),
        }
    }

    fn linear_val(&self, v: Val) -> Linear {
        if let Some(cached) = self.linear_cache.borrow().get(&v) {
            return cached.clone();
        }
        // Long unrolled accumulations would recurse once per addition; past
        // the limit the value is an opaque term (decompositions are far shorter).
        if self.linear_depth.get() >= LINEAR_MAX_DEPTH {
            return Linear::atom(Atom::Value(v));
        }
        self.linear_depth.set(self.linear_depth.get() + 1);
        let result = self.compute_linear(v);
        self.linear_depth.set(self.linear_depth.get() - 1);
        self.linear_cache.borrow_mut().insert(v, result.clone());
        result
    }

    fn compute_linear(&self, v: Val) -> Linear {
        let Some(instr) = self.def(v) else {
            return Linear::atom(Atom::Value(v));
        };
        let lin = match &instr.kind {
            Kind::Cast { value, .. } => match value {
                Operand::Val(inner) => self.linear_val(*inner),
                other => self.linear(other),
            },
            Kind::Binary {
                op: BinOp::Add,
                lhs,
                rhs,
                ..
            } => {
                let mut out = self.linear(lhs);
                out.add_scaled(&self.linear(rhs), &BigInt::one());
                out
            }
            Kind::Binary {
                op: BinOp::Sub,
                lhs,
                rhs,
                ..
            } => {
                let mut out = self.linear(lhs);
                out.add_scaled(&self.linear(rhs), &-BigInt::one());
                out
            }
            Kind::Binary {
                op: BinOp::Mul,
                lhs,
                rhs,
                ..
            } => match (lhs.constant(), rhs.constant()) {
                (Some(c), _) => self.linear(rhs).scaled(c),
                (_, Some(c)) => self.linear(lhs).scaled(c),
                _ => {
                    let a = self.strip_casts(lhs.val().unwrap_or(v));
                    let b = self.strip_casts(rhs.val().unwrap_or(v));
                    Linear::atom(Atom::Product(a.min(b), a.max(b)))
                }
            },
            _ => Linear::atom(Atom::Value(v)),
        };
        if lin.terms.len() > LINEAR_MAX_TERMS {
            Linear::atom(Atom::Value(v))
        } else {
            lin
        }
    }

    /// `lhs - rhs` of an equality constraint.
    pub fn equation(&self, idx: usize) -> Option<Linear> {
        let Kind::Constrain { lhs, rhs, .. } = &self.instrs[idx].kind else {
            return None;
        };
        let mut eq = self.linear(lhs);
        eq.add_scaled(&self.linear(rhs), &-BigInt::one());
        Some(eq)
    }

    pub fn atom_leaves(&self, atom: &Atom) -> Leaves {
        match atom {
            Atom::Value(v) => self.leaves_of_val(*v),
            Atom::Product(a, b) => {
                let mut out = self.leaves_of_val(*a);
                out.extend(self.leaves_of_val(*b));
                out
            }
        }
    }

    pub fn touches_call(&self, leaves: &Leaves, call: usize) -> bool {
        leaves.iter().any(|l| l.hint_call() == Some(call))
    }

    /// Leaves reaching any return value.
    pub fn returned_leaves(&self) -> Leaves {
        self.func
            .returns()
            .into_iter()
            .flat_map(|op| self.leaves_of(op))
            .collect()
    }

    /// The value `x` when the constraint forces `x ∈ {0, 1}`: `x·x - x = 0`,
    /// `x·(1 - x) = 0` or `x·(x - 1) = 0`, in any scaling.
    pub fn is_boolean_check(&self, idx: usize) -> Option<Val> {
        let eq = self.equation(idx)?;
        if !eq.constant.is_zero() {
            return None;
        }
        match eq.terms.len() {
            2 => {
                let mut square = None;
                let mut linear = None;
                for (atom, coeff) in &eq.terms {
                    match atom {
                        Atom::Product(a, b) if a == b => square = Some((*a, coeff.clone())),
                        Atom::Value(v) => linear = Some((self.strip_casts(*v), coeff.clone())),
                        _ => {}
                    }
                }
                let ((sq, c1), (lin, c2)) = (square?, linear?);
                (sq == lin && (&c1 + &c2).is_zero()).then_some(sq)
            }
            1 => {
                let (Atom::Product(a, b), _) = eq.terms.iter().next()? else {
                    return None;
                };
                [(*a, *b), (*b, *a)].into_iter().find_map(|(x, other)| {
                    // `other` must be `±(x - 1)`.
                    let lin = self.linear_val(other);
                    let coeff = lin.terms.get(&Atom::Value(x))?;
                    (lin.terms.len() == 1 && (coeff + &lin.constant).is_zero() && !coeff.is_zero())
                        .then_some(x)
                })
            }
            _ => None,
        }
    }

    pub fn loc(&self, idx: usize) -> Option<&crate::ssa::Loc> {
        self.instrs[idx].loc.as_ref()
    }

    /// Every `lt` comparison, as (instruction index, lhs, rhs).
    pub fn comparisons(&self) -> impl Iterator<Item = (usize, &Operand, &Operand)> + '_ {
        self.instrs
            .iter()
            .enumerate()
            .filter_map(|(idx, instr)| match &instr.kind {
                Kind::Binary {
                    op: BinOp::Lt,
                    lhs,
                    rhs,
                    ..
                } => Some((idx, lhs, rhs)),
                _ => None,
            })
    }
}

/// Ratio `hi / lo` rounded up, as a bit width when it is a power of two.
pub fn ratio_bits(lo: &BigInt, hi: &BigInt) -> Option<u32> {
    if lo.is_zero() {
        return None;
    }
    let (lo, hi) = (lo.abs(), hi.abs());
    if &hi % &lo != BigInt::zero() {
        return None;
    }
    let ratio = hi / lo;
    let bits = ratio.bits();
    (ratio == BigInt::one() << (bits - 1)).then(|| (bits - 1) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::parse_program;

    fn graph_of(text: &str) -> (Program, String) {
        (parse_program(text), "f0".to_string())
    }

    const SAMPLE: &str = "acir(inline) fn main f0 {
  b0(v0: Field, v1: Field):
    v2 = call f1(v0) -> (Field, Field)
    v3 = mul v1, Field 4
    v4 = sub v0, v3
    v5 = mul v2, v2
    constrain v5 == v2
    v6 = sub Field 1, v2
    v7 = mul v2, v6
    constrain v7 == Field 0
    constrain v4 == v1
    return
}
brillig(inline) fn hint f1 {
  b0(v0: Field):
    return v0, v0
}
";

    #[test]
    fn traces_leaves_and_linear_forms() {
        let (program, id) = graph_of(SAMPLE);
        let g = Graph::build(&program, &program.functions[&id]);
        assert_eq!(g.hints.len(), 1);
        let v2 = Val {
            global: false,
            id: 2,
        };
        assert_eq!(
            g.hint_value(&Operand::Val(v2)),
            Some(Leaf::Hint {
                call: 0,
                pos: 0,
                elem: None
            })
        );
        // v4 - v1 = v0 - 4·v1 - v1
        let eq = g.equation(g.constraints[2].instr).unwrap();
        let v0 = Val {
            global: false,
            id: 0,
        };
        let v1 = Val {
            global: false,
            id: 1,
        };
        assert_eq!(eq.terms[&Atom::Value(v0)], BigInt::from(1));
        assert_eq!(eq.terms[&Atom::Value(v1)], BigInt::from(-5));
    }

    #[test]
    fn recognizes_both_boolean_check_shapes() {
        let (program, id) = graph_of(SAMPLE);
        let g = Graph::build(&program, &program.functions[&id]);
        let v2 = Val {
            global: false,
            id: 2,
        };
        assert_eq!(g.is_boolean_check(g.constraints[0].instr), Some(v2));
        assert_eq!(g.is_boolean_check(g.constraints[1].instr), Some(v2));
        assert_eq!(g.is_boolean_check(g.constraints[2].instr), None);
    }

    #[test]
    fn long_addition_chains_do_not_exhaust_the_stack() {
        let mut text = String::from("acir(inline) fn main f0 {\n  b0(v0: Field):\n");
        let n = 20_000;
        for i in 1..=n {
            text.push_str(&format!("    v{i} = add v{}, v0\n", i - 1));
        }
        text.push_str(&format!("    constrain v{n} == Field 0\n    return\n}}\n"));
        let program = parse_program(&text);
        let g = Graph::build(&program, &program.functions["f0"]);
        assert!(g.equation(g.constraints[0].instr).is_some());
    }

    #[test]
    fn ratio_bits_needs_a_power_of_two() {
        assert_eq!(ratio_bits(&BigInt::from(1), &BigInt::from(256)), Some(8));
        assert_eq!(
            ratio_bits(&BigInt::from(256), &BigInt::from(65536)),
            Some(8)
        );
        assert_eq!(ratio_bits(&BigInt::from(1), &BigInt::from(10)), None);
    }
}
