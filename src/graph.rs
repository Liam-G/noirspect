//! Data-flow facts about one constrained (ACIR) SSA function.
//!
//! Every value is traced back to its *leaves*: the circuit inputs and the
//! results of unconstrained hint calls it was computed from. A constraint
//! "touches" a hint when one of the hint's leaves is among the constraint's
//! leaves. Rules are written against these facts and against linear views of
//! constraint expressions.
//!
//! Large unrolled circuits have hundreds of thousands of values, so leaf sets
//! are shared and capped: past [`LEAVES_CAP`] leaves a set is summarized as
//! "many", and every query on a summarized set answers the way that keeps a
//! rule quiet. Likewise each hint's [`HintSlice`] is a bounded forward walk.

use crate::ssa::{BinOp, Function, Instr, Kind, Operand, Program, Val, array_len, int_bits};
use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

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

/// Leaf sets larger than this are summarized as "many".
pub const LEAVES_CAP: usize = 64;

/// Values a forward walk from one hint visits before it gives up.
pub const SLICE_BUDGET: usize = 5_000;

/// The leaves a value is computed from, shared between values. A summarized
/// set (`many`) may hold anything: queries on it answer "maybe", and the rules
/// read every "maybe" in the direction that suppresses a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Leaves {
    set: Rc<BTreeSet<Leaf>>,
    many: bool,
}

impl Leaves {
    pub fn single(leaf: Leaf) -> Leaves {
        Leaves {
            set: Rc::new(BTreeSet::from([leaf])),
            many: false,
        }
    }

    pub fn many() -> Leaves {
        Leaves {
            set: Rc::default(),
            many: true,
        }
    }

    pub fn union(&self, other: &Leaves) -> Leaves {
        if self.many || other.many {
            return Leaves::many();
        }
        if Rc::ptr_eq(&self.set, &other.set) || other.set.is_subset(&self.set) {
            return self.clone();
        }
        if self.set.is_subset(&other.set) {
            return other.clone();
        }
        let merged: BTreeSet<Leaf> = self.set.union(&other.set).copied().collect();
        if merged.len() > LEAVES_CAP {
            Leaves::many()
        } else {
            Leaves {
                set: Rc::new(merged),
                many: false,
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.many && self.set.is_empty()
    }

    pub fn is_many(&self) -> bool {
        self.many
    }

    /// The exact set, unless it was summarized.
    pub fn exact(&self) -> Option<&BTreeSet<Leaf>> {
        (!self.many).then_some(&*self.set)
    }

    pub fn may_contain(&self, leaf: &Leaf) -> bool {
        self.many || self.set.contains(leaf)
    }

    pub fn may_touch_call(&self, call: usize) -> bool {
        self.many || self.set.iter().any(|l| l.hint_call() == Some(call))
    }

    /// May hold a leaf that is not from hint `call` (an input or another hint).
    pub fn may_reach_beyond(&self, call: usize) -> bool {
        self.many || self.set.iter().any(|l| l.hint_call() != Some(call))
    }

    pub fn may_intersect(&self, other: &Leaves) -> bool {
        self.many || other.many || self.set.iter().any(|l| other.set.contains(l))
    }

    /// `target` may be contained in `self`.
    pub fn may_include(&self, target: &Leaves) -> bool {
        self.many || (!target.many && target.set.is_subset(&self.set))
    }

    /// `target` is non-empty and certainly contained in `self`.
    pub fn surely_includes(&self, target: &Leaves) -> bool {
        !self.many && !target.many && !target.set.is_empty() && target.set.is_subset(&self.set)
    }

    pub fn may_equal(&self, other: &Leaves) -> bool {
        self.many || other.many || self.set == other.set
    }

    /// The exact single leaf, if there is one.
    pub fn only(&self) -> Option<Leaf> {
        (!self.many && self.set.len() == 1).then(|| *self.set.iter().next().expect("one leaf"))
    }

    /// More than one leaf, or possibly so.
    pub fn may_be_several(&self) -> bool {
        self.many || self.set.len() > 1
    }
}

/// What a forward walk from one hint's results reaches.
#[derive(Debug, Clone, Default)]
pub struct HintSlice {
    /// Indices into [`Graph::constraints`].
    pub constraints: Vec<usize>,
    /// Instructions reached: comparisons, array reads, everything else.
    pub instrs: Vec<usize>,
    /// The walk ran out of budget, so more may be reached than listed.
    pub truncated: bool,
}

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
    /// Instruction index of a constraint → its index in `constraints`.
    pub constraint_at: HashMap<usize, usize>,
    linear_cache: std::cell::RefCell<HashMap<Val, Linear>>,
    linear_depth: std::cell::Cell<usize>,
    boolean_checked: std::cell::OnceCell<HashSet<Val>>,
    returned_values: std::cell::OnceCell<HashSet<Val>>,
    is_hint_call: HashSet<usize>,
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
            constraint_at: HashMap::new(),
            linear_cache: Default::default(),
            linear_depth: Default::default(),
            boolean_checked: Default::default(),
            returned_values: Default::default(),
            is_hint_call: HashSet::new(),
        };
        for (id, typ) in &program.global_types {
            graph.types.insert(
                Val {
                    global: true,
                    id: *id,
                },
                typ.clone(),
            );
        }
        for block in &func.blocks {
            for (val, typ) in &block.params {
                graph.types.insert(*val, typ.clone());
                graph.leaves.insert(*val, Leaves::single(Leaf::Input(*val)));
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
            self.is_hint_call.insert(idx);
            for (pos, result) in instr.results.iter().enumerate() {
                self.leaves.insert(
                    *result,
                    Leaves::single(Leaf::Hint {
                        call: idx,
                        pos,
                        elem: None,
                    }),
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
                    Leaves::single(Leaf::Hint { call, pos, elem })
                }
                _ => self.union_of(&[array, index]),
            },
            Kind::Constrain { lhs, rhs, .. } | Kind::ConstrainNotEqual { lhs, rhs, .. } => {
                self.union_of(&[lhs, rhs])
            }
            Kind::Call { args, .. } => self.union_of(&args.iter().collect::<Vec<_>>()),
            // Memory is left only where the compiler could not resolve it (a
            // generic instance with `&mut` parameters standing in for `main`):
            // a loaded value may come from anything stored before.
            Kind::Other { opcode, .. } if opcode == "load" => Leaves::many(),
            kind => self.union_of(&kind.operands()),
        };

        if matches!(
            instr.kind,
            Kind::Constrain { .. } | Kind::ConstrainNotEqual { .. } | Kind::RangeCheck { .. }
        ) {
            self.constraint_at.insert(idx, self.constraints.len());
        }
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
        let mut out = Leaves::default();
        for op in ops {
            if let Some(v) = op.val() {
                out = out.union(&self.leaves_of_val(v));
            }
        }
        out
    }

    pub fn leaves_of_val(&self, v: Val) -> Leaves {
        match self.leaves.get(&v) {
            Some(l) => l.clone(),
            // Globals and values without a known definition are constants or inputs.
            None if v.global => Leaves::default(),
            None => Leaves::single(Leaf::Input(v)),
        }
    }

    /// Everything a bounded forward walk from `hint`'s results reaches.
    /// Values do not flow through another hint call: its results are new leaves.
    pub fn slice(&self, hint: &HintCall) -> HintSlice {
        let mut seen: HashSet<Val> = hint.results.iter().copied().collect();
        let mut queue: Vec<Val> = hint.results.clone();
        let mut reached: BTreeSet<usize> = BTreeSet::new();
        // A hint that reads or writes through a reference passes values through
        // memory, which the walk cannot follow.
        let by_reference = |v: &Val| self.type_of(*v).is_some_and(|t| t.starts_with('&'));
        let mut truncated = hint
            .args
            .iter()
            .filter_map(Operand::val)
            .any(|v| by_reference(&v))
            || hint.results.iter().any(by_reference);
        while let Some(v) = queue.pop() {
            if seen.len() > SLICE_BUDGET {
                truncated = true;
                break;
            }
            for idx in self.uses.get(&v).into_iter().flatten() {
                if !reached.insert(*idx) || self.is_hint_call.contains(idx) {
                    continue;
                }
                if matches!(&self.instrs[*idx].kind, Kind::Other { opcode, .. } if opcode == "store")
                {
                    truncated = true;
                }
                for result in &self.instrs[*idx].results {
                    if seen.insert(*result) {
                        queue.push(*result);
                    }
                }
            }
        }
        let constraints = reached
            .iter()
            .filter_map(|idx| self.constraint_at.get(idx).copied())
            .collect();
        HintSlice {
            constraints,
            instrs: reached.into_iter().collect(),
            truncated,
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
        let leaf = self.leaves.get(&v)?.only()?;
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
                if let Some(bits) = self.asserted_below(*idx, value) {
                    consider(bits);
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
                    if let Some(bits) = self.asserted_below(*use_idx, *result) {
                        consider(bits);
                    }
                }
            }
        }
        best
    }

    /// The bits `value` fits in when instruction `idx` is `value < C` for a
    /// constant `C` and the comparison is asserted true, as in the bounds
    /// check of a read from a fixed-size table, or when it reads an array of
    /// `C` scalars at index `value`, which ACIR bounds checks itself.
    fn asserted_below(&self, idx: usize, value: Val) -> Option<u32> {
        let instr = self.instrs[idx];
        if let Kind::ArrayGet {
            array: Operand::Val(array),
            index: Operand::Val(index),
        } = &instr.kind
        {
            let typ = self.type_of(*array)?;
            let scalar = typ
                .strip_prefix('[')
                .is_some_and(|t| !t.starts_with(['[', '(']));
            let len = array_len(typ).filter(|len| *len > 0 && scalar)?;
            return (*index == value).then(|| BigInt::from(len - 1).bits() as u32);
        }
        let Kind::Binary {
            op: BinOp::Lt,
            lhs: Operand::Val(x),
            rhs: Operand::Const { value: limit, .. },
            ..
        } = &instr.kind
        else {
            return None;
        };
        let result = instr.results.first()?;
        let asserted = self.uses.get(result).into_iter().flatten().any(|i| {
            matches!(&self.instrs[*i].kind, Kind::Constrain { lhs: Operand::Val(r), rhs, .. }
                if r == result && rhs.constant().is_some_and(|c| !c.is_zero()))
        });
        (*x == value && asserted && limit.is_positive())
            .then(|| (limit - BigInt::one()).bits() as u32)
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
            Atom::Product(a, b) => self.leaves_of_val(*a).union(&self.leaves_of_val(*b)),
        }
    }

    /// Whether `leaf` may flow into a return value: a bounded forward walk
    /// from the values that are that leaf (true when the walk gives up).
    pub fn leaf_may_reach_return(&self, leaf: Leaf) -> bool {
        let returned = self.returned_values.get_or_init(|| {
            self.func
                .returns()
                .into_iter()
                .filter_map(Operand::val)
                .collect()
        });
        // For one element of a hinted array, the walk starts at the array and
        // skips reads of the other elements at constant indices.
        let (mut start, element): (Vec<Val>, Option<(Val, u64)>) = match leaf {
            Leaf::Input(v) => (vec![v], None),
            Leaf::Hint { call, pos, elem } => {
                let Some(result) = self.instrs[call].results.get(pos).copied() else {
                    return true;
                };
                (vec![result], elem.map(|i| (result, i)))
            }
        };
        let other_element = |idx: usize| match (&self.instrs[idx].kind, element) {
            (Kind::ArrayGet { array, index }, Some((array_val, i))) => {
                array.val() == Some(array_val)
                    && index
                        .constant()
                        .is_some_and(|c| u64::try_from(c).ok() != Some(i))
            }
            _ => false,
        };
        let mut seen: HashSet<Val> = start.iter().copied().collect();
        while let Some(v) = start.pop() {
            if returned.contains(&v) {
                return true;
            }
            if seen.len() > SLICE_BUDGET {
                return true;
            }
            for idx in self.uses.get(&v).into_iter().flatten() {
                if self.is_hint_call.contains(idx) || other_element(*idx) {
                    continue;
                }
                for result in &self.instrs[*idx].results {
                    if seen.insert(*result) {
                        start.push(*result);
                    }
                }
            }
        }
        false
    }

    /// Leaves reaching any return value.
    pub fn returned_leaves(&self) -> Leaves {
        self.func
            .returns()
            .into_iter()
            .fold(Leaves::default(), |acc, op| acc.union(&self.leaves_of(op)))
    }

    /// Values some constraint forces into `{0, 1}`, computed once.
    pub fn boolean_checked(&self) -> &HashSet<Val> {
        self.boolean_checked.get_or_init(|| {
            self.constraints
                .iter()
                .filter_map(|c| self.is_boolean_check(c.instr))
                .collect()
        })
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
    fn asserted_constant_bounds_prove_bits() {
        let text = "acir(inline) fn main f0 {
  b0(v0: Field):
    v1 = call f1(v0) -> [u32; 2]
    v2 = array_get v1, index u32 0 -> u32
    v3 = cast v2 as u64
    v4 = lt v3, u64 32
    constrain v4 == u1 1, \"Index out of bounds\"
    return
}
brillig(inline) fn hint f1 {
  b0(v0: Field):
    return v0
}
";
        let (program, id) = graph_of(text);
        let g = Graph::build(&program, &program.functions[&id]);
        let v2 = Val {
            global: false,
            id: 2,
        };
        assert_eq!(g.proven_bits(v2), Some(5));
    }

    #[test]
    fn values_through_memory_are_not_followed() {
        let text = "acir(inline) fn main f0 {
  b0(v0: &mut Field, v1: Field):
    v2 = call f1(v1) -> Field
    store v2 at v0
    v3 = load v0 -> Field
    constrain v3 == v1
    v4 = call f1(v1) -> Field
    constrain v4 == Field 1
    return
}
brillig(inline) fn hint f1 {
  b0(v0: Field):
    return v0
}
";
        let (program, id) = graph_of(text);
        let g = Graph::build(&program, &program.functions[&id]);
        let val = |id| Val { global: false, id };
        // A loaded value may come from anything stored before it.
        assert!(g.leaves_of_val(val(3)).is_many());
        // The first hint is stored, so its slice is incomplete; the second is not.
        assert!(g.slice(&g.hints[0]).truncated);
        assert!(!g.slice(&g.hints[1]).truncated);
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
