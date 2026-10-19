//! A model of the compiler's printed SSA and a parser for it.
//!
//! The compiler keeps its SSA internals crate-private, but it can print the
//! optimized SSA with source locations. The printed form is what `nargo
//! compile --show-ssa` shows, and it is the only stable public view of the IR,
//! so the analyzer works on that text. Instructions the parser does not know
//! are kept as `Kind::Other` with their operands, so new compiler instructions
//! degrade analysis precision instead of breaking it.

use num_bigint::BigInt;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Val {
    pub global: bool,
    pub id: u32,
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", if self.global { 'g' } else { 'v' }, self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Val(Val),
    Const { typ: String, value: BigInt },
    Func(String),
    Name(String),
}

impl Operand {
    pub fn val(&self) -> Option<Val> {
        match self {
            Operand::Val(v) => Some(*v),
            _ => None,
        }
    }

    pub fn constant(&self) -> Option<&BigInt> {
        match self {
            Operand::Const { value, .. } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Lt,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

impl BinOp {
    fn parse(word: &str) -> Option<(BinOp, bool)> {
        let (word, unchecked) = match word.strip_prefix("unchecked_") {
            Some(rest) => (rest, true),
            None => (word, false),
        };
        let op = match word {
            "add" => BinOp::Add,
            "sub" => BinOp::Sub,
            "mul" => BinOp::Mul,
            "div" => BinOp::Div,
            "mod" => BinOp::Mod,
            "eq" => BinOp::Eq,
            "lt" => BinOp::Lt,
            "and" => BinOp::And,
            "or" => BinOp::Or,
            "xor" => BinOp::Xor,
            "shl" => BinOp::Shl,
            "shr" => BinOp::Shr,
            _ => return None,
        };
        Some((op, unchecked))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Binary {
        op: BinOp,
        unchecked: bool,
        lhs: Operand,
        rhs: Operand,
    },
    Cast {
        value: Operand,
        typ: String,
    },
    Not(Operand),
    Truncate {
        value: Operand,
        bits: u32,
        max_bits: u32,
    },
    Constrain {
        lhs: Operand,
        rhs: Operand,
        msg: Option<String>,
    },
    ConstrainNotEqual {
        lhs: Operand,
        rhs: Operand,
        msg: Option<String>,
    },
    Call {
        func: Operand,
        args: Vec<Operand>,
    },
    ArrayGet {
        array: Operand,
        index: Operand,
    },
    ArraySet {
        array: Operand,
        index: Operand,
        value: Operand,
    },
    RangeCheck {
        value: Operand,
        bits: u32,
        msg: Option<String>,
    },
    IfElse {
        then_cond: Operand,
        then_val: Operand,
        else_cond: Operand,
        else_val: Operand,
    },
    MakeArray {
        elements: Vec<Operand>,
    },
    EnableSideEffects(Operand),
    Other {
        opcode: String,
        operands: Vec<Operand>,
    },
}

impl Kind {
    /// Every operand the instruction reads, in source order.
    pub fn operands(&self) -> Vec<&Operand> {
        match self {
            Kind::Binary { lhs, rhs, .. }
            | Kind::Constrain { lhs, rhs, .. }
            | Kind::ConstrainNotEqual { lhs, rhs, .. } => vec![lhs, rhs],
            Kind::Cast { value, .. }
            | Kind::Not(value)
            | Kind::Truncate { value, .. }
            | Kind::RangeCheck { value, .. }
            | Kind::EnableSideEffects(value) => vec![value],
            Kind::Call { func, args } => std::iter::once(func).chain(args).collect(),
            Kind::ArrayGet { array, index } => vec![array, index],
            Kind::ArraySet {
                array,
                index,
                value,
            } => vec![array, index, value],
            Kind::IfElse {
                then_cond,
                then_val,
                else_cond,
                else_val,
            } => {
                vec![then_cond, then_val, else_cond, else_val]
            }
            Kind::MakeArray { elements } => elements.iter().collect(),
            Kind::Other { operands, .. } => operands.iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct Loc {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.col)
    }
}

#[derive(Debug, Clone)]
pub struct Instr {
    pub results: Vec<Val>,
    pub result_types: Vec<String>,
    pub kind: Kind,
    pub loc: Option<Loc>,
}

#[derive(Debug, Clone, Default)]
pub enum Terminator {
    Return(Vec<Operand>),
    Jmp {
        args: Vec<Operand>,
    },
    JmpIf {
        cond: Operand,
        args: Vec<Operand>,
    },
    #[default]
    None,
}

#[derive(Debug, Clone, Default)]
pub struct Block {
    pub params: Vec<(Val, String)>,
    pub instructions: Vec<Instr>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Acir,
    Brillig,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub id: String,
    pub name: String,
    pub runtime: Runtime,
    pub blocks: Vec<Block>,
}

impl Function {
    pub fn params(&self) -> &[(Val, String)] {
        self.blocks
            .first()
            .map(|b| b.params.as_slice())
            .unwrap_or(&[])
    }

    pub fn returns(&self) -> Vec<&Operand> {
        self.blocks
            .iter()
            .filter_map(|b| match &b.terminator {
                Terminator::Return(values) => Some(values),
                _ => None,
            })
            .flatten()
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    pub functions: BTreeMap<String, Function>,
    /// Types of the globals printed before the functions (`g4 = ... : [u128; 3]`).
    pub global_types: BTreeMap<u32, String>,
}

impl Program {
    pub fn is_brillig(&self, func_id: &str) -> bool {
        self.functions
            .get(func_id)
            .is_some_and(|f| f.runtime == Runtime::Brillig)
    }

    pub fn acir_functions(&self) -> impl Iterator<Item = &Function> {
        self.functions
            .values()
            .filter(|f| f.runtime == Runtime::Acir)
    }
}

/// Integer width of a numeric type name, `None` for `Field` and non-numeric types.
pub fn int_bits(typ: &str) -> Option<u32> {
    let rest = typ.strip_prefix('u').or_else(|| typ.strip_prefix('i'))?;
    rest.parse().ok()
}

pub fn is_field(typ: &str) -> bool {
    typ == "Field"
}

pub fn is_array(typ: &str) -> bool {
    typ.starts_with('[')
}

/// The length of a fixed-size array type such as `[u32; 4]` or `[(u32, u32); 4]`.
pub fn array_len(typ: &str) -> Option<u64> {
    let inner = typ.strip_prefix('[')?.strip_suffix(']')?;
    inner.rsplit_once("; ")?.1.parse().ok()
}

fn is_numeric_type(word: &str) -> bool {
    is_field(word) || int_bits(word).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Num(BigInt),
    Str(String),
    Punct(&'static str),
}

fn tokenize(text: &str) -> Vec<Tok> {
    const PUNCT: [&str; 14] = [
        "==", "!=", "->", ",", "(", ")", "[", "]", ";", ":", "=", "&", "-", "!",
    ];
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' || (c == 'b' && chars.get(i + 1) == Some(&'"')) {
            i += if c == 'b' { 2 } else { 1 };
            let mut s = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                s.push(chars[i]);
                i += 1;
            }
            i += 1;
            tokens.push(Tok::Str(s));
        } else if c.is_ascii_digit()
            || (c == '-' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit()))
        {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let digits: String = chars[start..i].iter().collect();
            tokens.push(Tok::Num(digits.parse().unwrap_or_default()));
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || "_:<>".contains(chars[i])) {
                // `::` and generic brackets appear in some foreign function names.
                if chars[i] == ':'
                    && chars.get(i + 1) != Some(&':')
                    && chars.get(i - 1) != Some(&':')
                {
                    break;
                }
                if (chars[i] == '<' || chars[i] == '>') && start == i {
                    break;
                }
                i += 1;
            }
            tokens.push(Tok::Word(chars[start..i].iter().collect()));
        } else {
            let rest: String = chars[i..chars.len().min(i + 2)].iter().collect();
            match PUNCT.iter().find(|p| rest.starts_with(**p)) {
                Some(p) => {
                    tokens.push(Tok::Punct(p));
                    i += p.len();
                }
                None => i += 1,
            }
        }
    }
    tokens
}

struct Cursor {
    toks: Vec<Tok>,
    pos: usize,
}

impl Cursor {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(q)) if *q == p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, w: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Word(q)) if q == w) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn word(&mut self) -> Option<String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Some(w)
            }
            _ => None,
        }
    }

    fn number(&mut self) -> Option<BigInt> {
        match self.peek() {
            Some(Tok::Num(n)) => {
                let n = n.clone();
                self.pos += 1;
                Some(n)
            }
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        match self.peek() {
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => None,
        }
    }

    fn operand(&mut self) -> Option<Operand> {
        let word = self.word()?;
        if let Some(op) = parse_value_ref(&word) {
            return Some(op);
        }
        if is_numeric_type(&word)
            && let Some(value) = self.number()
        {
            return Some(Operand::Const { typ: word, value });
        }
        Some(Operand::Name(word))
    }

    fn operand_list(&mut self, close: &str) -> Vec<Operand> {
        let mut out = Vec::new();
        while self.peek().is_some() && !self.eat_punct(close) {
            match self.operand() {
                Some(op) => out.push(op),
                None => {
                    self.pos += 1;
                }
            }
            self.eat_punct(",");
        }
        out
    }

    /// A type spelled as tokens up to the next top-level `,` or `)`.
    fn type_text(&mut self) -> String {
        let mut depth = 0i32;
        let mut parts: Vec<String> = Vec::new();
        while let Some(tok) = self.peek() {
            match tok {
                Tok::Punct(p @ ("[" | "(")) => {
                    depth += 1;
                    parts.push(p.to_string());
                }
                Tok::Punct(p @ ("]" | ")")) => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    parts.push(p.to_string());
                }
                Tok::Punct(",") if depth == 0 => break,
                Tok::Punct(p) => parts.push(format!("{p} ")),
                Tok::Word(w) => parts.push(format!("{w} ")),
                Tok::Num(n) => parts.push(n.to_string()),
                Tok::Str(_) => break,
            }
            self.pos += 1;
        }
        parts
            .concat()
            .replace(" ]", "]")
            .replace(" )", ")")
            .replace(" ,", ",")
            .replace(" ;", ";")
            .trim()
            .to_string()
    }

    fn result_types(&mut self) -> Vec<String> {
        if !self.eat_punct("->") {
            return Vec::new();
        }
        if self.eat_punct("(") {
            let mut types = Vec::new();
            loop {
                types.push(self.type_text());
                if !self.eat_punct(",") {
                    break;
                }
            }
            self.eat_punct(")");
            types
        } else {
            vec![self.type_text()]
        }
    }

    fn rest_operands(&mut self) -> Vec<Operand> {
        let mut out = Vec::new();
        while self.peek().is_some() {
            if let Some(Tok::Word(_)) = self.peek() {
                if let Some(op) = self.operand() {
                    out.push(op);
                }
            } else {
                self.pos += 1;
            }
        }
        out
    }
}

fn parse_value_ref(word: &str) -> Option<Operand> {
    let (prefix, digits) = word.split_at(1);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id = digits.parse().ok()?;
    match prefix {
        "v" => Some(Operand::Val(Val { global: false, id })),
        "g" => Some(Operand::Val(Val { global: true, id })),
        "f" => Some(Operand::Func(word.to_string())),
        _ => None,
    }
}

fn parse_loc(text: &str) -> Option<Loc> {
    let mut parts = text.trim().rsplitn(3, ':');
    let col = parts.next()?.parse().ok()?;
    let line = parts.next()?.parse().ok()?;
    let file = parts.next()?.to_string();
    Some(Loc { file, line, col })
}

fn optional_message(cur: &mut Cursor) -> Option<String> {
    if cur.eat_punct(",") {
        cur.string()
    } else {
        None
    }
}

fn parse_body(body: &str) -> Kind {
    let mut cur = Cursor {
        toks: tokenize(body),
        pos: 0,
    };
    let Some(opcode) = cur.word() else {
        return Kind::Other {
            opcode: String::new(),
            operands: Vec::new(),
        };
    };
    let parsed = (|| -> Option<Kind> {
        if let Some((op, unchecked)) = BinOp::parse(&opcode) {
            let lhs = cur.operand()?;
            cur.eat_punct(",");
            let rhs = cur.operand()?;
            return Some(Kind::Binary {
                op,
                unchecked,
                lhs,
                rhs,
            });
        }
        Some(match opcode.as_str() {
            "cast" => {
                let value = cur.operand()?;
                cur.eat_word("as");
                Kind::Cast {
                    value,
                    typ: cur.type_text(),
                }
            }
            "not" => Kind::Not(cur.operand()?),
            "truncate" => {
                let value = cur.operand()?;
                cur.eat_word("to");
                let bits = cur.number()?.try_into().ok()?;
                cur.eat_word("bits");
                cur.eat_punct(",");
                cur.eat_word("max_bit_size");
                cur.eat_punct(":");
                let max_bits = cur.number()?.try_into().ok()?;
                Kind::Truncate {
                    value,
                    bits,
                    max_bits,
                }
            }
            "constrain" => {
                let lhs = cur.operand()?;
                let equal = if cur.eat_punct("==") {
                    true
                } else if cur.eat_punct("!=") {
                    false
                } else {
                    return None;
                };
                let rhs = cur.operand()?;
                let msg = optional_message(&mut cur);
                if equal {
                    Kind::Constrain { lhs, rhs, msg }
                } else {
                    Kind::ConstrainNotEqual { lhs, rhs, msg }
                }
            }
            "call" => {
                cur.eat_word("pure");
                let func = cur.operand()?;
                cur.eat_punct("(");
                let args = cur.operand_list(")");
                Kind::Call { func, args }
            }
            "array_get" => {
                let array = cur.operand()?;
                cur.eat_punct(",");
                cur.eat_word("index");
                let index = cur.operand()?;
                Kind::ArrayGet { array, index }
            }
            "array_set" => {
                cur.eat_word("mut");
                let array = cur.operand()?;
                cur.eat_punct(",");
                cur.eat_word("index");
                let index = cur.operand()?;
                if cur.eat_word("minus") {
                    cur.number();
                }
                cur.eat_punct(",");
                cur.eat_word("value");
                let value = cur.operand()?;
                Kind::ArraySet {
                    array,
                    index,
                    value,
                }
            }
            "range_check" => {
                let value = cur.operand()?;
                cur.eat_word("to");
                let bits = cur.number()?.try_into().ok()?;
                cur.eat_word("bits");
                Kind::RangeCheck {
                    value,
                    bits,
                    msg: optional_message(&mut cur),
                }
            }
            "if" => {
                let then_cond = cur.operand()?;
                cur.eat_word("then");
                let then_val = cur.operand()?;
                cur.eat_word("else");
                cur.eat_punct("(");
                cur.eat_word("if");
                let else_cond = cur.operand()?;
                cur.eat_punct(")");
                let else_val = cur.operand()?;
                Kind::IfElse {
                    then_cond,
                    then_val,
                    else_cond,
                    else_val,
                }
            }
            "make_array" => {
                if cur.eat_punct("[") {
                    Kind::MakeArray {
                        elements: cur.operand_list("]"),
                    }
                } else {
                    Kind::MakeArray {
                        elements: Vec::new(),
                    }
                }
            }
            "enable_side_effects" => Kind::EnableSideEffects(cur.operand()?),
            _ => return None,
        })
    })();
    match parsed {
        Some(kind) => kind,
        None => {
            let mut cur = Cursor {
                toks: tokenize(body),
                pos: 1,
            };
            Kind::Other {
                opcode,
                operands: cur.rest_operands(),
            }
        }
    }
}

/// Split a printed instruction line into its results, its body, and its location comment.
fn parse_instruction(line: &str) -> Instr {
    let (code, loc) = match line.rfind("\t// ") {
        Some(at) => (&line[..at], parse_loc(&line[at + 4..])),
        None => (line, None),
    };
    let code = code.trim();
    let (results, body) = match code.split_once(" = ") {
        Some((lhs, rhs))
            if lhs
                .split(", ")
                .all(|w| matches!(parse_value_ref(w), Some(Operand::Val(_)))) =>
        {
            let results = lhs
                .split(", ")
                .filter_map(|w| parse_value_ref(w)?.val())
                .collect();
            (results, rhs)
        }
        _ => (Vec::new(), code),
    };
    let kind = parse_body(body);
    let result_types = match body.rfind("-> ") {
        Some(at) if !results.is_empty() => {
            let mut cur = Cursor {
                toks: tokenize(&body[at..]),
                pos: 0,
            };
            cur.result_types()
        }
        _ => Vec::new(),
    };
    Instr {
        results,
        result_types,
        kind,
        loc,
    }
}

fn parse_block_header(line: &str) -> Option<Vec<(Val, String)>> {
    let line = line.trim();
    let rest = line.strip_prefix('b')?;
    let open = rest.find('(')?;
    if !rest[..open].bytes().all(|b| b.is_ascii_digit()) || !line.ends_with("):") {
        return None;
    }
    let inner = &rest[open + 1..rest.len() - 2];
    let mut cur = Cursor {
        toks: tokenize(inner),
        pos: 0,
    };
    let mut params = Vec::new();
    while let Some(Tok::Word(w)) = cur.peek().cloned() {
        cur.pos += 1;
        let Some(Operand::Val(v)) = parse_value_ref(&w) else {
            break;
        };
        cur.eat_punct(":");
        params.push((v, cur.type_text()));
        cur.eat_punct(",");
    }
    Some(params)
}

fn parse_terminator(line: &str) -> Option<Terminator> {
    let line = line.trim();
    let mut cur = Cursor {
        toks: tokenize(line),
        pos: 1,
    };
    if line == "return" {
        return Some(Terminator::Return(Vec::new()));
    }
    if line.starts_with("return ") {
        return Some(Terminator::Return(cur.rest_operands()));
    }
    if line.starts_with("jmp ") {
        cur.pos += 1;
        cur.eat_punct("(");
        return Some(Terminator::Jmp {
            args: cur.operand_list(")"),
        });
    }
    if line.starts_with("jmpif ") {
        let cond = cur.operand()?;
        let args = cur
            .rest_operands()
            .into_iter()
            .filter(|op| op.val().is_some())
            .collect();
        return Some(Terminator::JmpIf { cond, args });
    }
    if line == "unreachable" {
        return Some(Terminator::None);
    }
    None
}

fn parse_function_header(line: &str) -> Option<(Runtime, String, String)> {
    let line = line.trim();
    let runtime = if line.starts_with("acir(") {
        Runtime::Acir
    } else if line.starts_with("brillig(") {
        Runtime::Brillig
    } else {
        return None;
    };
    let line = line.strip_suffix('{')?.trim();
    let words: Vec<&str> = line.split_whitespace().collect();
    let fn_at = words.iter().position(|w| *w == "fn")?;
    let id = words.last()?.to_string();
    let name = words[fn_at + 1..words.len() - 1].join(" ");
    Some((runtime, name, id))
}

/// Parse a whole printed SSA program.
/// `g4 = make_array [...] : [u128; 3]` or `g1 = u128 6719...`: the id and type.
fn parse_global(line: &str) -> Option<(u32, String)> {
    let (name, value) = line.trim().split_once(" = ")?;
    let id = name.strip_prefix('g')?.parse().ok()?;
    let typ = match value.strip_prefix("make_array ") {
        Some(array) => array.rsplit_once(" : ")?.1.to_string(),
        None => value.split_whitespace().next()?.to_string(),
    };
    Some((id, typ))
}

pub fn parse_program(text: &str) -> Program {
    let mut program = Program::default();
    let mut current: Option<Function> = None;
    for line in text.lines() {
        if let Some((runtime, name, id)) = parse_function_header(line) {
            current = Some(Function {
                id,
                name,
                runtime,
                blocks: Vec::new(),
            });
            continue;
        }
        let Some(function) = current.as_mut() else {
            if let Some((id, typ)) = parse_global(line) {
                program.global_types.insert(id, typ);
            }
            continue;
        };
        if line.trim() == "}" {
            let function = current.take().expect("function in progress");
            program.functions.insert(function.id.clone(), function);
            continue;
        }
        if let Some(params) = parse_block_header(line) {
            function.blocks.push(Block {
                params,
                ..Block::default()
            });
            continue;
        }
        let Some(block) = function.blocks.last_mut() else {
            continue;
        };
        if let Some(terminator) = parse_terminator(line) {
            block.terminator = terminator;
            continue;
        }
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            block.instructions.push(parse_instruction(line));
        }
    }
    program
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "acir(inline) predicate_pure fn main f0 {
  b0(v0: u32, v1: u32, v2: [Field; 4]):
    v8, v9 = call f3(v0, v1) -> (u32, u32)                	// src/main.nr:7:27
    v10 = mul v8, v1                              	// src/main.nr:8:12
    v11 = add v10, v9                             	// src/main.nr:8:12
    constrain v11 == v0, \"bad, really\"             	// src/main.nr:8:5
    v12 = array_get v2, index u32 1 -> Field      	// src/main.nr:9:5
    v13 = truncate v12 to 8 bits, max_bit_size: 254 	// src/main.nr:10:5
    v14 = cast v13 as u8                          	// src/main.nr:10:5
    range_check v13 to 8 bits
    v15 = make_array [v12, Field 3] : [Field; 2]
    return v8, v14
}
brillig(inline) predicate_pure fn div_hint f3 {
  b0(v0: u32, v1: u32):
    v2 = div v0, v1
    v3 = mod v0, v1
    return v2, v3
}
";

    #[test]
    fn array_lengths() {
        assert_eq!(array_len("[u32; 4]"), Some(4));
        assert_eq!(array_len("[(u32, u32); 16]"), Some(16));
        assert_eq!(array_len("[[u8; 2]; 3]"), Some(3));
        assert_eq!(array_len("[Field]"), None);
        assert_eq!(array_len("u32"), None);
    }

    #[test]
    fn parses_functions_and_instructions() {
        let program = parse_program(SAMPLE);
        assert_eq!(program.functions.len(), 2);
        assert!(program.is_brillig("f3"));
        let main = &program.functions["f0"];
        assert_eq!(main.name, "main");
        assert_eq!(main.params().len(), 3);
        assert_eq!(main.params()[2].1, "[Field; 4]");
        let instrs = &main.blocks[0].instructions;
        assert_eq!(instrs.len(), 9);
        assert_eq!(instrs[0].results.len(), 2);
        assert_eq!(instrs[0].result_types, vec!["u32", "u32"]);
        assert!(
            matches!(&instrs[0].kind, Kind::Call { func: Operand::Func(f), args } if f == "f3" && args.len() == 2)
        );
        assert_eq!(instrs[0].loc.as_ref().unwrap().line, 7);
        assert!(
            matches!(&instrs[3].kind, Kind::Constrain { msg: Some(m), .. } if m == "bad, really")
        );
        assert!(matches!(
            &instrs[5].kind,
            Kind::Truncate {
                bits: 8,
                max_bits: 254,
                ..
            }
        ));
        assert!(matches!(&instrs[6].kind, Kind::Cast { typ, .. } if typ == "u8"));
        assert!(matches!(&instrs[7].kind, Kind::RangeCheck { bits: 8, .. }));
        assert!(matches!(&instrs[8].kind, Kind::MakeArray { elements } if elements.len() == 2));
        assert_eq!(main.returns().len(), 2);
    }

    #[test]
    fn unknown_instructions_keep_their_operands() {
        let instr = parse_instruction("    v3 = frobnicate v1, v2 -> u32");
        match instr.kind {
            Kind::Other { opcode, operands } => {
                assert_eq!(opcode, "frobnicate");
                assert_eq!(operands.len(), 3);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_signed_constants() {
        let instr = parse_instruction("    v3 = add v1, i8 -3");
        assert!(matches!(
            instr.kind,
            Kind::Binary { rhs: Operand::Const { ref value, .. }, .. } if *value == BigInt::from(-3)
        ));
    }
}
