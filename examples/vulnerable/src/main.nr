// A deliberately vulnerable circuit: every function below compiles without
// warnings, and every one lets a dishonest prover choose a wrong answer.

unconstrained fn div_hint(n: u32, d: u32) -> (u32, u32) {
    (n / d, n % d)
}

/// Integer division through a hint. Missing `r < d` (NUC-002).
fn div(n: u32, d: u32) -> u32 {
    // Safety: q and r are checked below
    let (q, r) = unsafe { div_hint(n, d) };
    assert(q * d + r == n);
    q
}

unconstrained fn is_zero_hint(x: Field) -> Field {
    if x == 0 { 1 } else { 0 }
}

/// Is-zero gadget with only one of its two constraints (NUC-004).
fn is_zero(x: Field) -> Field {
    // Safety: x * flag == 0 below
    let flag = unsafe { is_zero_hint(x) };
    assert(x * flag == 0);
    flag
}

unconstrained fn bits_hint(x: Field) -> [Field; 8] {
    let bits: [bool; 8] = x.to_le_bits();
    let mut out = [0; 8];
    for i in 0..8 {
        out[i] = bits[i] as Field;
    }
    out
}

/// Byte decomposition whose bits are never checked to be 0 or 1 (NUC-003).
fn to_bits(x: Field) -> [Field; 8] {
    // Safety: TODO
    let bits = unsafe { bits_hint(x) };
    let mut acc = 0;
    let mut pow = 1;
    for i in 0..8 {
        acc += bits[i] * pow;
        pow *= 2;
    }
    assert(acc == x);
    bits
}

fn main(n: u32, d: u32, x: Field, byte: Field) -> pub (u32, Field, [Field; 8]) {
    (div(n, d), is_zero(x), to_bits(byte))
}
